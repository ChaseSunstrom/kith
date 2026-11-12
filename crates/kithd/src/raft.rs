//! This node's replica of the store, and Raft between nodes (PLAN.md §4.3).
//!
//! ```text
//! POST /v1/raft/append | vote | snapshot    Raft's own messages
//! POST /v1/raft/write  Command -> [reply, log index] | null    for the leader; null: ask again
//! ```
//! Members only. Every change goes through [`Shared::submit`]: the leader puts it in
//! the log, and each node applies it to its own copy once a majority has it on disk.
//! Reads are answered from the node's own copy, which may be a moment behind.
//
// ponytail: Raft messages are JSON over the node API (a snapshot is an array of numbers).
// Fine for stores of a few MB; a binary body is the upgrade if snapshots get slow.

use crate::Shared;
use axum::extract::{DefaultBodyLimit, State};
use axum::routing::post;
use axum::{Json, Router};
use kith_api::store::Error;
use kith_store::openraft::error::{
    ClientWriteError, InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError, Unreachable,
};
use kith_store::openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use kith_store::openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse, VoteRequest,
    VoteResponse,
};
use kith_store::openraft::{BasicNode, ChangeMembers};
use kith_store::{Command, Done, NodeId, Reply, TypeConfig};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// How Raft reaches the other nodes: the node API, as this node. `None` outside a cluster.
pub struct Network(pub Option<reqwest::Client>);

pub struct Link {
    client: Option<reqwest::Client>,
    target: NodeId,
    address: String,
}

impl RaftNetworkFactory<TypeConfig> for Network {
    type Network = Link;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> Link {
        Link {
            client: self.0.clone(),
            target,
            address: node.addr.clone(),
        }
    }
}

impl Link {
    // The error type is openraft's.
    #[allow(clippy::result_large_err)]
    async fn call<Q, A, E>(&self, what: &str, rpc: &Q, option: RPCOption) -> Result<A, RPCError<NodeId, BasicNode, E>>
    where
        Q: Serialize,
        A: DeserializeOwned,
        E: std::error::Error + DeserializeOwned,
    {
        let alone = || Unreachable::new(&std::io::Error::other("this node is not in a cluster"));
        let client = self.client.as_ref().ok_or_else(alone)?;
        let call = client.post(format!("https://{}/v1/raft/{what}", self.address));
        let reply = call.timeout(option.hard_ttl()).json(rpc).send().await;
        let reply = reply.and_then(reqwest::Response::error_for_status);
        let reply = reply.map_err(|e| Unreachable::new(&e))?;
        let reply: Result<A, E> = reply.json().await.map_err(|e| NetworkError::new(&e))?;
        reply.map_err(|e| RemoteError::new(self.target, e).into())
    }
}

type Rpc<A, E = kith_store::openraft::error::Infallible> = Result<A, RPCError<NodeId, BasicNode, RaftError<NodeId, E>>>;

impl RaftNetwork<TypeConfig> for Link {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Rpc<AppendEntriesResponse<NodeId>> {
        self.call("append", &rpc, option).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        option: RPCOption,
    ) -> Rpc<InstallSnapshotResponse<NodeId>, InstallSnapshotError> {
        self.call("snapshot", &rpc, option).await
    }

    async fn vote(&mut self, rpc: VoteRequest<NodeId>, option: RPCOption) -> Rpc<VoteResponse<NodeId>> {
        self.call("vote", &rpc, option).await
    }
}

/// What other nodes' Raft calls. A snapshot chunk is 3 MiB of bytes, each written as a number.
pub fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/v1/raft/append", post(append))
        .route("/v1/raft/vote", post(vote))
        .route("/v1/raft/snapshot", post(snapshot))
        .route("/v1/raft/write", post(write))
        .layer(DefaultBodyLimit::max(64 << 20))
        .with_state(shared)
}

type Answer<A, E = kith_store::openraft::error::Infallible> = Json<Result<A, RaftError<NodeId, E>>>;

async fn append(
    State(shared): State<Arc<Shared>>,
    Json(rpc): Json<AppendEntriesRequest<TypeConfig>>,
) -> Answer<AppendEntriesResponse<NodeId>> {
    Json(shared.raft.append_entries(rpc).await)
}

async fn vote(State(shared): State<Arc<Shared>>, Json(rpc): Json<VoteRequest<NodeId>>) -> Answer<VoteResponse<NodeId>> {
    Json(shared.raft.vote(rpc).await)
}

async fn snapshot(
    State(shared): State<Arc<Shared>>,
    Json(rpc): Json<InstallSnapshotRequest<TypeConfig>>,
) -> Answer<InstallSnapshotResponse<NodeId>, InstallSnapshotError> {
    Json(shared.raft.install_snapshot(rpc).await)
}

/// A change another node passes to the leader: the reply and where in the log it is.
async fn write(State(shared): State<Arc<Shared>>, Json(command): Json<Command>) -> Json<Option<(Reply, u64)>> {
    let written = tokio::time::timeout(PATIENCE, shared.raft.client_write(command)).await;
    Json(match written {
        Ok(Ok(written)) => Some((written.data, written.log_id.index)),
        _ => None,
    })
}

/// How long a change waits for a leader and a majority.
const PATIENCE: Duration = Duration::from_secs(10);

fn unavailable(why: impl std::fmt::Display) -> Error {
    Error::Io(format!("the store cannot take changes now: {why}"))
}

impl Shared {
    /// Make a change to the store, on every node. Returns once this node has applied it.
    //
    // ponytail: a change whose answer is lost (the leader died after writing it, or was
    // too slow) is reported as failed although it may have happened, and a change that is
    // tried again here after such a loss can find its own first try: a delete then says
    // "not found", an apply that names a revision "conflict". Request ids kept in the
    // state machine are the fix when that matters.
    pub async fn submit(&self, command: Command) -> Result<Done, Error> {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let written = tokio::time::timeout(PATIENCE, self.raft.client_write(command.clone())).await;
            let leader = match written {
                Ok(Ok(written)) => return written.data,
                Ok(Err(RaftError::APIError(ClientWriteError::ForwardToLeader(to)))) => to.leader_node,
                Ok(Err(e)) => return Err(unavailable(e)),
                Err(_) => return Err(unavailable(NO_MAJORITY)),
            };
            if let (Some(leader), Some(cluster)) = (leader, &self.cluster)
                && !leader.addr.is_empty()
            {
                let call = cluster.client.post(format!("https://{}/v1/raft/write", leader.addr));
                match call.timeout(PATIENCE).json(&command).send().await {
                    Ok(reply) => {
                        if let Ok(Some((reply, index))) = reply.json::<Option<(Reply, u64)>>().await {
                            // What a client writes through this node, it can read from this node.
                            let caught_up = self.raft.wait(Some(PATIENCE));
                            let _ = caught_up.applied_index_at_least(Some(index), "own write").await;
                            return reply;
                        }
                    }
                    // Never reached it: nothing happened, and asking again is safe.
                    Err(e) if e.is_connect() => {}
                    Err(e) => {
                        let why = format!(
                            "the leader at {} did not answer ({e}); look before trying again",
                            leader.addr
                        );
                        return Err(unavailable(why));
                    }
                }
            }
            if Instant::now() > deadline {
                return Err(unavailable(NO_MAJORITY));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

const NO_MAJORITY: &str = "no leader, or it did not hear from more than half of the voting nodes in time \
    (they have to be running); the change may still happen, so look before trying again";

/// Voters once the cluster has this many nodes; a single voter below that, since two
/// voters stop when either one does.
const VOTERS: usize = 3;

/// On the leader, keep Raft's members the same as the `Node` resources: a new Node
/// starts receiving the store, a deleted one stops, and there are [`VOTERS`] voters when
/// there are that many nodes.
//
// ponytail: a voter that dies is not replaced by a healthy non-voter; that needs to know
// who is alive (gossip, next).
pub async fn tend_members(shared: Arc<Shared>, mut stopping: watch::Receiver<bool>) {
    let mut generation = shared.generation.subscribe();
    loop {
        tokio::select! {
            _ = generation.changed() => {}
            () = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = stopping.changed() => return,
        }
        if let Err(e) = tend_once(&shared).await {
            eprintln!("kithd: changing the cluster's members: {e}");
        }
    }
}

/// The Raft id and address of every Node in `store` that has reported them.
fn nodes_of(store: &kith_api::store::Store) -> BTreeMap<NodeId, BasicNode> {
    let member = |node: &kith_api::Resource| {
        let status = node.status.as_ref()?;
        let id = status["raftId"].as_str()?.parse().ok()?;
        Some((id, BasicNode::new(status["address"].as_str()?)))
    };
    store.list(Some("Node")).filter_map(member).collect()
}

/// The next change to make, if any: one at a time, each seen in the metrics before the next.
/// `current` are the nodes that have (nearly) all of the log: only those may start to vote.
fn next_change(
    me: NodeId,
    wanted: &BTreeMap<NodeId, BasicNode>,
    known: &BTreeMap<NodeId, BasicNode>,
    voters: &BTreeSet<NodeId>,
    current: &BTreeSet<NodeId>,
) -> Option<ChangeMembers<NodeId, BasicNode>> {
    let differ = |(id, node): &(&NodeId, &BasicNode)| known.get(id) != Some(node);
    let (changed, new): (BTreeMap<_, _>, BTreeMap<_, _>) = wanted
        .iter()
        .filter(differ)
        .map(|(id, node)| (*id, node.clone()))
        .partition(|(id, _)| known.contains_key(id));
    if !new.is_empty() {
        return Some(ChangeMembers::AddNodes(new));
    }
    if !changed.is_empty() {
        return Some(ChangeMembers::SetNodes(changed));
    }
    // The leader stays a voter, then those that already are, then by id. A node that
    // is not receiving the store (down, or it gave an address nobody can reach) must not
    // become a voter: with two such voters of three, nothing could be agreed again.
    let target = if wanted.len() >= VOTERS { VOTERS } else { 1 };
    let by_preference = [me]
        .into_iter()
        .chain(voters.iter().copied())
        .chain(current.iter().copied());
    let mut next = BTreeSet::new();
    for id in by_preference.filter(|id| *id == me || wanted.contains_key(id)) {
        if next.len() < target {
            next.insert(id);
        }
    }
    // Not from one voter to two while the third is not ready: two stop when either does.
    let waiting = voters.len() == 1 && next.len() == 2;
    if next != *voters && !waiting {
        return Some(ChangeMembers::ReplaceAllVoters(next));
    }
    let gone: BTreeSet<NodeId> = known
        .keys()
        .filter(|id| **id != me && !wanted.contains_key(id))
        .copied()
        .collect();
    (!gone.is_empty()).then_some(ChangeMembers::RemoveNodes(gone))
}

async fn tend_once(shared: &Shared) -> Result<(), String> {
    let metrics = shared.raft.metrics().borrow().clone();
    if metrics.current_leader != Some(metrics.id) {
        return Ok(());
    }
    let wanted = nodes_of(&shared.store.lock().expect("nothing panics holding the store").store);
    let membership = metrics.membership_config.membership();
    let known: BTreeMap<NodeId, BasicNode> = membership.nodes().map(|(id, node)| (*id, node.clone())).collect();
    let voters: BTreeSet<NodeId> = membership.voter_ids().collect();
    // Within a hundred changes of the leader's log counts as having it.
    let last = metrics.last_log_index.unwrap_or(0);
    let has_it =
        |matched: &Option<kith_store::openraft::LogId<NodeId>>| matched.is_some_and(|log| log.index + 100 >= last);
    let replication = metrics.replication.iter().flatten();
    let current: BTreeSet<NodeId> = replication
        .filter(|(_, matched)| has_it(matched))
        .map(|(id, _)| *id)
        .collect();
    let Some(mut change) = next_change(metrics.id, &wanted, &known, &voters, &current) else {
        return Ok(());
    };
    // Having the log says a node was there, not that it is: ask the ones about to vote.
    if let ChangeMembers::ReplaceAllVoters(next) = &change {
        let mut there = current.clone();
        for id in next.difference(&voters) {
            let client = shared.cluster.as_ref().map(|cluster| &cluster.client);
            let address = wanted.get(id).map_or("", |node| node.addr.as_str());
            let asked = client.map(|client| client.get(format!("https://{address}/v1/ca")));
            let answered = match asked {
                Some(asked) => asked.timeout(Duration::from_secs(2)).send().await.is_ok(),
                None => false,
            };
            if !answered {
                there.remove(id);
            }
        }
        match next_change(metrics.id, &wanted, &known, &voters, &there) {
            Some(with_those_there) => change = with_those_there,
            None => return Ok(()),
        }
    }
    eprintln!("kithd: cluster members: {change:?}");
    // Voters that stop being voters keep receiving the store until their Node is deleted.
    let changing = shared.raft.change_membership(change, true);
    match tokio::time::timeout(PATIENCE, changing).await {
        Ok(changed) => changed.map(drop).map_err(|e| e.to_string()),
        Err(_) => Err("not agreed on in time: too few of the voting nodes answer".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_follow_the_nodes() {
        let node = |n: u64| (n, BasicNode::new(format!("10.0.0.{n}:7443")));
        let nodes = |ids: &[u64]| ids.iter().map(|n| node(*n)).collect::<BTreeMap<_, _>>();
        let set = |ids: &[u64]| ids.iter().copied().collect::<BTreeSet<_>>();
        // Every known node has the store, unless said otherwise.
        let next = |wanted: &[u64], known: &[u64], voters: &[u64]| {
            next_change(1, &nodes(wanted), &nodes(known), &set(voters), &set(known))
        };
        let voters = |ids: &[u64]| Some(ChangeMembers::ReplaceAllVoters(set(ids)));

        assert_eq!(next(&[1], &[1], &[1]), None);
        // A second node only receives; with a third, all three vote.
        assert_eq!(next(&[1, 2], &[1], &[1]), Some(ChangeMembers::AddNodes(nodes(&[2]))));
        assert_eq!(next(&[1, 2], &[1, 2], &[1]), None);
        assert_eq!(
            next(&[1, 2, 3], &[1, 2], &[1]),
            Some(ChangeMembers::AddNodes(nodes(&[3])))
        );
        assert_eq!(next(&[1, 2, 3], &[1, 2, 3], &[1]), voters(&[1, 2, 3]));
        // A fourth does not vote, and takes the place of a voter whose Node is deleted.
        assert_eq!(next(&[1, 2, 3, 4], &[1, 2, 3, 4], &[1, 2, 3]), None);
        assert_eq!(next(&[1, 3, 4], &[1, 2, 3, 4], &[1, 2, 3]), voters(&[1, 3, 4]));
        let gone = Some(ChangeMembers::RemoveNodes(set(&[2])));
        assert_eq!(next(&[1, 3, 4], &[1, 2, 3, 4], &[1, 3, 4]), gone);
        // Back under three nodes: one voter, the leader, even if its own Node is gone.
        assert_eq!(next(&[2, 3], &[1, 2, 3], &[1, 2, 3]), voters(&[1]));
        assert_eq!(next(&[2, 3], &[1, 2, 3], &[1]), None);
        // A node that moved is told to the others.
        let mut moved = nodes(&[1, 2]);
        moved.insert(2, BasicNode::new("10.0.0.9:7443"));
        let told = next_change(1, &moved, &nodes(&[1, 2]), &set(&[1]), &set(&[2]));
        let there = BTreeMap::from([(2, BasicNode::new("10.0.0.9:7443"))]);
        assert_eq!(told, Some(ChangeMembers::SetNodes(there)));

        // A node that does not have the store does not get to vote: not the dead one of
        // three, and not one of two while the third is still catching up.
        let all = nodes(&[1, 2, 3]);
        assert_eq!(next_change(1, &all, &all, &set(&[1]), &set(&[])), None);
        assert_eq!(next_change(1, &all, &all, &set(&[1]), &set(&[3])), None);
        assert_eq!(
            next_change(1, &all, &all, &set(&[1]), &set(&[2, 3])),
            voters(&[1, 2, 3])
        );
        // With four, the three that have it; a voter that falls behind stays one.
        let four = nodes(&[1, 2, 3, 4]);
        assert_eq!(
            next_change(1, &four, &four, &set(&[1]), &set(&[3, 4])),
            voters(&[1, 3, 4])
        );
        assert_eq!(next_change(1, &four, &four, &set(&[1, 2, 3]), &set(&[4])), None);
        // When a voter's Node is deleted and nobody is ready to take its place, two go on.
        let left = nodes(&[1, 3, 4]);
        assert_eq!(
            next_change(1, &left, &four, &set(&[1, 2, 3]), &set(&[])),
            voters(&[1, 3])
        );
    }
}
