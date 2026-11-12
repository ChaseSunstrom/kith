//! Scheduler v1: filter, score, bind. Pure: the cluster comes in as plain
//! data and a plan comes out, with no I/O and no clock.
//!
//! One greedy pass per replica, in id order, so the same input always gives
//! the same plan. Nothing is moved to improve a score: a replica stays where it
//! is until its node is lost past the grace period, gets a `NoExecute` taint or
//! no longer matches the replica's `require` labels.

use kith_api::kinds::{NodeSpec, Placement, Resources, TaintEffect, Template};
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::time::Duration;

#[cfg(test)]
mod tests;

type Labels = BTreeMap<String, String>;

/// CPU in cores and memory in bytes. kith-api has no node capacity field, so
/// the caller reads it from the node and passes it in.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Amount {
    pub cpu: f64,
    pub memory: f64,
}

impl Amount {
    pub fn of_resources(r: &Resources) -> Amount {
        let get = |q: &Option<_>| q.as_ref().map_or(0.0, kith_api::kinds::Quantity::value);
        Amount {
            cpu: get(&r.cpu),
            memory: get(&r.memory),
        }
    }

    /// The sum of every container's and exec unit's resources.
    pub fn of_template(t: &Template) -> Amount {
        let each = t
            .containers
            .iter()
            .map(|c| &c.resources)
            .chain(t.exec.iter().map(|e| &e.resources));
        each.flatten()
            .map(Amount::of_resources)
            .fold(Amount::default(), |a, b| Amount {
                cpu: a.cpu + b.cpu,
                memory: a.memory + b.memory,
            })
    }
}

/// A node as the scheduler sees it.
#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub labels: Labels,
    pub spec: NodeSpec,
    pub capacity: Amount,
    /// How long the node has been out of contact; `None` while it is ready.
    /// kith-api has no readiness field, so the caller works this out.
    pub lost_for: Option<Duration>,
}

/// One replica to place.
#[derive(Debug, Clone)]
pub struct Replica {
    /// Unique, e.g. `default/web-0`.
    pub id: String,
    /// What it belongs to, e.g. `default/web`: replicas of one workload spread out.
    pub workload: String,
    pub requests: Amount,
    pub placement: Option<Placement>,
    /// The node it is bound to now, if any.
    pub bound: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Replica id -> node name, for every replica that has a home (kept ones included).
    pub bind: BTreeMap<String, String>,
    /// Replica id -> why no node would take it, in plain words.
    pub unschedulable: BTreeMap<String, String>,
}

/// Does every `require`-style label match? Keys may carry the `node.labels.` prefix.
fn matches(have: &Labels, want: &Labels) -> bool {
    want.iter()
        .all(|(k, v)| have.get(k.strip_prefix("node.labels.").unwrap_or(k)) == Some(v))
}

fn tainted(n: &Node, effects: &[TaintEffect]) -> usize {
    n.spec.taints.iter().filter(|t| effects.contains(&t.effect)).count()
}

/// Lost for longer than the grace period: its replicas are rebound.
fn gone(n: &Node, grace: Duration) -> bool {
    n.lost_for.is_some_and(|d| d > grace)
}

fn cordoned(n: &Node) -> bool {
    n.spec.unschedulable == Some(true)
}

/// Why `n` cannot take `r` given what is already `used` on it.
fn reject(n: &Node, r: &Replica, used: Amount) -> Option<&'static str> {
    let reserved = n.spec.reserved.as_ref().map_or(Amount::default(), Amount::of_resources);
    let require = r.placement.as_ref().map(|p| &p.require);
    Some(if n.lost_for.is_some() {
        "not ready"
    } else if cordoned(n) {
        "cordoned"
    } else if tainted(n, &[TaintEffect::NoSchedule, TaintEffect::NoExecute]) > 0 {
        "tainted"
    } else if require.is_some_and(|q| !matches(&n.labels, q)) {
        "missing required labels"
    } else if r.requests.cpu > n.capacity.cpu - reserved.cpu - used.cpu {
        "not enough cpu"
    } else if r.requests.memory > n.capacity.memory - reserved.memory - used.memory {
        "not enough memory"
    } else {
        return None;
    })
}

/// May a replica stay on `n`? Cordon, `NoSchedule` and capacity only stop new
/// placements: a replica already running is not evicted for them.
fn keeps(n: &Node, r: &Replica, grace: Duration) -> bool {
    !gone(n, grace)
        && tainted(n, &[TaintEffect::NoExecute]) == 0
        && r.placement.as_ref().is_none_or(|p| matches(&n.labels, &p.require))
}

/// Places `replicas` on `nodes`. A node lost for up to `grace` keeps what is
/// bound to it, but takes nothing new.
pub fn schedule(nodes: &[Node], replicas: &[Replica], grace: Duration) -> Plan {
    let mut nodes: Vec<&Node> = nodes.iter().collect();
    nodes.sort_by(|a, b| a.name.cmp(&b.name));
    let mut replicas: Vec<&Replica> = replicas.iter().collect();
    replicas.sort_by(|a, b| a.id.cmp(&b.id));

    let mut plan = Plan::default();

    // Pass 1: replicas that stay put count against their node first.
    let mut state = State {
        used: BTreeMap::new(),
        spread: BTreeMap::new(),
    };
    for r in &replicas {
        let home = r.bound.as_deref().and_then(|b| nodes.iter().find(|n| n.name == b));
        if let Some(n) = home.filter(|n| keeps(n, r, grace))
            && !plan.bind.contains_key(&r.id)
        {
            state.put(&mut plan, n, r);
        }
    }
    // Pass 2: the rest, filter then score.
    for r in &replicas {
        if plan.bind.contains_key(&r.id) || plan.unschedulable.contains_key(&r.id) {
            continue;
        }
        let mut why: BTreeMap<&str, usize> = BTreeMap::new();
        let mut best: Option<(_, &Node)> = None;
        for n in &nodes {
            match reject(n, r, state.used(n)) {
                Some(reason) => *why.entry(reason).or_default() += 1,
                None => {
                    let score = state.score(n, r);
                    if best.as_ref().is_none_or(|(b, _)| score > *b) {
                        best = Some((score, n));
                    }
                }
            }
        }
        match best {
            Some((_, n)) => state.put(&mut plan, n, r),
            None => {
                let why: Vec<String> = why.iter().map(|(k, c)| format!("{c} {k}")).collect();
                let why = if why.is_empty() {
                    "there are no nodes".into()
                } else {
                    why.join(", ")
                };
                plan.unschedulable
                    .insert(r.id.clone(), format!("0/{} nodes can take it: {why}", nodes.len()));
            }
        }
    }
    plan
}

/// What the plan has put on each node so far.
struct State<'a> {
    used: BTreeMap<&'a str, Amount>,
    spread: BTreeMap<(&'a str, &'a str), usize>,
}

impl<'a> State<'a> {
    fn used(&self, n: &Node) -> Amount {
        self.used.get(n.name.as_str()).copied().unwrap_or_default()
    }

    fn put(&mut self, plan: &mut Plan, n: &'a Node, r: &'a Replica) {
        let u = self.used.entry(&n.name).or_default();
        u.cpu += r.requests.cpu;
        u.memory += r.requests.memory;
        *self.spread.entry((&n.name, &r.workload)).or_default() += 1;
        plan.bind.insert(r.id.clone(), n.name.clone());
    }

    /// Bigger is better: preference weights, then fewer soft taints, fewer
    /// replicas of the same workload, more free memory, then the name.
    fn score(&self, n: &'a Node, r: &Replica) -> (u64, Reverse<usize>, Reverse<usize>, u64, Reverse<&'a str>) {
        let weight = r
            .placement
            .iter()
            .flat_map(|p| &p.prefer)
            .filter(|p| matches(&n.labels, &p.labels));
        let reserved = n.spec.reserved.as_ref().map_or(0.0, |x| Amount::of_resources(x).memory);
        let free = n.capacity.memory - reserved - self.used(n).memory;
        (
            weight.map(|p| u64::from(p.weight)).sum(),
            Reverse(tainted(n, &[TaintEffect::PreferNoSchedule])),
            Reverse(
                self.spread
                    .get(&(n.name.as_str(), r.workload.as_str()))
                    .copied()
                    .unwrap_or(0),
            ),
            free.max(0.0) as u64,
            Reverse(n.name.as_str()),
        )
    }
}

/// The nodes that run one copy of a NodeWorkload: every node whose labels match
/// `selector`, minus cordoned nodes, `NoExecute`-tainted nodes and nodes lost
/// past the grace period. Capacity is ignored. Names come back sorted.
pub fn node_workload(nodes: &[Node], selector: &Labels, grace: Duration) -> Vec<String> {
    let mut names: Vec<String> = nodes
        .iter()
        .filter(|n| {
            matches(&n.labels, selector)
                && !cordoned(n)
                && tainted(n, &[TaintEffect::NoExecute]) == 0
                && !gone(n, grace)
        })
        .map(|n| n.name.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}
