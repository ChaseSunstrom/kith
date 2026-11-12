use super::*;
use kith_api::kinds::{Preference, Taint};

const GRACE: Duration = Duration::from_secs(60);
const GI: f64 = 1024.0 * 1024.0 * 1024.0;

fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn node(name: &str, cpu: f64, mem_gi: f64) -> Node {
    let spec = NodeSpec {
        roles: vec![],
        taints: vec![],
        os_version: None,
        extensions: vec![],
        reserved: None,
        unschedulable: None,
    };
    Node {
        name: name.into(),
        labels: Labels::new(),
        spec,
        capacity: Amount {
            cpu,
            memory: mem_gi * GI,
        },
        lost_for: None,
    }
}

fn taint(n: &mut Node, effect: TaintEffect) {
    n.spec.taints.push(Taint {
        key: "k".into(),
        value: None,
        effect,
    });
}

fn replica(id: &str, workload: &str) -> Replica {
    Replica {
        id: id.into(),
        workload: workload.into(),
        requests: Amount { cpu: 1.0, memory: GI },
        placement: None,
        bound: None,
    }
}

fn placement(require: &[(&str, &str)], prefer: &[(u32, &str, &str)]) -> Option<Placement> {
    let prefer = prefer
        .iter()
        .map(|(w, k, v)| Preference {
            weight: *w,
            labels: labels(&[(k, v)]),
        })
        .collect();
    Some(Placement {
        require: labels(require),
        prefer,
    })
}

fn bound(mut r: Replica, to: &str) -> Replica {
    r.bound = Some(to.into());
    r
}

fn home(plan: &Plan, id: &str) -> String {
    plan.bind
        .get(id)
        .cloned()
        .unwrap_or_else(|| format!("unplaced: {:?}", plan.unschedulable.get(id)))
}

#[test]
fn filters_each_turn_a_node_away() {
    type Tweak = fn(&mut Node);
    let cases: [(&str, Tweak, &str); 7] = [
        ("lost", |n| n.lost_for = Some(Duration::from_secs(1)), "not ready"),
        ("cordoned", |n| n.spec.unschedulable = Some(true), "cordoned"),
        ("noschedule", |n| taint(n, TaintEffect::NoSchedule), "tainted"),
        ("noexecute", |n| taint(n, TaintEffect::NoExecute), "tainted"),
        ("cpu", |n| n.capacity.cpu = 0.5, "not enough cpu"),
        ("memory", |n| n.capacity.memory = 0.5 * GI, "not enough memory"),
        (
            "reserved",
            |n| {
                n.spec.reserved = Some(Resources {
                    cpu: Some(quantity("1500m")),
                    memory: None,
                });
                n.capacity.cpu = 2.0;
            },
            "not enough cpu",
        ),
    ];
    for (name, tweak, reason) in cases {
        let bad = || {
            let mut n = node("a", 4.0, 4.0);
            tweak(&mut n);
            n
        };
        let plan = schedule(&[bad(), node("b", 4.0, 4.0)], &[replica("r", "w")], GRACE);
        assert_eq!(home(&plan, "r"), "b", "{name}");
        let plan = schedule(&[bad()], &[replica("r", "w")], GRACE);
        assert_eq!(
            plan.unschedulable["r"],
            format!("0/1 nodes can take it: 1 {reason}"),
            "{name}"
        );
    }
}

fn quantity(s: &str) -> kith_api::kinds::Quantity {
    serde_json::from_value(serde_json::json!(s)).unwrap()
}

#[test]
fn require_labels_all_match_with_or_without_the_prefix() {
    let mut a = node("a", 4.0, 4.0);
    a.labels = labels(&[("disks", "hdd")]);
    let mut b = node("b", 4.0, 4.0);
    b.labels = labels(&[("disks", "hdd"), ("room", "closet")]);
    let c = node("c", 4.0, 4.0);
    let mut r = replica("r", "w");
    r.placement = placement(&[("node.labels.disks", "hdd"), ("room", "closet")], &[]);
    assert_eq!(home(&schedule(&[a, b, c], &[r], GRACE), "r"), "b");
}

#[test]
fn prefer_weights_add_up_and_beat_spread_and_memory() {
    let mut a = node("a", 4.0, 64.0);
    a.labels = labels(&[("room", "attic")]);
    let mut b = node("b", 4.0, 2.0);
    b.labels = labels(&[("room", "closet"), ("fast", "yes")]);
    let mut c = node("c", 4.0, 2.0);
    c.labels = labels(&[("room", "closet")]);
    let mut r = replica("r", "w");
    r.placement = placement(
        &[],
        &[
            (50, "node.labels.room", "closet"),
            (10, "fast", "yes"),
            (30, "room", "attic"),
        ],
    );
    // a scores 30, b scores 60, c scores 50.
    assert_eq!(home(&schedule(&[a, b, c], &[r], GRACE), "r"), "b");
}

#[test]
fn spread_then_free_memory_then_name() {
    let nodes = [node("a", 8.0, 4.0), node("b", 8.0, 8.0), node("c", 8.0, 8.0)];
    // Most free memory first, name breaks the tie between b and c; then spread
    // sends the next two to the nodes that have none of this workload yet.
    let rs = [
        replica("w-0", "w"),
        replica("w-1", "w"),
        replica("w-2", "w"),
        replica("w-3", "w"),
    ];
    let plan = schedule(&nodes, &rs, GRACE);
    assert_eq!(home(&plan, "w-0"), "b");
    assert_eq!(home(&plan, "w-1"), "c");
    assert_eq!(home(&plan, "w-2"), "a");
    // all three have one: b has 7 Gi free after w-0, c 7, a 3, so b (name before c).
    assert_eq!(home(&plan, "w-3"), "b");
}

#[test]
fn spread_counts_only_the_same_workload() {
    let nodes = [node("a", 8.0, 8.0), node("b", 8.0, 8.0)];
    let rs = [replica("x-0", "x"), replica("y-0", "y")];
    let plan = schedule(&nodes, &rs, GRACE);
    // x-0 takes a (name); y has none of its own on a or b, but b has more memory left.
    assert_eq!((home(&plan, "x-0"), home(&plan, "y-0")), ("a".into(), "b".into()));
}

#[test]
fn prefer_no_schedule_taint_is_a_last_resort_not_a_filter() {
    let mut a = node("a", 4.0, 64.0);
    taint(&mut a, TaintEffect::PreferNoSchedule);
    let b = node("b", 4.0, 1.0);
    assert_eq!(home(&schedule(&[a.clone(), b], &[replica("r", "w")], GRACE), "r"), "b");
    assert_eq!(home(&schedule(&[a], &[replica("r", "w")], GRACE), "r"), "a");
}

#[test]
fn capacity_is_shared_by_the_replicas_of_one_pass() {
    let nodes = [node("a", 2.0, 8.0)];
    let rs = [replica("r-0", "w"), replica("r-1", "w"), replica("r-2", "w")];
    let plan = schedule(&nodes, &rs, GRACE);
    assert_eq!(plan.bind.len(), 2);
    assert_eq!(plan.unschedulable["r-2"], "0/1 nodes can take it: 1 not enough cpu");
}

#[test]
fn replicas_that_stay_hold_their_capacity_against_new_ones() {
    let nodes = [node("a", 1.0, 8.0), node("b", 1.0, 8.0)];
    // "z" sorts last but is bound to a: "a-new" must not take a's only core.
    let rs = [replica("a-new", "w"), bound(replica("z", "w"), "a")];
    let plan = schedule(&nodes, &rs, GRACE);
    assert_eq!((home(&plan, "z"), home(&plan, "a-new")), ("a".into(), "b".into()));
}

#[test]
fn the_same_plan_whatever_the_input_order() {
    let nodes = [node("a", 4.0, 4.0), node("b", 4.0, 4.0), node("c", 4.0, 8.0)];
    let rs: Vec<Replica> = (0..6)
        .map(|i| replica(&format!("r-{i}"), if i % 2 == 0 { "x" } else { "y" }))
        .collect();
    let want = schedule(&nodes, &rs, GRACE);
    let (mut n2, mut r2) = (nodes.to_vec(), rs.clone());
    n2.reverse();
    r2.reverse();
    assert_eq!(schedule(&n2, &r2, GRACE), want);
    assert_eq!(schedule(&nodes, &rs, GRACE), want);
}

#[test]
fn a_replica_stays_even_when_a_better_node_appears() {
    let nodes = [node("a", 4.0, 1.0), node("b", 4.0, 64.0)];
    let plan = schedule(&nodes, &[bound(replica("r", "w"), "a")], GRACE);
    assert_eq!(home(&plan, "r"), "a");
}

#[test]
fn cordon_and_noschedule_do_not_evict_but_noexecute_and_labels_do() {
    let mut cordoned = node("a", 4.0, 1.0);
    cordoned.spec.unschedulable = Some(true);
    let mut soft = node("b", 4.0, 1.0);
    taint(&mut soft, TaintEffect::NoSchedule);
    let mut hard = node("c", 4.0, 1.0);
    taint(&mut hard, TaintEffect::NoExecute);
    let mut plain = node("d", 4.0, 1.0);
    plain.labels = labels(&[("disks", "hdd")]);
    let nodes = [cordoned, soft, hard, plain, node("e", 4.0, 64.0)];
    let mut on_d = bound(replica("on-d", "w"), "d");
    on_d.placement = placement(&[("disks", "ssd")], &[]);
    let rs = [
        bound(replica("on-a", "w"), "a"),
        bound(replica("on-b", "w"), "b"),
        bound(replica("on-c", "w"), "c"),
        on_d,
    ];
    let plan = schedule(&nodes, &rs, GRACE);
    assert_eq!(home(&plan, "on-a"), "a");
    assert_eq!(home(&plan, "on-b"), "b");
    assert_eq!(home(&plan, "on-c"), "e");
    assert_eq!(
        plan.unschedulable["on-d"],
        "0/5 nodes can take it: 1 cordoned, 2 missing required labels, 2 tainted"
    );
}

#[test]
fn grace_period_decides_between_staying_and_rebinding() {
    let mut a = node("a", 4.0, 1.0);
    let b = node("b", 4.0, 64.0);
    for (lost, stays) in [(0, true), (30, true), (60, true), (61, false), (3600, false)] {
        a.lost_for = Some(Duration::from_secs(lost));
        let plan = schedule(&[a.clone(), b.clone()], &[bound(replica("r", "w"), "a")], GRACE);
        assert_eq!(home(&plan, "r"), if stays { "a" } else { "b" }, "lost for {lost}s");
    }
}

#[test]
fn a_node_lost_within_grace_takes_nothing_new() {
    let mut a = node("a", 4.0, 64.0);
    a.lost_for = Some(Duration::from_secs(10));
    let plan = schedule(
        &[a, node("b", 4.0, 1.0)],
        &[replica("new", "w"), bound(replica("old", "w"), "a")],
        GRACE,
    );
    assert_eq!((home(&plan, "old"), home(&plan, "new")), ("a".into(), "b".into()));
}

#[test]
fn a_replica_bound_to_a_node_that_is_gone_is_rebound() {
    let plan = schedule(&[node("b", 4.0, 4.0)], &[bound(replica("r", "w"), "deleted")], GRACE);
    assert_eq!(home(&plan, "r"), "b");
}

#[test]
fn no_nodes_and_duplicate_ids_are_handled() {
    let plan = schedule(&[], &[replica("r", "w")], GRACE);
    assert_eq!(plan.unschedulable["r"], "0/0 nodes can take it: there are no nodes");
    let plan = schedule(&[node("a", 8.0, 8.0)], &[replica("r", "w"), replica("r", "w")], GRACE);
    assert_eq!(plan.bind.len(), 1);
}

#[test]
fn requests_sum_every_container_and_exec_unit() {
    let t: Template = serde_json::from_value(serde_json::json!({
        "containers": [
            {"name": "a", "image": "i", "resources": {"cpu": "500m", "memory": "1Gi"}},
            {"name": "b", "image": "i"},
        ],
        "exec": [{"name": "e", "command": ["x"], "resources": {"cpu": "1", "memory": "512Mi"}}],
    }))
    .unwrap();
    let a = Amount::of_template(&t);
    assert_eq!((a.cpu, a.memory), (1.5, 1.5 * GI));
}

#[test]
fn node_workload_runs_on_every_matching_node() {
    let mut a = node("a", 0.0, 0.0);
    a.labels = labels(&[("role", "edge")]);
    let mut b = a.clone();
    b.name = "b".into();
    let mut cordoned = a.clone();
    cordoned.name = "c".into();
    cordoned.spec.unschedulable = Some(true);
    let mut hard = a.clone();
    hard.name = "d".into();
    taint(&mut hard, TaintEffect::NoExecute);
    let mut soft = a.clone();
    soft.name = "e".into();
    taint(&mut soft, TaintEffect::NoSchedule);
    let mut lost = a.clone();
    lost.name = "f".into();
    lost.lost_for = Some(GRACE + Duration::from_secs(1));
    let mut blip = a.clone();
    blip.name = "g".into();
    blip.lost_for = Some(Duration::from_secs(5));
    let other = node("h", 0.0, 0.0);
    let nodes = [other, blip, lost, soft, hard, cordoned, b, a];
    let edge = labels(&[("node.labels.role", "edge")]);
    assert_eq!(node_workload(&nodes, &edge, GRACE), ["a", "b", "e", "g"]);
    // An empty selector means every node that is not excluded.
    assert_eq!(node_workload(&nodes, &Labels::new(), GRACE), ["a", "b", "e", "g", "h"]);
}

/// A tiny deterministic generator, so the property test needs no crate.
struct Lcg(u64);

impl Lcg {
    fn below(&mut self, n: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) % n
    }
}

#[test]
fn random_clusters_never_break_a_filter_or_capacity() {
    let mut rng = Lcg(7);
    for round in 0..300 {
        let mut nodes = Vec::new();
        for i in 0..rng.below(6) {
            let mut n = node(&format!("n{i}"), (1 + rng.below(4)) as f64, (1 + rng.below(4)) as f64);
            n.labels = labels(&[("zone", ["x", "y"][rng.below(2) as usize])]);
            match rng.below(6) {
                0 => n.spec.unschedulable = Some(true),
                1 => taint(&mut n, TaintEffect::NoSchedule),
                2 => taint(&mut n, TaintEffect::NoExecute),
                3 => n.lost_for = Some(Duration::from_secs(rng.below(120))),
                _ => {}
            }
            if rng.below(3) == 0 {
                n.spec.reserved = Some(Resources {
                    cpu: Some(quantity("500m")),
                    memory: Some(quantity("512Mi")),
                });
            }
            nodes.push(n);
        }
        let replicas: Vec<Replica> = (0..rng.below(12))
            .map(|i| {
                let mut r = replica(&format!("r{i:02}"), &format!("w{}", rng.below(3)));
                r.requests = Amount {
                    cpu: rng.below(3) as f64 * 0.5,
                    memory: rng.below(3) as f64 * GI / 2.0,
                };
                if rng.below(2) == 0 {
                    r.placement = placement(&[("zone", ["x", "y"][rng.below(2) as usize])], &[(5, "zone", "x")]);
                }
                r
            })
            .collect();
        let plan = schedule(&nodes, &replicas, GRACE);
        let mut used: BTreeMap<&str, Amount> = BTreeMap::new();
        for r in &replicas {
            assert!(
                plan.bind.contains_key(&r.id) ^ plan.unschedulable.contains_key(&r.id),
                "round {round}: {} has no verdict",
                r.id
            );
            let Some(name) = plan.bind.get(&r.id) else { continue };
            let n = nodes.iter().find(|n| &n.name == name).unwrap();
            assert!(n.lost_for.is_none(), "round {round}: bound to a lost node");
            assert_ne!(
                n.spec.unschedulable,
                Some(true),
                "round {round}: bound to a cordoned node"
            );
            assert_eq!(
                tainted(n, &[TaintEffect::NoSchedule, TaintEffect::NoExecute]),
                0,
                "round {round}: bound to a tainted node"
            );
            assert!(matches(
                &n.labels,
                &r.placement
                    .as_ref()
                    .unwrap_or(&Placement {
                        require: Labels::new(),
                        prefer: vec![]
                    })
                    .require
            ));
            let u = used.entry(name).or_default();
            u.cpu += r.requests.cpu;
            u.memory += r.requests.memory;
        }
        for (name, u) in used {
            let n = nodes.iter().find(|n| n.name == name).unwrap();
            let reserved = n.spec.reserved.as_ref().map_or(Amount::default(), Amount::of_resources);
            assert!(u.cpu <= n.capacity.cpu - reserved.cpu, "round {round}: {name} over cpu");
            assert!(
                u.memory <= n.capacity.memory - reserved.memory,
                "round {round}: {name} over memory"
            );
        }
        // Feeding the plan back in changes nothing.
        let again: Vec<Replica> = replicas
            .iter()
            .map(|r| Replica {
                bound: plan.bind.get(&r.id).cloned(),
                ..r.clone()
            })
            .collect();
        assert_eq!(
            schedule(&nodes, &again, GRACE).bind,
            plan.bind,
            "round {round}: not stable"
        );
    }
}
