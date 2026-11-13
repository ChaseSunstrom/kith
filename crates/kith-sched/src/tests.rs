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
        extensions: vec![],
        reserved: None,
        unschedulable: None,
        roaming: None,
        mesh: None,
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
        node: None,
    }
}

#[test]
fn a_replica_with_a_node_goes_there_and_nowhere_else() {
    let nodes = [node("a", 4.0, 8.0), node("b", 4.0, 8.0)];
    // (b is the node with more room, and still not where it may go; a bound replica moves.)
    let pinned = |id: &str, on: &str| Replica {
        node: Some(on.into()),
        ..replica(id, "w")
    };
    let plan = schedule(&nodes, &[pinned("w#0", "a"), pinned("w#1", "c")], GRACE);
    assert_eq!(home(&plan, "w#0"), "a");
    let why = plan.unschedulable.get("w#1").expect("c is no node");
    assert!(why.contains("2 not the node it needs"), "{why}");
    let moved = Replica {
        bound: Some("b".into()),
        ..pinned("w#0", "a")
    };
    assert_eq!(home(&schedule(&nodes, &[moved], GRACE), "w#0"), "a");
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
fn nan_inf_and_negative_numbers_never_admit_a_replica() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
        // A broken capacity counts as 0, so a replica that asks for something is refused.
        let mut cpu = node("a", 4.0, 4.0);
        cpu.capacity.cpu = bad;
        let mut mem = node("b", 4.0, 4.0);
        mem.capacity.memory = bad;
        let plan = schedule(&[cpu, mem], &[replica("r", "w")], GRACE);
        assert_eq!(
            plan.unschedulable["r"], "0/2 nodes can take it: 1 not enough cpu, 1 not enough memory",
            "capacity {bad}"
        );
        // A broken request is unschedulable on any node, bound or not.
        for on in [None, Some("e")] {
            let mut r = replica("r", "w");
            r.requests.memory = bad;
            r.bound = on.map(Into::into);
            let plan = schedule(&[node("e", 4.0, 4.0)], &[r], GRACE);
            assert!(plan.bind.is_empty(), "request {bad}");
            assert_eq!(
                plan.unschedulable["r"],
                "its requests are not finite, non-negative numbers"
            );
        }
    }
}

#[test]
fn duplicate_names_and_ids_give_one_plan_whatever_the_order() {
    let (big, small) = (node("a", 8.0, 8.0), node("a", 1.0, 1.0));
    let x = replica("r", "w");
    let mut y = replica("r", "w");
    y.requests.cpu = 4.0;
    let want = schedule(&[big.clone(), small.clone()], &[x.clone(), y.clone()], GRACE);
    assert_eq!(schedule(&[small, big], &[y, x], GRACE), want);
    assert_eq!(want.bind.len() + want.unschedulable.len(), 1);
}

#[test]
fn requests_sum_every_container_and_exec_unit() {
    let t: Template = serde_json::from_value(serde_json::json!({
        "containers": [
            {"name": "a", "image": "i", "resources": {"cpu": "500m", "memory": "1Gi"}},
            {"name": "b", "image": "i"},
        ],
        "exec": [{"name": "e", "command": ["x"], "resources": {"cpu": "1", "memory": "512Mi"}}],
        // A machine costs what it says, or else what it is given.
        "vms": [
            {"name": "v", "kernel": "/k", "cpus": 2, "memory": "1Gi"},
            {"name": "w", "kernel": "/k", "cpus": 8, "memory": "4Gi", "resources": {"cpu": "1", "memory": "5Gi"}},
        ],
    }))
    .unwrap();
    let a = Amount::of_template(&t);
    assert_eq!((a.cpu, a.memory), (4.5, 7.5 * GI));
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

fn shuffled<T: Clone>(rng: &mut Lcg, v: &[T]) -> Vec<T> {
    let mut v = v.to_vec();
    for i in (1..v.len()).rev() {
        v.swap(i, rng.below(i as u64 + 1) as usize);
    }
    v
}

/// `below(n) * unit`, now and then NaN, infinite or negative instead.
fn odd(rng: &mut Lcg, n: u64, unit: f64) -> f64 {
    match rng.below(12) {
        0 => f64::NAN,
        1 => f64::INFINITY,
        2 => -unit,
        _ => rng.below(n) as f64 * unit,
    }
}

fn random_cluster(rng: &mut Lcg) -> (Vec<Node>, Vec<Replica>) {
    let mut nodes: Vec<Node> = Vec::new();
    for i in 0..rng.below(7) {
        // Now and then a second node with a name already taken.
        let name = match nodes.len() {
            0 => format!("n{i}"),
            len if rng.below(6) == 0 => nodes[rng.below(len as u64) as usize].name.clone(),
            _ => format!("n{i}"),
        };
        let mut n = node(&name, odd(rng, 5, 1.0), odd(rng, 5, 1.0));
        n.labels = labels(&[("zone", ["x", "y"][rng.below(2) as usize])]);
        match rng.below(8) {
            0 => n.spec.unschedulable = Some(true),
            1 => taint(&mut n, TaintEffect::NoSchedule),
            2 => taint(&mut n, TaintEffect::NoExecute),
            3 | 4 => n.lost_for = Some(Duration::from_secs(rng.below(120))),
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
    let mut replicas: Vec<Replica> = Vec::new();
    for i in 0..rng.below(14) {
        let id = match replicas.len() {
            len if len > 0 && rng.below(6) == 0 => replicas[rng.below(len as u64) as usize].id.clone(),
            _ => format!("r{i:02}"),
        };
        let mut r = replica(&id, &format!("w{}", rng.below(3)));
        r.requests = Amount {
            cpu: odd(rng, 3, 0.5),
            memory: odd(rng, 3, GI / 2.0),
        };
        if rng.below(2) == 0 {
            r.placement = placement(&[("zone", ["x", "y"][rng.below(2) as usize])], &[(5, "zone", "x")]);
        }
        // Bound to a live node, or to `n{len}`, which does not exist.
        if rng.below(3) > 0 {
            r.bound = Some(format!("n{}", rng.below(nodes.len() as u64 + 1)));
        }
        replicas.push(r);
    }
    (nodes, replicas)
}

/// The copy of each name that wins: the smallest by its `Debug` text.
fn winners<T: std::fmt::Debug>(items: &[T], name: fn(&T) -> &str) -> BTreeMap<&str, &T> {
    let mut won: BTreeMap<&str, &T> = BTreeMap::new();
    for x in items {
        let e = won.entry(name(x)).or_insert(x);
        if format!("{x:?}") < format!("{e:?}") {
            *e = x;
        }
    }
    won
}

fn fine(x: f64) -> bool {
    x.is_finite() && x >= 0.0
}

/// Checks one plan against the rules, from the input alone.
fn check(nodes: &[Node], replicas: &[Replica], plan: &Plan) -> (usize, usize) {
    let live = winners(nodes, |n| &n.name);
    let mut kept: BTreeMap<&str, (Amount, usize)> = BTreeMap::new();
    let mut new: BTreeMap<&str, (Amount, usize)> = BTreeMap::new();
    for r in replicas {
        // (d) exactly one verdict for every id.
        assert!(
            plan.bind.contains_key(&r.id) ^ plan.unschedulable.contains_key(&r.id),
            "{} has no single verdict",
            r.id
        );
    }
    for id in plan.bind.keys().chain(plan.unschedulable.keys()) {
        assert!(replicas.iter().any(|r| &r.id == id), "{id} is not a replica");
    }
    for r in winners(replicas, |r| &r.id).into_values() {
        let valid = fine(r.requests.cpu) && fine(r.requests.memory);
        let require = r.placement.as_ref().map(|p| p.require.clone()).unwrap_or_default();
        let may_stay = |n: &Node| {
            valid
                && !n.lost_for.is_some_and(|d| d > GRACE)
                && !n.spec.taints.iter().any(|t| t.effect == TaintEffect::NoExecute)
                && matches(&n.labels, &require)
        };
        let stays = r.bound.as_deref().and_then(|b| live.get(b)).filter(|n| may_stay(n));
        let Some(to) = plan.bind.get(&r.id) else {
            assert!(stays.is_none(), "{} was evicted from a node it may stay on", r.id);
            continue;
        };
        assert!(valid, "{} has broken requests but was bound", r.id);
        let n = live.get(to.as_str()).expect("bound to a node that does not exist");
        let (side, count) = if stays.is_some() {
            // (c) a kept replica is where it was and may stay there.
            assert_eq!(r.bound.as_ref(), Some(to));
            kept.entry(to).or_default()
        } else {
            // (a) a new placement passes every filter.
            assert_ne!(r.bound.as_ref(), Some(to), "{} kept on a node it must leave", r.id);
            assert!(
                n.lost_for.is_none() && n.spec.unschedulable != Some(true),
                "{to}: not ready or cordoned"
            );
            assert_eq!(
                tainted(n, &[TaintEffect::NoSchedule, TaintEffect::NoExecute]),
                0,
                "{to}: tainted"
            );
            assert!(matches(&n.labels, &require), "{to}: labels");
            new.entry(to).or_default()
        };
        side.cpu += r.requests.cpu;
        side.memory += r.requests.memory;
        *count += 1;
    }
    // (b) new placements fit beside the kept ones, unless the kept ones fill the node already.
    for (name, (add, count)) in &new {
        let n = live[name];
        let held = kept.get(name).map_or(Amount::default(), |k| k.0);
        let reserved = n.spec.reserved.as_ref().map_or(Amount::default(), Amount::of_resources);
        let room = |cap: f64, res: f64| if fine(cap) { cap - res } else { 0.0 - res };
        let (cpu, mem) = (
            room(n.capacity.cpu, reserved.cpu),
            room(n.capacity.memory, reserved.memory),
        );
        assert!(held.cpu + add.cpu <= cpu, "{name}: over cpu ({count} new)");
        assert!(held.memory + add.memory <= mem, "{name}: over memory ({count} new)");
    }
    (kept.values().map(|k| k.1).sum(), new.values().map(|k| k.1).sum())
}

#[test]
fn random_clusters_keep_every_rule_and_ignore_input_order() {
    let mut rng = Lcg(7);
    let (mut kept, mut new, mut refused) = (0, 0, 0);
    for round in 0..4000 {
        let (nodes, replicas) = random_cluster(&mut rng);
        let plan = schedule(&nodes, &replicas, GRACE);
        let (k, n) = check(&nodes, &replicas, &plan);
        kept += k;
        new += n;
        refused += plan.unschedulable.len();
        // The same plan for any order of nodes and replicas.
        for _ in 0..3 {
            let (n2, r2) = (shuffled(&mut rng, &nodes), shuffled(&mut rng, &replicas));
            assert_eq!(schedule(&n2, &r2, GRACE), plan, "round {round}: order changed the plan");
        }
        // (e) Feeding the plan back in changes nothing.
        let again: Vec<Replica> = replicas
            .iter()
            .map(|r| Replica {
                bound: plan.bind.get(&r.id).cloned(),
                ..r.clone()
            })
            .collect();
        let second = schedule(&nodes, &again, GRACE);
        assert_eq!(second.bind, plan.bind, "round {round}: not stable");
        assert!(
            second.unschedulable.keys().eq(plan.unschedulable.keys()),
            "round {round}: not stable"
        );
    }
    assert!(kept > 1000 && new > 1000 && refused > 1000, "{kept} {new} {refused}");
}
