// What `GET /v1/metrics?range=R` answers (T-1111's contract), made up the same every time:
// for test.mjs, for the Rust test that runs the dashboard against it, and for the
// screenshots (ci/ui_shots.py) of a cluster whose real nodes have kept no history yet.
// Not one of the page's files: kithd does not serve it.
//
//   { range, step, end, nodes: { NAME: { cpu: [0..1], cpus, mem: [B], memTotal, disk: [B], diskTotal,
//       diskRead: [B/s], diskWrite: [B/s], rx: [B/s], tx: [B/s], load1: [n], missing?: true } },
//     workloads: { 'NS/NAME': { node, cpu: [cores], mem: [B] } } }
//
// Arrays are oldest first, point i at `end - step * (len - 1 - i)` (seconds); null is a gap.
// A node that did not answer has the whole shape, its arrays all null and its sizes 0, with
// `missing: true`; its Workloads are not there. A Workload on several nodes is `NS/NAME` on the
// first node by name and `NS/NAME@NODE` on each other. A point of mem or disk may be null where
// kithd could not read it; `workloads` holds only the namespaces the caller may read, so `{}` is
// an ordinary answer.

const GiB = 2 ** 30;
const MiB = 2 ** 20;
/** The rings T-1111 keeps: 10 s points for an hour, 5 min points for a day. */
export const STEPS = { '15m': 10, '1h': 10, '6h': 300, '24h': 300 };
const SECONDS = { '15m': 900, '1h': 3600, '6h': 21600, '24h': 86400 };

const NODES = {
  alpha: { cpus: 4, memTotal: 16 * GiB, diskTotal: 240 * GiB, busy: 0.34, phase: 0 },
  beta: { cpus: 8, memTotal: 32 * GiB, diskTotal: 480 * GiB, busy: 0.18, phase: 2.1 },
  gamma: { cpus: 4, memTotal: 8 * GiB, diskTotal: 120 * GiB, busy: 0.52, phase: 4.2 },
};
const WORKLOADS = {
  'default/web': { node: 'alpha', cores: 0.42, mem: 180 * MiB, phase: 0.4 },
  'default/web@beta': { node: 'beta', cores: 0.21, mem: 150 * MiB, phase: 2.2 },
  'default/queue': { node: 'beta', cores: 0.11, mem: 96 * MiB, phase: 1.7 },
  'default/mail': { node: 'gamma', cores: 0.03, mem: 24 * MiB, phase: 3.3 },
};

const round = (value, places) => Number(value.toFixed(places));
const wave = (t, period, phase) => Math.sin((t / period) * 2 * Math.PI + phase);
/** Bursts: mostly quiet, now and then a lot. */
const burst = (t, period, phase) => Math.max(0, wave(t, period, phase)) ** 6;

/**
 * The answer for `range` ending at `end` (unix seconds). `missing` names nodes that did not
 * answer; `gap` blanks a few points of alpha's and web's (a restart), where there are enough.
 */
export function fixture(range = '1h', end = 1_800_000_000, { missing = [], gap = true } = {}) {
  const step = STEPS[range] ?? 10;
  const count = Math.floor((SECONDS[range] ?? 3600) / step);
  const at = Array.from({ length: count }, (_, i) => end - step * (count - 1 - i));
  const hole = (i) => gap && count > 20 && i >= Math.floor(count * 0.62) && i < Math.floor(count * 0.62) + 3;
  const nodes = {};
  for (const [name, node] of Object.entries(NODES)) {
    if (missing.includes(name)) {
      const nulls = at.map(() => null);
      nodes[name] = { cpu: nulls, cpus: 0, mem: nulls, memTotal: 0, disk: nulls, diskTotal: 0, diskRead: nulls, diskWrite: nulls, rx: nulls, tx: nulls, load1: nulls, missing: true };
      continue;
    }
    const series = (make) => at.map((t, i) => (name === 'alpha' && hole(i) ? null : make(t)));
    const cpu = series((t) => round(Math.min(1, Math.max(0.01, node.busy + 0.16 * wave(t, 1500, node.phase) + 0.06 * wave(t, 170, node.phase * 3))), 4));
    nodes[name] = {
      cpu,
      cpus: node.cpus,
      mem: series((t) => Math.round(node.memTotal * (0.38 + node.busy * 0.4 + 0.05 * wave(t, 2700, node.phase)))),
      memTotal: node.memTotal,
      disk: series((t) => Math.round(node.diskTotal * (0.31 + node.busy * 0.3) + (t - at[0]) * 4096)),
      diskTotal: node.diskTotal,
      diskRead: series((t) => Math.round(220e3 + 38 * MiB * burst(t, 900, node.phase))),
      diskWrite: series((t) => Math.round(640e3 + 22 * MiB * burst(t, 640, node.phase + 1))),
      rx: series((t) => Math.round(90e3 + 12 * MiB * burst(t, 1100, node.phase + 2))),
      tx: series((t) => Math.round(40e3 + 5 * MiB * burst(t, 1300, node.phase + 0.5))),
      load1: cpu.map((value) => (value == null ? null : round(value * node.cpus * 0.9, 2))),
    };
  }
  const workloads = {};
  for (const [key, one] of Object.entries(WORKLOADS)) {
    if (missing.includes(one.node)) continue;
    const series = (make) => at.map((t, i) => (key === 'default/web' && hole(i) ? null : make(t)));
    workloads[key] = {
      node: one.node,
      cpu: series((t) => round(one.cores * (1 + 0.5 * wave(t, 1200, one.phase)), 4)),
      mem: series((t) => Math.round(one.mem * (1 + 0.08 * wave(t, 3000, one.phase)))),
    };
  }
  return { range, step, end, nodes, workloads };
}
