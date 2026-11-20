// The overview: the cluster at a glance, the way a dashboard puts it. Four tiles across the
// top, a panel per measure with a line per node, the busiest workloads and what was done
// lately. The figures are `GET /v1/metrics?range=R` (T-1111), asked again every ten seconds
// while the overview is in view; a kithd that keeps none gets one calm line, not an error.
//
// The functions above `dashPart` are plain, so that `node test.mjs` runs them; `dashPart`
// draws with the `h` and `$` it is given. The charts are SVG drawn here: no library.
import { health, keyOf } from './forms.js';

export const RANGES = ['15m', '1h', '6h', '24h'];
/** A range kithd answers: an hour unless another of the four is asked for. */
export const rangeOf = (asked) => (RANGES.includes(asked) ? asked : '1h');
/** How often the figures are asked for again, in ms. */
const EVERY = 10_000;

/** The panels, in order: a measure each (two in a panel are drawn solid, then dashed). */
export const PANELS = [
  { id: 'cpu', title: 'CPU', unit: 'pct', series: ['cpu'] },
  { id: 'mem', title: 'Memory', unit: 'bytes', series: ['mem'] },
  { id: 'disk', title: 'Disk used', unit: 'bytes', series: ['disk'] },
  { id: 'io', title: 'Disk read and write', unit: 'rate', series: ['diskRead', 'diskWrite'], labels: ['read', 'write'] },
  { id: 'net', title: 'Network in and out', unit: 'rate', series: ['rx', 'tx'], labels: ['in', 'out'] },
  { id: 'load', title: 'Load', unit: 'num', series: ['load1'] },
];

const answered = (node) => node && !node.missing && Array.isArray(node.cpu);
/** The latest value of `values` that is there, or null. */
const lastOf = (values) => (Array.isArray(values) ? values.findLast((value) => value != null) : undefined) ?? null;
const round = (value) => Math.round(value * 10) / 10;
const clean = (value) => Number(value.toPrecision(12));

/** The time (unix seconds) of each point of `metrics`: the newest at `end`, `step` apart. */
export function times(metrics) {
  const node = Object.values(metrics?.nodes ?? {}).find(answered);
  const count = node ? node.cpu.length : 0;
  return Array.from({ length: count }, (_, i) => metrics.end - metrics.step * (count - 1 - i));
}

/**
 * `values` as an SVG path `width` × `height`: the oldest at the left, the newest at the right
 * edge, `max` at the top. A null lifts the pen; a point alone is still drawn (a dot of the cap).
 */
export function line(values, { width, height, min = 0, max }) {
  const count = values.length;
  const span = max - min || 1;
  const x = (i) => round(count > 1 ? (i * width) / (count - 1) : width);
  const y = (value) => round(height - Math.min(1, Math.max(0, (value - min) / span)) * height);
  let d = '';
  let run = 0;
  values.forEach((value, i) => {
    if (value == null) {
      if (run === 1) d += 'h0';
      run = 0;
      return;
    }
    d += `${run ? 'L' : 'M'}${x(i)} ${y(value)}`;
    run++;
  });
  return run === 1 ? `${d}h0` : d;
}

/** 1, 2, 2.5, 5 or 10 times a power of ten: the least of them that is at least `value`. */
function nice(value) {
  const power = 10 ** Math.floor(Math.log10(value));
  return [1, 2, 2.5, 5, 10].find((n) => n * power >= value * (1 - 1e-9)) * power;
}

/**
 * An axis up to `max` in `unit` (pct, bytes, rate or num): `{ top, ticks }`. A fraction is 0 to
 * 100 % in quarters; bytes and rates go in whole binary units; four steps at most.
 */
export function scale(max, unit) {
  if (unit === 'pct') return { top: 1, ticks: [0, 0.25, 0.5, 0.75, 1] };
  const base = unit === 'bytes' || unit === 'rate' ? 1024 : 1;
  if (!(max > 0) || !Number.isFinite(max)) return { top: base, ticks: [0, base] };
  const size = base === 1 ? 1 : base ** Math.max(0, Math.floor(Math.log(max) / Math.log(base)));
  const step = nice(max / size / 4) * size;
  const count = Math.max(1, Math.ceil(max / step - 1e-9));
  const ticks = Array.from({ length: count + 1 }, (_, i) => clean(i * step));
  return { top: ticks.at(-1), ticks };
}

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
/** `value` in `unit` the way a person says it; a dash where there is none. */
export function format(value, unit) {
  if (value == null || !Number.isFinite(value)) return '–';
  if (unit === 'pct') {
    const pct = value * 100;
    return `${pct !== 0 && Math.abs(pct) < 1 ? Number(pct.toFixed(1)) : Math.round(pct)}%`;
  }
  if (unit === 'num') return Math.abs(value) >= 10 ? value.toFixed(1) : String(Number(value.toFixed(2)));
  let size = Math.abs(value);
  let i = 0;
  while (size >= 1024 && i < UNITS.length - 1) {
    size /= 1024;
    i++;
  }
  const said = i === 0 || size >= 10 ? Math.round(size) : Number(size.toFixed(1));
  return `${value < 0 ? '-' : ''}${said} ${UNITS[i]}${unit === 'rate' ? '/s' : ''}`;
}

/** Each node's colour, 1 to 6 in the order of their names, 0 (dim) past the sixth: never one twice. */
export function hues(metrics) {
  const names = Object.keys(metrics?.nodes ?? {}).sort();
  return new Map(names.map((name, i) => [name, i < 6 ? i + 1 : 0]));
}

/** Sums point by point of what is there; null where nothing is. */
function sums(arrays, count) {
  return Array.from({ length: count }, (_, i) => {
    const there = arrays.map((values) => values?.[i]).filter((value) => value != null);
    return there.length ? there.reduce((sum, value) => sum + value, 0) : null;
  });
}

/**
 * The tiles: nodes and workloads ready (from the cluster's resources), CPU (cores) and memory
 * (bytes) used of the total of the nodes that answered, and how many answered, point by point.
 */
export function tiles(resources, metrics) {
  const of = (kind) => resources.filter((resource) => resource.kind === kind);
  const ready = (list) => ({ ready: list.filter((one) => health(one) === 'ok').length, total: list.length });
  const workloads = of('Workload');
  const counted = workloads.map((one) => one.status ?? {}).filter((status) => Number.isInteger(status.ready) && Number.isInteger(status.replicas));
  const nodes = Object.values(metrics?.nodes ?? {}).filter(answered);
  const count = nodes.length ? Math.max(...nodes.map((node) => node.cpu.length)) : 0;
  const read = nodes.filter((node) => lastOf(node.mem) != null && node.memTotal > 0);
  const none = { used: null, total: null, series: [] };
  const measure = (series, total) => ({ used: lastOf(series), total, series });
  return {
    nodes: ready(of('Node')),
    workloads: ready(workloads),
    replicas: {
      ready: counted.reduce((sum, status) => sum + status.ready, 0),
      total: counted.reduce((sum, status) => sum + status.replicas, 0),
    },
    cpu: nodes.length
      ? measure(sums(nodes.map((node) => node.cpu.map((value) => (value == null ? null : value * node.cpus))), count), nodes.reduce((sum, node) => sum + node.cpus, 0))
      : none,
    // (A node whose memory kithd could not read is left out, not counted as none used of its total.)
    mem: read.length ? measure(sums(read.map((node) => node.mem), count), read.reduce((sum, node) => sum + node.memTotal, 0)) : none,
    reporting: Array.from({ length: count }, (_, i) => nodes.filter((node) => node.cpu[i] != null).length),
  };
}

/**
 * The workloads, busiest first: by CPU now, then memory, then name. kithd answers a Workload on
 * several nodes as `NS/NAME` and `NS/NAME@NODE`: here it is one row, its nodes' use summed.
 */
export function busiest(metrics) {
  const each = new Map();
  for (const [key, one] of Object.entries(metrics?.workloads ?? {})) {
    const name = key.split('@')[0];
    each.set(name, [...(each.get(name) ?? []), one]);
  }
  return [...each]
    .map(([key, parts]) => {
      const count = Math.max(...parts.map((one) => one.cpu?.length ?? 0));
      const cpu = sums(parts.map((one) => one.cpu), count);
      const mem = sums(parts.map((one) => one.mem), count);
      return { key, nodes: [...new Set(parts.map((one) => one.node))].sort(), cpu: lastOf(cpu), mem: lastOf(mem), series: cpu };
    })
    .sort((a, b) => (b.cpu ?? -1) - (a.cpu ?? -1) || (b.mem ?? -1) - (a.mem ?? -1) || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

const two = (n) => String(n).padStart(2, '0');
const clock = (at) => {
  const date = new Date(at * 1000);
  return `${two(date.getHours())}:${two(date.getMinutes())}`;
};
/** How long ago `at` (unix seconds) was, shortly. */
function ago(at) {
  if (!Number.isFinite(at)) return '';
  const seconds = Math.max(0, Date.now() / 1000 - at);
  return seconds < 60 ? 'just now'
    : seconds < 3600 ? `${Math.floor(seconds / 60)} min ago`
    : seconds < 86400 ? `${Math.floor(seconds / 3600)} h ago`
    : new Date(at * 1000).toISOString().slice(0, 10);
}

/**
 * The overview, drawn into the page: `show(view)` ('dash', 'events' or false) puts it in view
 * and keeps it fresh; `refresh()` asks kithd now; `redraw()` draws what the cluster's state
 * says again (the watch calls it). `still()` is true where motion is not wanted.
 */
export function dashPart({ $, h, api, state, still }) {
  let range = '1h';
  let metrics = null;
  let why = null;
  let audit = null;
  let auditWhy = null;
  let shown = false;
  let timer = null;
  let turns = 0;
  let plots = [];
  /** The point under the pointer (or the keys), shared by every panel: its index, or null. */
  let at = null;

  const whyNot = () =>
    why?.status === 404 ? 'No metrics yet: this kithd does not keep them.'
    : why?.status === 403 ? 'No metrics to show you: they are for those who may read Nodes.'
    : why && !why.status ? 'No metrics yet: kithd does not answer.'
    : why ? `No metrics yet: kithd says ${why.message}`
    : 'No metrics yet: no node has sent any.';

  function drawRanges() {
    $('ranges').replaceChildren(...RANGES.map((one) =>
      h('button', { type: 'button', class: 'range', 'aria-pressed': String(one === range), onclick: () => pick(one) }, one)));
  }
  function pick(one) {
    range = rangeOf(one);
    drawRanges();
    return refresh();
  }

  // ── The tiles ──
  const spark = (series, max) =>
    h('svg', { class: 'spark', viewBox: '0 0 120 32', preserveAspectRatio: 'none', 'aria-hidden': 'true' },
      h('path', { class: 'spark-line', d: line(series, { width: 120, height: 30, max: max || 1 }), transform: 'translate(0 1)' }));
  const tile = (title, value, about, picture) =>
    h('section', { class: 'tile' }, h('h3', {}, title), h('p', { class: 'value' }, value), h('p', { class: 'dim' }, about), picture);
  function drawTiles() {
    const sum = tiles(state.resources, metrics);
    const { cpu, mem } = sum;
    const workloads = state.resources.filter((resource) => resource.kind === 'Workload');
    const reporting = lastOf(sum.reporting);
    $('tiles').replaceChildren(
      tile('Nodes ready', `${sum.nodes.ready} of ${sum.nodes.total}`,
        metrics ? `${reporting ?? 0} sending metrics` : 'from the cluster’s state',
        metrics && spark(sum.reporting, Object.keys(metrics.nodes).length)),
      tile('Workloads ready', `${sum.workloads.ready} of ${sum.workloads.total}`, `${sum.replicas.ready} of ${sum.replicas.total} replicas`,
        h('div', { class: 'stops', 'aria-hidden': 'true' }, workloads.slice(0, 24).map((one) => h('span', { class: `stop ${health(one)}`, title: keyOf(one) })))),
      tile('CPU used', format(cpu.used == null ? null : cpu.used / cpu.total, 'pct'),
        cpu.total == null ? 'no metrics' : `${format(cpu.used, 'num')} of ${cpu.total} cores`, cpu.total != null && spark(cpu.series, cpu.total)),
      tile('Memory used', format(mem.used == null ? null : mem.used / mem.total, 'pct'),
        mem.total == null ? 'no metrics' : `${format(mem.used, 'bytes')} of ${format(mem.total, 'bytes')}`, mem.total != null && spark(mem.series, mem.total)),
    );
  }

  // ── The panels ──
  function drawCharts() {
    const box = $('charts');
    plots = [];
    at = null;
    const when = metrics ? times(metrics) : [];
    if (!metrics || when.length === 0) return box.replaceChildren(h('p', { class: 'dim empty' }, whyNot()));
    const hue = hues(metrics);
    const names = [...hue.keys()];
    box.replaceChildren(...PANELS.map((panel) => {
      const svg = h('svg', { class: 'chart', role: 'img', tabindex: '0', 'aria-label': `${panel.title}, a line per node, the last ${range}` });
      const values = new Map();
      const legend = h('ul', { class: 'legend' }, names.map((name) => {
        const node = metrics.nodes[name];
        if (!answered(node)) return h('li', { class: 'missing' }, h('span', { class: 'swatch', 'aria-hidden': 'true' }), h('span', { class: 'name' }, name), h('span', { class: 'value' }, 'no answer'));
        const value = h('span', { class: 'value' }, '');
        values.set(name, value);
        return h('li', {}, h('span', { class: `swatch s${hue.get(name)}`, 'aria-hidden': 'true' }), h('span', { class: 'name' }, name), value);
      }));
      const tip = h('div', { class: 'tip', hidden: true, 'aria-hidden': 'true' });
      const plot = { panel, svg, tip, values, when, hue };
      plots.push(plot);
      svg.addEventListener('pointermove', (event) => {
        const box = svg.getBoundingClientRect();
        const x = ((event.clientX - box.left) / (box.width || 1)) * plot.width;
        hover(Math.round((Math.min(Math.max(x, 0), plot.width) / plot.width) * (when.length - 1)), plot);
      });
      svg.addEventListener('pointerleave', () => hover(null));
      svg.addEventListener('blur', () => hover(null));
      svg.addEventListener('keydown', (event) => {
        const moves = { ArrowLeft: -1, ArrowRight: 1, Home: -Infinity, End: Infinity };
        if (event.key === 'Escape') return hover(null);
        if (!(event.key in moves)) return;
        event.preventDefault();
        hover(Math.min(when.length - 1, Math.max(0, (at ?? when.length - 1) + moves[event.key])), plot);
      });
      return h('section', { class: 'chart-panel', 'data-panel': panel.id }, h('h3', {}, panel.title), svg, tip, legend);
    }));
    plots.forEach(plotOne);
    hover(null);
  }

  const HEIGHT = 180;
  const TOP = 18;
  const BOTTOM = 22;
  /** Draws one panel's lines to the width it has. */
  function plotOne(plot) {
    const { panel, svg, when, hue } = plot;
    const width = Math.max(Math.round(svg.getBoundingClientRect().width), 240);
    const right = width - 8;
    const inner = HEIGHT - TOP - BOTTOM;
    const nodes = [...hue.keys()].filter((name) => answered(metrics.nodes[name]));
    let max = 0;
    for (const name of nodes) for (const key of panel.series) for (const value of metrics.nodes[name][key] ?? []) if (value > max) max = value;
    const { top, ticks } = scale(max, panel.unit);
    const y = (value) => TOP + inner - Math.min(1, Math.max(0, value / top)) * inner;
    const x = (i) => (when.length > 1 ? (i * right) / (when.length - 1) : right);
    Object.assign(plot, { width, right, x, y });
    svg.setAttribute('viewBox', `0 0 ${width} ${HEIGHT}`);
    svg.setAttribute('height', String(HEIGHT));
    const drawn = [];
    // (The axis's figures go over the lines, haloed in paper, so a line never strikes one out.)
    const figures = [];
    for (const tick of ticks) {
      const gy = round(y(tick));
      drawn.push(h('line', { class: tick === 0 ? 'grid base' : 'grid', x1: 0, x2: width, y1: gy, y2: gy }));
      figures.push(h('text', { class: 'tick', x: 0, y: gy - 5 }, format(tick, panel.unit)));
    }
    const marks = when.length > 2 ? [0, Math.floor((when.length - 1) / 2), when.length - 1] : [when.length - 1];
    for (const i of marks) {
      const anchor = i === 0 && marks.length > 1 ? 'start' : i === when.length - 1 ? 'end' : 'middle';
      drawn.push(h('text', { class: 'tick', x: round(x(i)), y: HEIGHT - 4, 'text-anchor': anchor }, clock(when[i])));
    }
    const lines = [];
    const nows = [];
    const dots = [];
    const live = !still();
    for (const name of nodes) {
      panel.series.forEach((key, n) => {
        const values = metrics.nodes[name][key] ?? [];
        const d = line(values, { width: right, height: inner, max: top });
        const look = `s${hue.get(name)}${n ? ' second' : ''}`;
        if (d) lines.push(h('path', { class: `series ${look}`, d }));
        const last = values.at(-1);
        if (n === 0 && last != null) nows.push(h('circle', { class: `now s${hue.get(name)}${live ? ' live' : ''}`, cx: round(right), cy: round(y(last)), r: 4 }));
        const dot = h('circle', { class: `at ${look}`, r: 4.5, visibility: 'hidden' });
        dots.push({ dot, values });
      });
    }
    const cross = h('line', { class: 'cross', y1: TOP, y2: TOP + inner, visibility: 'hidden' });
    svg.replaceChildren(...drawn, h('g', { transform: `translate(0 ${TOP})` }, lines), ...figures, cross, ...nows, ...dots.map((one) => one.dot));
    Object.assign(plot, { cross, dots });
  }

  /** What `panel` says of node `name` at point `i` (null: the latest). */
  function said(panel, name, i) {
    const node = metrics.nodes[name];
    return panel.series.map((key, n) => {
      const value = i == null ? lastOf(node[key]) : node[key]?.[i];
      return `${panel.labels ? `${panel.labels[n]} ` : ''}${format(value, panel.unit)}`;
    }).join('  ');
  }

  /** The crosshair at point `i` in every panel (null: none), and the tip by the one pointed at. */
  function hover(i, source) {
    at = i;
    for (const plot of plots) {
      for (const [name, value] of plot.values) value.textContent = said(plot.panel, name, i);
      if (!plot.cross) continue;
      if (i == null) {
        plot.cross.setAttribute('visibility', 'hidden');
        plot.dots.forEach(({ dot }) => dot.setAttribute('visibility', 'hidden'));
        plot.tip.hidden = true;
        continue;
      }
      const cx = round(plot.x(i));
      plot.cross.setAttribute('x1', cx);
      plot.cross.setAttribute('x2', cx);
      plot.cross.setAttribute('visibility', 'visible');
      for (const { dot, values } of plot.dots) {
        const value = values[i];
        dot.setAttribute('visibility', value == null ? 'hidden' : 'visible');
        if (value != null) {
          dot.setAttribute('cx', cx);
          dot.setAttribute('cy', round(plot.y(value)));
        }
      }
      plot.tip.hidden = plot !== source;
      if (plot !== source) continue;
      plot.tip.replaceChildren(
        h('b', {}, clock(plot.when[i])),
        [...plot.values.keys()].map((name) =>
          h('span', { class: 'row' }, h('span', { class: `swatch s${plot.hue.get(name)}` }), h('span', { class: 'name' }, name), h('span', {}, said(plot.panel, name, i)))),
      );
      // (Beside the line, on the side with room.)
      const share = cx / plot.width;
      plot.tip.style.left = share > 0.55 ? '' : `${(share * 100).toFixed(1)}%`;
      plot.tip.style.right = share > 0.55 ? `${((1 - share) * 100).toFixed(1)}%` : '';
    }
  }

  // ── The workloads, busiest first ──
  function drawBusiest() {
    const hue = hues(metrics);
    const rows = busiest(metrics).slice(0, 10);
    const head = h('tr', {},
      h('th', { scope: 'col' }, 'Workload'),
      h('th', { scope: 'col' }, 'Node'),
      h('th', { scope: 'col', class: 'num' }, 'CPU cores'),
      h('th', { scope: 'col', class: 'num' }, 'Memory'),
      h('th', { scope: 'col' }, `last ${range}`));
    const link = (key) => `#/Workload/${key.split('/').map(encodeURIComponent).join('/')}`;
    const body = rows.map((one) => {
      const top = one.series.reduce((most, value) => (value > most ? value : most), 0);
      // (A line in its node's colour; one on several nodes is drawn in ink.)
      const look = one.nodes.length === 1 ? ` s${hue.get(one.nodes[0]) ?? 0}` : '';
      return h('tr', {},
        h('td', {}, h('a', { href: link(one.key) }, one.key)),
        h('td', { class: 'nodes' }, one.nodes.map((node) =>
          h('span', { class: 'node' }, h('span', { class: `swatch s${hue.get(node) ?? 0}`, 'aria-hidden': 'true' }), node))),
        h('td', { class: 'num' }, format(one.cpu, 'num')),
        h('td', { class: 'num' }, format(one.mem, 'bytes')),
        h('td', {}, h('svg', { class: 'spark small', viewBox: '0 0 96 20', preserveAspectRatio: 'none', 'aria-hidden': 'true' },
          h('path', { class: `spark-line${look}`, d: line(one.series, { width: 96, height: 18, max: top || 1 }), transform: 'translate(0 1)' }))),
      );
    });
    // (kithd answers only the namespaces the caller may read: none of them is an empty table, said
    // calmly, not an error; and with nothing in it, no head.)
    $('busiest').replaceChildren(...(rows.length
      ? [h('thead', {}, head), h('tbody', {}, body)]
      : [h('caption', { class: 'dim' }, metrics ? 'No workload you may see is running.' : 'No figures for workloads yet.')]));
  }

  // ── What was done ──
  function items(entries) {
    return [...entries].reverse().map((entry) => {
      const what = Array.isArray(entry.what) ? entry.what.map(String).join(', ') : '';
      return h('li', { class: entry.ok === false ? 'refused' : null },
        h('time', { datetime: Number.isFinite(entry.at) ? new Date(entry.at * 1000).toISOString() : null }, ago(entry.at)),
        h('span', { class: 'said' }, h('b', {}, String(entry.who ?? '')), ` ${entry.verb ?? ''} `, h('span', { class: 'what' }, what),
          entry.ok === false ? h('span', { class: 'error' }, ` refused: ${entry.error ?? ''}`) : null));
    });
  }
  function drawRecent() {
    const none = auditWhy?.status === 403 ? 'What was done is not yours to read: it takes get on Audit.'
      : auditWhy ? 'What was done: kithd does not say.'
      : 'Nothing done yet.';
    const entries = Array.isArray(audit) ? audit : [];
    for (const [id, count] of [['recent', 8], ['event-list', 200]]) {
      const shownItems = items(entries.slice(-count));
      $(id).replaceChildren(...(shownItems.length ? shownItems : [h('li', { class: 'dim' }, none)]));
    }
    $('events-said').textContent = entries.length ? `the last ${entries.length}, newest first` : '';
  }

  function draw() {
    $('dash-said').textContent = metrics ? `the last ${range}, every ${EVERY / 1000} s` : '';
    drawRanges();
    drawTiles();
    drawCharts();
    drawBusiest();
    drawRecent();
  }

  function schedule() {
    clearTimeout(timer);
    if (shown) timer = setTimeout(tick, EVERY);
  }
  function tick() {
    // (Out of sight in the browser: asked again when it is back, not now.)
    if (typeof document !== 'undefined' && document.hidden) return schedule();
    refresh();
  }
  async function refresh() {
    const turn = ++turns;
    const asked = range;
    const answer = (call) => call.then((value) => [value, null], (error) => [null, error]);
    const [[got, gotWhy], [log, logWhy]] = await Promise.all([
      answer(api('GET', `metrics?range=${asked}`)),
      answer(api('GET', `audit?tail=${shown === 'events' ? 200 : 12}`)),
    ]);
    // (A slower answer to an older question changes nothing.)
    if (turn !== turns || asked !== range) return;
    [metrics, why] = got && typeof got === 'object' && got.nodes && typeof got.nodes === 'object' ? [got, null] : [null, gotWhy];
    [audit, auditWhy] = [log, logWhy];
    try {
      draw();
    } finally {
      schedule();
    }
  }

  if (typeof ResizeObserver !== 'undefined') {
    let width = 0;
    new ResizeObserver(() => {
      const now = $('charts').clientWidth;
      if (now === width) return;
      width = now;
      plots.forEach(plotOne);
      hover(null);
    }).observe($('charts'));
  }

  return {
    refresh,
    redraw: drawTiles,
    show(view) {
      shown = view || false;
      if (shown) refresh();
      else clearTimeout(timer);
    },
  };
}
