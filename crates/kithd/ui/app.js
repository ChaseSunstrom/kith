// The kith board: what the cluster holds, live, and a form for every kind of it.
// It asks kithd what `kith` asks, as whoever the browser is to kithd; every change is
// one of `kith`'s calls, made after its diff has been shown.
//
// What is shown is other people's text (names, messages, logs): it goes into the page as
// text nodes only, and the page's policy allows no script or style but its own files.
import { at, blank, diffLines, entriesCheck, health, keyOf, lamps, resourceOf, shape, summary, written } from './forms.js';

const $ = (id) => document.getElementById(id);
const PROPERTIES = new Set(['value', 'checked', 'disabled', 'hidden', 'open', 'readOnly', 'selected']);

/** An element. Children that are strings become text, never markup. */
function h(tag, props = {}, ...children) {
  const el = tag === 'svg' || SVG.has(tag) ? document.createElementNS('http://www.w3.org/2000/svg', tag) : document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value == null || value === false) continue;
    if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else if (PROPERTIES.has(key)) el[key] = value;
    else el.setAttribute(key, value === true ? '' : value);
  }
  el.append(...children.flat(3).filter((child) => child != null && child !== false));
  return el;
}
const SVG = new Set(['g', 'circle', 'line', 'path', 'text', 'title', 'rect', 'animateMotion']);

const state = {
  caller: '',
  kinds: [],
  resources: [],
  generation: null,
  /** The kind listed in panel 03. */
  kind: null,
  /** The resource open in panel 04: its key, `+` for a new one, or null. */
  key: null,
  tab: 'form',
  /** What is being edited: { doc, base, yaml, mode, dirty }. */
  draft: null,
  filter: '',
};

const kindNamed = (name) => state.kinds.find((kind) => kind.kind.toLowerCase() === String(name).toLowerCase());
const live = (key) => state.resources.find((resource) => keyOf(resource) === key);
const may = (verb, kind = kindNamed(state.kind)) => Boolean(kind?.may.includes(verb));
const path = (key) => key.split('/').map(encodeURIComponent).join('/');
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/** One call of kithd's API; an error carries what kithd said. */
async function api(method, what, body) {
  const asked = await fetch(`../v1/${what}`, {
    method,
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await asked.text();
  let said = text;
  try {
    said = JSON.parse(text);
  } catch {
    // (Not JSON: said as it is.)
  }
  if (!asked.ok) {
    const error = new Error(said?.error ?? (text || `${asked.status} ${asked.statusText}`));
    error.status = asked.status;
    throw error;
  }
  return said;
}

function toast(text, bad = false) {
  const line = h('div', { class: bad ? 'toast bad' : 'toast' }, text);
  $('toasts').append(line);
  setTimeout(() => line.remove(), bad ? 8000 : 4000);
}

function say(el, text, how = 'dim') {
  el.className = `check ${how}`;
  el.textContent = text;
}

// ── The dialog: nothing is changed without one ──────────────────────────────────────

/**
 * Ask before doing. `act` does it when the answer is yes; while it fails, the dialog
 * stays and says why (an error with a `body` replaces what is shown: look again).
 * Resolves to what `act` gave, or undefined when the answer was no.
 */
function ask({ title, body, yes, danger = false, act = async () => true }) {
  const [dialog, said, no, go] = [$('dialog'), $('dialog-said'), $('dialog-no'), $('dialog-yes')];
  $('dialog-title').textContent = title;
  $('dialog-body').replaceChildren(body);
  say(said, '');
  go.hidden = !yes;
  go.textContent = yes ?? '';
  go.className = danger ? 'danger' : 'primary';
  no.textContent = yes ? 'Cancel' : 'Close';
  return new Promise((done) => {
    const finish = (result) => {
      go.onclick = no.onclick = dialog.oncancel = null;
      dialog.close();
      done(result);
    };
    no.onclick = () => finish(undefined);
    dialog.oncancel = (event) => {
      event.preventDefault();
      finish(undefined);
    };
    go.onclick = async () => {
      go.disabled = no.disabled = true;
      say(said, 'working');
      try {
        finish(await act());
      } catch (error) {
        if (error.body) $('dialog-body').replaceChildren(error.body);
        say(said, error.message, 'bad');
      } finally {
        go.disabled = no.disabled = false;
      }
    };
    dialog.showModal();
    (yes && !danger ? go : no).focus();
  });
}

/** A plan (what `/v1/diff` said) to read: each resource, what happens to it, its diff. */
function planView(plan) {
  return h('div', { class: 'plan' }, plan.map((change) =>
    h('section', {},
      h('h3', { class: change.action }, `${change.action} `, h('b', {}, change.key)),
      change.diff && h('pre', { class: 'diff' }, diffLines(change.diff).map((line) => h('span', { class: line.what }, `${line.text}\n`))),
    ),
  ));
}

// ── Panel 01: kinds ─────────────────────────────────────────────────────────────────

function drawKinds() {
  const counts = new Map();
  for (const resource of state.resources) counts.set(resource.kind, (counts.get(resource.kind) ?? 0) + 1);
  const link = (kind) =>
    h('a', { href: `#/${kind.kind}`, 'aria-current': kind.kind === state.kind ? 'page' : null, title: kind.about },
      h('span', {}, kind.kind),
      h('span', { class: 'count' }, String(counts.get(kind.kind) ?? '')),
    );
  const group = (title, kinds) => kinds.length > 0 && [h('h3', {}, title), h('ul', {}, kinds.map((kind) => h('li', {}, link(kind))))];
  $('kinds').replaceChildren(...[
    group('of kith', state.kinds.filter((kind) => !kind.definition)),
    group('of this cluster', state.kinds.filter((kind) => kind.definition)),
  ].flat().filter(Boolean));
  $('kinds').querySelector('[aria-current]')?.scrollIntoView({ block: 'nearest' });
  if (state.kinds.length === 0) $('kinds').append(h('p', { class: 'dim' }, 'No kind is yours to see: no Role is bound to you.'));
}

// ── Panel 02: pulse ─────────────────────────────────────────────────────────────────

/** The nodes as a lit mesh, and a lamp for every replica of everything that runs. */
function drawPulse() {
  const nodes = state.resources.filter((resource) => resource.kind === 'Node');
  const running = state.resources
    .map((resource) => ({ resource, lamps: lamps(resource) }))
    .filter((entry) => entry.lamps.length > 0)
    // (What is not well comes first: there is room for a dozen.)
    .sort((a, b) => Number(health(b.resource) !== 'ok') - Number(health(a.resource) !== 'ok'));
  const lampCount = running.reduce((sum, entry) => sum + entry.lamps.length, 0);
  const lit = running.reduce((sum, entry) => sum + entry.lamps.filter((lamp) => lamp.state === 'ok').length, 0);
  const up = nodes.filter((node) => health(node) !== 'bad').length;
  $('pulse-said').textContent = nodes.length + lampCount === 0
    ? 'no nodes or replicas to show'
    : `${up}/${nodes.length} nodes up · ${lit}/${lampCount} replicas ready`;

  // Drawn to the width there is: side by side on a desk, the lamps under the mesh on a phone.
  const svg = $('pulse');
  const width = Math.max(svg.clientWidth, 300);
  const wide = width >= 760;
  const rows = running.slice(0, 12);
  const perColumn = wide ? 4 : Math.max(1, Math.ceil(rows.length / Math.max(1, Math.floor(width / 230))));
  const height = wide ? 150 : 150 + perColumn * 28;
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('height', String(height));
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const drawn = [];
  // The mesh, as the mark draws it: a hub (the cluster's store), and a line out to every node,
  // with what passes between them on it.
  const span = wide ? 460 : width;
  const hub = [44, 75];
  const shown = nodes.slice(0, 8);
  const place = (i) => [
    shown.length === 1 ? Math.min(220, span - 60) : 150 + (i * (span - 210)) / (shown.length - 1),
    shown.length < 3 ? 75 : i % 2 ? 104 : 46,
  ];
  shown.forEach((node, i) => {
    const [x, y] = place(i);
    const down = health(node) === 'bad';
    const way = `M ${hub[0]} ${hub[1]} C ${hub[0] + 60} ${hub[1]} ${x - 60} ${y} ${x} ${y}`;
    drawn.push(h('path', { class: down ? 'mesh bad' : 'mesh', d: way }));
    if (down || still) return;
    // (Out and back, each node out of step with the last.)
    for (const [points, begin] of [['0;1', i * -0.7], ['1;0', i * -0.7 - 1.3]]) {
      drawn.push(h('circle', { class: 'packet', r: 2.5 },
        h('animateMotion', { path: way, dur: '2.6s', begin: `${begin}s`, repeatCount: 'indefinite', keyPoints: points, keyTimes: '0;1', calcMode: 'linear' })));
    }
  });
  if (shown.length > 0) drawn.push(h('circle', { class: 'halo', cx: hub[0], cy: hub[1], r: 9 }), h('circle', { class: 'hub', cx: hub[0], cy: hub[1], r: 9 }));
  shown.forEach((node, i) => {
    const [x, y] = place(i);
    drawn.push(h('g', { class: `node ${health(node)}` },
      h('title', {}, `${keyOf(node)}: ${summary(node) || 'no status'}`),
      h('circle', { class: 'halo', cx: x, cy: y, r: 9 }),
      h('circle', { class: 'body', cx: x, cy: y, r: 9 }),
      h('circle', { class: 'core', cx: x, cy: y, r: 3.5 }),
      h('text', { class: 'name', x, y: y + 28, 'text-anchor': 'middle' }, node.metadata.name.slice(0, 12)),
    ));
  });
  if (nodes.length > shown.length) drawn.push(h('text', { x: span - 8, y: 144, 'text-anchor': 'end' }, `+${nodes.length - shown.length} nodes`));
  // The lamps: a row per thing that runs, a lamp per replica.
  rows.forEach((entry, i) => {
    const [left, top] = [(wide ? 500 : 8) + Math.floor(i / perColumn) * 230, (wide ? 30 : 166) + (i % perColumn) * 28];
    const name = entry.resource.metadata.name;
    const ready = entry.lamps.filter((lamp) => lamp.state === 'ok').length;
    drawn.push(h('g', {},
      h('title', {}, `${keyOf(entry.resource)}: ${summary(entry.resource)}`),
      h('text', { class: 'name', x: left, y: top + 4 }, name.length > 12 ? `${name.slice(0, 11)}…` : name),
      entry.lamps.slice(0, 6).map((lamp, n) => {
        const bar = h('rect', { class: `lamp ${lamp.state}`, x: left + 96 + n * 15, y: top - 4, width: 12, height: 8, rx: 4 });
        // (Each a little out of step with the last: a row of them breathes, it does not blink.)
        bar.style.setProperty('--step', String((i * 3 + n) % 8));
        return bar;
      }),
      h('text', { x: left + 100 + Math.min(entry.lamps.length, 6) * 15, y: top + 4 }, `${ready}/${entry.lamps.length}`),
    ));
  });
  if (running.length > rows.length) drawn.push(h('text', { x: width - 8, y: height - 6, 'text-anchor': 'end' }, `+${running.length - rows.length} more`));
  svg.replaceChildren(...drawn);
}

// ── Panel 03: the resources of a kind ───────────────────────────────────────────────

/** key → revision at the last draw: a row whose revision moved is flashed once. */
const drawnRevisions = new Map();

function drawTable() {
  const kind = kindNamed(state.kind);
  $('list-kind').textContent = kind?.kind ?? 'Resources';
  $('list-about').textContent = kind?.about ?? '';
  $('new').hidden = !may('apply');
  const table = $('table');
  if (!kind) return table.replaceChildren();
  const columns = kind.columns.length ? kind.columns : [{ name: 'Status', path: null }];
  const wanted = state.filter.toLowerCase();
  const rows = state.resources
    .filter((resource) => resource.kind === kind.kind)
    .filter((resource) => keyOf(resource).toLowerCase().includes(wanted));
  const head = h('tr', {},
    kind.namespaced && h('th', { scope: 'col' }, 'Namespace'),
    h('th', { scope: 'col' }, 'Name'),
    columns.map((column) => h('th', { scope: 'col' }, column.name)),
    h('th', { scope: 'col', class: 'num' }, 'Rev'),
  );
  const first = drawnRevisions.size === 0;
  const body = rows.map((resource) => {
    const key = keyOf(resource);
    const moved = !first && drawnRevisions.get(key) !== resource.metadata.revision;
    const cell = (column) => {
      const value = column.path ? at(resource, column.path) : summary(resource);
      return value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
    };
    return h('tr', { class: [key === state.key && 'current', moved && 'flash'].filter(Boolean).join(' ') || null },
      kind.namespaced && h('td', { class: 'dim' }, resource.metadata.namespace ?? ''),
      h('td', {}, h('span', { class: `lamp-text ${health(resource)}`, 'aria-hidden': 'true' }, '●'), ' ',
        h('a', { href: `#/${path(key)}` }, resource.metadata.name)),
      columns.map((column) => h('td', {}, cell(column))),
      h('td', { class: 'num dim' }, String(resource.metadata.revision ?? '')),
    );
  });
  drawnRevisions.clear();
  for (const resource of state.resources) drawnRevisions.set(keyOf(resource), resource.metadata.revision);
  table.replaceChildren(h('thead', {}, head), h('tbody', {}, body));
  if (rows.length === 0) {
    const none = wanted ? `Nothing of this kind matches “${state.filter}”.` : `No ${kind.kind} yet${may('apply') ? ': New makes one.' : '.'}`;
    table.append(h('caption', { class: 'dim' }, none));
  }
}

// ── Panel 04: one resource ──────────────────────────────────────────────────────────

let ids = 0;

/** The control for one value of `node`'s shape; `change(value)` whenever it is edited (`undefined`: not set). */
function control(node, root, value, change, { required = false, id, label } = {}) {
  const { kind, schema } = shape(node, root);
  const named = { id, 'aria-label': id ? null : label };
  const choice = (options, current) => {
    const pick = h('select', { ...named, onchange: () => change(pick.value === '' ? undefined : options[Number(pick.value)]) },
      h('option', { value: '' }, required ? 'choose' : 'not set'),
      options.map((option, i) => h('option', { value: String(i) }, String(option))),
    );
    pick.value = options.includes(current) ? String(options.indexOf(current)) : '';
    return pick;
  };
  switch (kind) {
    case 'const':
      return h('output', named, String(schema.const));
    case 'boolean':
      return choice([true, false], value);
    case 'enum':
      return choice(schema.enum, value);
    case 'number': {
      const input = h('input', { ...named, type: 'number', inputmode: 'decimal', min: schema.minimum, max: schema.maximum,
        step: schema.type === 'integer' ? '1' : 'any', value: value ?? '',
        oninput: () => change(input.value === '' ? undefined : Number(input.value)) });
      return input;
    }
    case 'string': {
      const long = typeof value === 'string' && value.includes('\n');
      const input = h(long ? 'textarea' : 'input', { ...named, type: long ? null : 'text', rows: long ? '6' : null, spellcheck: 'false',
        autocomplete: 'off', value: value ?? '',
        oninput: () => change(input.value === '' ? undefined : schema.orNumber && String(Number(input.value)) === input.value ? Number(input.value) : input.value) });
      return input;
    }
    case 'object':
      return fields(schema, root, value, change);
    case 'array': {
      const items = Array.isArray(value) ? [...value] : [];
      const one = label ?? 'item';
      const box = h('div', { class: 'items' });
      const draw = () => box.replaceChildren(
        ...items.map((item, i) => h('div', { class: 'item' },
          control(schema.items, root, item, (next) => { items[i] = next; change(items); }, { required: true, label: `${one} ${i + 1}` }),
          h('button', { type: 'button', class: 'small', 'aria-label': `Remove ${one} ${i + 1}`,
            onclick: () => { items.splice(i, 1); change(items); draw(); } }, '×'),
        )),
        h('button', { type: 'button', class: 'small', onclick: () => { items.push(undefined); change(items); draw(); box.querySelector('.item:last-of-type :is(input, select, textarea)')?.focus(); } }, `+ ${one}`),
      );
      draw();
      return box;
    }
    case 'map': {
      const entries = Object.entries(value ?? {});
      const emit = () => change(Object.fromEntries(entries.filter(([key]) => key !== '')));
      const one = label ?? 'entry';
      const box = h('div', { class: 'items' });
      // A row with no name, or a name another row has, is not written: say so on the row (Review is held while one stands).
      const mark = () => {
        const wrong = entriesCheck(entries);
        box.querySelectorAll('.item').forEach((row, i) => {
          const input = row.querySelector('.key');
          const note = row.querySelector('.row-error');
          if (wrong[i]) {
            input.setAttribute('aria-invalid', 'true');
            if (note) note.textContent = wrong[i];
            else row.append(h('small', { class: 'row-error', role: 'alert' }, wrong[i]));
          } else {
            input.removeAttribute('aria-invalid');
            note?.remove();
          }
        });
      };
      const draw = () => { box.replaceChildren(
        ...entries.map((entry, i) => {
          const key = h('input', { type: 'text', class: 'key', 'aria-label': `${one} ${i + 1}: its name`, spellcheck: 'false', autocomplete: 'off',
            value: entry[0], oninput: () => { entry[0] = key.value; emit(); mark(); } });
          return h('div', { class: 'item' }, key,
            control(schema.additionalProperties, root, entry[1], (next) => { entry[1] = next; emit(); }, { required: true, label: `${one} ${i + 1}: its value` }),
            h('button', { type: 'button', class: 'small', 'aria-label': `Remove ${one} ${i + 1}`, onclick: () => { entries.splice(i, 1); emit(); draw(); } }, '×'),
          );
        }),
        h('button', { type: 'button', class: 'small', onclick: () => { entries.push(['', undefined]); draw(); box.querySelector('.item:last-of-type input')?.focus(); } }, `+ ${one}`),
      ); mark(); };
      draw();
      return box;
    }
    default: {
      // What the form does not draw (a choice between shapes, anything at all): JSON, checked as it is typed.
      const input = h('textarea', { ...named, class: 'raw', rows: '4', spellcheck: 'false', placeholder: 'JSON',
        value: value === undefined ? '' : JSON.stringify(value, null, 2),
        oninput: () => {
          try {
            change(input.value.trim() === '' ? undefined : JSON.parse(input.value));
            input.removeAttribute('aria-invalid');
          } catch {
            input.setAttribute('aria-invalid', 'true');
          }
        } });
      return input;
    }
  }
}

/** The fields of an object: a labelled control each; what holds more fields folds away. */
function fields(schema, root, value, change, skip = []) {
  const held = { ...(value ?? {}) };
  const required = schema.required ?? [];
  const set = (key) => (next) => {
    if (next === undefined) delete held[key];
    else held[key] = next;
    change(held);
  };
  return h('div', { class: 'fields' }, Object.entries(schema.properties).filter(([key]) => !skip.includes(key)).map(([key, node]) => {
    const { kind, schema: inner } = shape(node, root);
    const must = required.includes(key);
    const star = must && h('abbr', { title: 'required' }, '*');
    const hint = inner.description && h('small', { class: 'hint' }, inner.description);
    if (!['object', 'array', 'map'].includes(kind)) {
      const id = `field-${++ids}`;
      return h('div', { class: 'field' }, h('label', { for: id }, key, star), control(node, root, held[key], set(key), { required: must, id }), hint);
    }
    // (Drawn when first opened: a Workload has hundreds of fields, most of them never looked at.)
    const said = held[key] != null && Object.keys(held[key]).length > 0;
    const group = h('details', { class: 'group', open: must || said }, h('summary', {}, key, star, h('span', { class: 'dim' }, ` ${kind === 'object' ? '' : kind === 'array' ? 'list' : 'map'}`)), hint);
    const fill = () => {
      if (group.dataset.drawn) return;
      group.dataset.drawn = 'yes';
      group.append(control(node, root, held[key], set(key), { required: must, label: key.replace(/s$/, '') }));
    };
    group.addEventListener('toggle', fill);
    if (group.open) fill();
    return group;
  }));
}

/** The resource being edited, as a form drawn from its kind's schema. */
function formPane() {
  const kind = kindNamed(state.kind);
  const [root, draft] = [kind.schema, state.draft];
  const doc = draft.doc;
  const edited = (part) => (next) => {
    doc[part] = next ?? {};
    touched();
  };
  const metadata = fields(shape(root.properties.metadata, root).schema, root, doc.metadata, edited('metadata'),
    kind.namespaced ? ['revision'] : ['revision', 'namespace']);
  // (Another name is another resource: an existing one keeps where and what it is.)
  if (draft.base) {
    for (const input of metadata.querySelectorAll(':scope > .field > input')) {
      if (['name', 'namespace'].includes(input.labels[0]?.firstChild?.textContent)) input.readOnly = true;
    }
  }
  const spec = shape(root.properties.spec, root);
  const body = spec.kind === 'object'
    ? fields(spec.schema, root, doc.spec, edited('spec'))
    : h('div', { class: 'field' }, h('label', { for: 'spec-raw' }, 'spec'), control(root.properties.spec, root, doc.spec, edited('spec'), { id: 'spec-raw' }));
  return h('form', { class: 'form', onsubmit: (event) => event.preventDefault() },
    h('fieldset', {}, h('legend', {}, 'metadata'), metadata),
    h('fieldset', {}, h('legend', {}, 'spec'), body),
  );
}

function yamlPane() {
  const draft = state.draft;
  const text = h('textarea', { class: 'yaml', 'aria-label': 'This resource, as YAML', spellcheck: 'false', autocomplete: 'off', value: draft.yaml,
    oninput: () => {
      draft.yaml = text.value;
      touched();
    } });
  return text;
}

/** The resources to send: the form's one, or whatever the YAML holds. */
async function drafted() {
  const draft = state.draft;
  if (draft.mode === 'form') return [resourceOf(draft.doc, draft.base)];
  return (await api('POST', 'convert', { yaml: draft.yaml })).resources;
}

let checking = 0;
let checkTimer;

/** Something was edited: say, shortly, what kithd makes of it. */
function touched() {
  state.draft.dirty = true;
  clearTimeout(checkTimer);
  checkTimer = setTimeout(check, 500);
}

async function check() {
  const turn = ++checking;
  const line = $('check');
  if (!state.draft || !['form', 'yaml'].includes(state.tab)) return say(line, '');
  if (!state.draft.dirty) return say(line, state.draft.base ? 'as the cluster has it' : 'not yet written');
  try {
    const plan = await api('POST', 'diff', await drafted());
    const words = { created: 'would create', updated: 'would change', unchanged: 'no change to' };
    if (turn === checking) say(line, plan.map((change) => `${words[change.action]} ${change.key}`).join(' · '), 'ok');
  } catch (error) {
    if (turn === checking) say(line, error.message, 'bad');
  }
}

/** Show the diff, and apply on a yes. The plan is made again at the yes: if it moved, it is shown again. */
async function review() {
  let resources;
  let plan;
  if (state.draft?.mode === 'form' && $('pane').querySelector('[aria-invalid="true"]')) {
    return say($('check'), 'Fix the rows and fields marked invalid first.', 'bad');
  }
  try {
    resources = await drafted();
    plan = await api('POST', 'diff', resources);
  } catch (error) {
    return say($('check'), error.message, 'bad');
  }
  const changes = plan.filter((change) => change.action !== 'unchanged').length;
  const done = await ask({
    title: changes ? `Apply ${changes} change${changes > 1 ? 's' : ''}?` : 'Nothing would change',
    body: planView(plan),
    yes: changes ? 'Apply' : null,
    act: async () => {
      const now = await api('POST', 'diff', resources);
      if (JSON.stringify(now) !== JSON.stringify(plan)) {
        plan = now;
        throw Object.assign(new Error('The cluster changed while this was open: this is what applying would do now.'), { body: planView(now) });
      }
      return api('POST', 'apply', resources);
    },
  });
  if (!done) return;
  toast(done.map((change) => `${change.action} ${keyOf(change.after)}`).join(' · '));
  state.draft = null;
  done.forEach((change) => absorb(change.after));
  // (Where the first of them is: the address says so, and the address is followed.)
  const target = `#/${path(keyOf(done[0].after))}`;
  if (location.hash === target) open(keyOf(done[0].after));
  else location.hash = target;
}

/** What kithd just said a resource is, ahead of the watch saying so. */
function absorb(resource) {
  state.resources = [...state.resources.filter((other) => keyOf(other) !== keyOf(resource)), resource];
}

async function remove() {
  const key = state.key;
  const done = await ask({
    title: `Delete ${key}?`,
    body: h('p', {}, 'The cluster stops keeping it, and what it runs or owns goes with it.'),
    yes: 'Delete',
    danger: true,
    act: () => api('DELETE', `resources/${path(key)}`),
  });
  if (!done) return;
  toast(`deleted ${key}`);
  state.draft = null;
  state.resources = state.resources.filter((resource) => keyOf(resource) !== key);
  location.hash = `#/${state.kind}`;
}

async function statusPane() {
  const resource = live(state.key);
  if (!resource?.status) return h('p', { class: 'dim' }, 'Nothing has reported a status for this yet.');
  const { yaml } = await api('POST', 'convert', { resources: [resource.status] });
  return h('pre', {}, yaml);
}

async function historyPane() {
  const key = state.key;
  const history = await api('GET', `history/${path(key)}`);
  const latest = history.at(-1)?.resource.metadata.revision;
  const back = async (was) => {
    const to = was.resource.metadata.revision;
    const plan = await api('POST', 'diff', [written(was.resource)]);
    const done = await ask({
      title: `Roll ${key} back to revision ${to}?`,
      body: planView(plan),
      yes: 'Roll back',
      act: () => api('POST', `rollback/${path(key)}?to=${to}`),
    });
    if (!done) return;
    toast(`${key} is as it was at revision ${to}`);
    absorb(done.after);
    state.draft = null;
    open(key);
  };
  return h('table', {},
    h('thead', {}, h('tr', {}, h('th', { scope: 'col', class: 'num' }, 'Rev'), h('th', { scope: 'col' }, 'Written'), h('th', { scope: 'col' }, ''))),
    h('tbody', {}, history.toReversed().map((was) => {
      const revision = was.resource.metadata.revision;
      return h('tr', {},
        h('td', { class: 'num' }, String(revision)),
        h('td', {}, new Date(was.at * 1000).toLocaleString()),
        h('td', {}, revision === latest ? h('span', { class: 'dim' }, 'live')
          : may('apply') && h('button', { type: 'button', class: 'small', onclick: () => back(was).catch((error) => toast(error.message, true)) }, `Roll back to ${revision}`)),
      );
    })),
  );
}

/** Which draw of panel 04 is current: what a slower answer finds changed, it leaves alone. */
let paneTurn = 0;

function logsPane() {
  const [key, turn] = [state.key, paneTurn];
  const units = [...new Set((live(key)?.status?.containers ?? []).map((unit) => unit.name))];
  const replicas = [...new Set((live(key)?.status?.containers ?? []).map((unit) => unit.replica ?? 0))].sort((a, b) => a - b);
  const pick = (label, options) => h('label', { class: 'dim' }, `${label} `, h('select', { onchange: () => follow() }, options.map((option) => h('option', {}, String(option)))));
  const [unit, replica] = [pick('unit', units), pick('replica', replicas.length ? replicas : [0])];
  const out = h('pre', { class: 'logs', tabindex: '0', 'aria-label': 'Output' });
  let following = 0;
  // (Asked again every two seconds while this is on screen; kithd answers from where the last answer ended.)
  async function follow() {
    const mine = ++following;
    out.textContent = '';
    let query = 'tail=200';
    while (mine === following && turn === paneTurn) {
      try {
        const chosen = [unit, replica].map((label) => label.querySelector('select').value);
        const got = await api('GET', `logs/${path(key)}?${query}&replica=${encodeURIComponent(chosen[1])}${chosen[0] ? `&unit=${encodeURIComponent(chosen[0])}` : ''}`);
        if (mine !== following) return;
        const atEnd = out.scrollTop + out.clientHeight >= out.scrollHeight - 4;
        out.append(got.data);
        if (atEnd) out.scrollTop = out.scrollHeight;
        query = `offset=${got.next}`;
      } catch (error) {
        out.append(`\n${error.message}\n`);
        return;
      }
      await sleep(2000);
    }
  }
  follow();
  return h('div', { class: 'logs-box' }, h('div', { class: 'tools' }, unit, replica), out);
}

const TABS = [
  ['form', 'Form', () => may('apply')],
  ['yaml', 'YAML', () => true],
  ['status', 'Status', () => state.key !== '+'],
  ['history', 'History', () => state.key !== '+'],
  ['logs', 'Logs', () => lamps(live(state.key) ?? {}).length > 0],
];

/** Go to another tab. Between the form and the YAML, what was edited goes along (kithd converts). */
async function show(tab) {
  const draft = state.draft;
  try {
    if (tab === 'yaml' && draft.mode === 'form') {
      draft.yaml = (await api('POST', 'convert', { resources: [resourceOf(draft.doc, draft.base)] })).yaml;
      draft.mode = 'yaml';
    } else if (tab === 'form' && draft.mode === 'yaml') {
      const { resources } = await api('POST', 'convert', { yaml: draft.yaml });
      if (resources.length !== 1 || resources[0]?.kind !== state.kind) {
        throw new Error(`The form is for one ${state.kind}: the YAML holds ${resources.length === 1 ? `a ${resources[0]?.kind}` : `${resources.length} documents`}. Apply it from here.`);
      }
      draft.doc = { ...resources[0], metadata: resources[0].metadata ?? {}, spec: resources[0].spec ?? {} };
      draft.mode = 'form';
    }
  } catch (error) {
    return say($('check'), error.message, 'bad');
  }
  state.tab = tab;
  drawDetail();
}

function drawDetail() {
  const turn = ++paneTurn;
  const [pane, tabs] = [$('pane'), $('tabs')];
  const editing = ['form', 'yaml'].includes(state.tab);
  $('detail-key').textContent = state.key === '+' ? `new ${state.kind}` : (state.key ?? 'Resource');
  $('review').hidden = !(state.draft && editing && may('apply'));
  $('delete').hidden = !(state.draft?.base && may('delete'));
  if (!state.draft) {
    tabs.replaceChildren();
    $('detail-said').textContent = '';
    say($('check'), '');
    return pane.replaceChildren(h('p', { class: 'dim' }, state.key ? `${state.key} is not there (any more).` : 'Pick a resource in 03, or make a new one.'));
  }
  const offered = TABS.filter(([, , when]) => when());
  tabs.replaceChildren(...offered.map(([tab, title]) =>
    h('button', { type: 'button', role: 'tab', id: `tab-${tab}`, 'aria-selected': String(tab === state.tab), tabindex: tab === state.tab ? '0' : '-1',
      onclick: () => show(tab),
      onkeydown: (event) => {
        const step = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
        if (!step) return;
        const next = offered[(offered.findIndex(([name]) => name === tab) + step + offered.length) % offered.length][0];
        show(next).then(() => $(`tab-${next}`)?.focus());
      } }, title)));
  pane.setAttribute('aria-labelledby', `tab-${state.tab}`);
  const fill = (content) => turn === paneTurn && pane.replaceChildren(content);
  const failed = (error) => fill(h('p', { class: 'bad' }, error.message));
  if (state.tab === 'form') fill(formPane());
  else if (state.tab === 'yaml') fill(yamlPane());
  else if (state.tab === 'logs') fill(logsPane());
  else (state.tab === 'status' ? statusPane() : historyPane()).then(fill, failed);
  stale();
  check();
}

/** Say when the cluster's copy has moved on from the one being edited. */
function stale() {
  const said = $('detail-said');
  const [draft, now] = [state.draft, live(state.key)];
  if (!draft?.base) return said.replaceChildren();
  const [mine, theirs] = [draft.base.metadata.revision, now?.metadata.revision];
  if (!now) return said.replaceChildren('deleted from the cluster');
  if (mine === theirs) return said.replaceChildren(`revision ${mine}`);
  said.replaceChildren(`revision ${mine}; the cluster has ${theirs} `,
    h('button', { type: 'button', class: 'small', onclick: () => { state.draft = null; open(state.key); } }, draft.dirty ? 'Load it (drops your edits)' : 'Load it'));
}

/** Open `key` in panel 04 (`+`: a new one of the kind listed). */
function open(key) {
  state.key = key;
  const kind = kindNamed(state.kind);
  const base = key && key !== '+' ? live(key) : null;
  if (!kind || !key || (key !== '+' && !base)) state.draft = null;
  else {
    const doc = base ? written(base) : blank(kind);
    state.draft = { base, doc: { ...doc, metadata: doc.metadata ?? {}, spec: doc.spec ?? {} }, yaml: '', mode: 'form', dirty: false };
    state.tab = 'form';
    if (!may('apply')) {
      // (Who may only look gets the YAML, to read.)
      state.tab = 'status';
      if (!base?.status) return show('yaml');
    }
  }
  drawDetail();
}

// ── What is on screen follows the address, and the cluster ──────────────────────────

async function route() {
  let asked = '';
  try { asked = decodeURIComponent(location.hash.replace(/^#\/?/, '')); } catch { /* a hash that is no address: the start */ }
  const [name, ...rest] = asked.split('/');
  const kind = kindNamed(name) ?? kindNamed(state.kind) ?? kindNamed('Workload') ?? state.kinds[0];
  const key = rest.length === 0 ? null : rest[0] === '+' ? '+' : [kind?.kind, ...rest].join('/');
  if (state.draft?.dirty && (key !== state.key || kind?.kind !== state.kind)) {
    const leave = await ask({ title: 'Leave what you changed?', body: h('p', {}, `Your edits to ${state.key === '+' ? `the new ${state.kind}` : state.key} were not applied.`), yes: 'Leave', danger: true });
    if (!leave) return history.replaceState(null, '', `#/${state.key === '+' ? `${state.kind}/+` : path(state.key)}`);
  }
  const moved = key !== state.key || kind?.kind !== state.kind;
  state.kind = kind?.kind ?? null;
  drawKinds();
  drawTable();
  if (moved || (!state.draft && key)) open(key);
}

/** The kinds, again: at the start, and whenever a definition of one changed. */
let definitions = null;
async function kinds() {
  const marks = JSON.stringify(state.resources.filter((resource) => /^(KindDefinition|Role|RoleBinding)$/.test(resource.kind)).map((resource) => [keyOf(resource), resource.metadata.revision]));
  if (marks === definitions) return;
  const got = await api('GET', 'schemas');
  definitions = marks;
  state.kinds = got.kinds;
  state.caller = got.caller;
  $('who').textContent = `as ${got.caller}`;
}

function linked(how, text) {
  const link = $('link');
  link.className = `link ${how}`;
  link.textContent = text;
}

/** Everything one may see, whenever any of it changes: one long question after another. */
async function watch() {
  let poll = false;
  for (;;) {
    try {
      const after = state.generation == null || poll ? '' : `?after=${state.generation}`;
      const got = poll ? { generation: null, resources: await api('GET', 'resources') } : await api('GET', `watch${after}`);
      const first = state.generation == null && state.kinds.length === 0;
      state.generation = got.generation;
      state.resources = got.resources;
      await kinds();
      linked('ok', 'live');
      $('generation').textContent = got.generation == null ? '' : `generation ${got.generation}`;
      drawPulse();
      if (first) await route();
      else {
        drawKinds();
        drawTable();
        stale();
        if (state.tab === 'status' && state.draft) drawDetail();
        if (!state.draft && state.key && state.key !== '+' && live(state.key)) open(state.key);
      }
      if (poll) await sleep(5000);
    } catch (error) {
      // (May list but not watch: asked every few seconds instead.)
      if (error.status === 403 && !poll) poll = true;
      else {
        linked(error.status ? 'bad' : 'wait', error.status ? error.message : 'kithd does not answer: trying again');
        await sleep(2000);
      }
    }
  }
}

$('filter').addEventListener('input', (event) => {
  state.filter = event.target.value;
  drawTable();
});
$('new').addEventListener('click', () => {
  location.hash = `#/${state.kind}/+`;
});
$('review').addEventListener('click', review);
$('delete').addEventListener('click', () => remove().catch((error) => toast(error.message, true)));
window.addEventListener('hashchange', route);
new ResizeObserver(drawPulse).observe($('pulse'));
window.addEventListener('beforeunload', (event) => {
  if (state.draft?.dirty) event.preventDefault();
});
watch();
