// What a form needs from a kind's JSON Schema, as plain functions: no DOM here, so that
// `node test.mjs` can run them over every kind's schema.

/** `schema` with its `$ref` followed and "or null" taken off: `{ schema, nullable }`. */
export function resolve(schema, root) {
  let nullable = false;
  // (A bound, not a parser: a schema that refers to itself in a circle ends as it is.)
  for (let hops = 0; hops < 16; hops++) {
    if (schema === true || schema == null) return { schema: {}, nullable };
    if (schema.$ref) {
      const { $ref, ...said } = schema;
      const name = $ref.replace(/^#\/\$defs\//, '');
      schema = { ...(root?.$defs?.[name] ?? {}), ...said };
      continue;
    }
    const either = schema.anyOf ?? schema.oneOf;
    if (either) {
      const real = either.filter((one) => one.type !== 'null');
      nullable ||= real.length < either.length;
      if (real.length !== 1) break;
      const { anyOf, oneOf, ...said } = schema;
      schema = { ...real[0], ...said };
      continue;
    }
    if (Array.isArray(schema.type)) {
      const real = schema.type.filter((type) => type !== 'null');
      nullable ||= real.length < schema.type.length;
      schema = { ...schema, type: real.length === 1 ? real[0] : real };
    }
    break;
  }
  return { schema, nullable };
}

/**
 * How to draw `schema`: `{ kind, schema }` where kind is one of
 * const, enum, boolean, number, string, object, map, array, or raw (JSON in a box: what
 * the form does not draw, such as a choice between shapes).
 */
export function shape(schema, root) {
  const { schema: s } = resolve(schema, root);
  const either = s.anyOf ?? s.oneOf;
  // A choice between fixed words is an enum, however it is spelled.
  if (either?.every((one) => one.const !== undefined || one.enum)) {
    return { kind: 'enum', schema: { ...s, enum: either.flatMap((one) => one.enum ?? [one.const]) } };
  }
  // A number or a name (a port): typed as text, kept a number when it is one.
  const scalar = (one) => ['string', 'integer'].includes(resolve(one, root).schema.type);
  if (either?.length === 2 && either.every(scalar)) return { kind: 'string', schema: { ...s, type: 'string', orNumber: true } };
  const kind =
    either ? 'raw'
    : s.const !== undefined ? 'const'
    : s.enum ? 'enum'
    : s.type === 'boolean' ? 'boolean'
    : s.type === 'integer' || s.type === 'number' ? 'number'
    : s.type === 'string' ? 'string'
    : s.type === 'array' && s.items ? 'array'
    : s.properties ? 'object'
    : s.type === 'object' && s.additionalProperties && s.additionalProperties !== true ? 'map'
    : 'raw';
  return { kind, schema: s };
}

const empty = (value) => value === '' || value === null
  || (typeof value === 'object' && (Array.isArray(value) ? value : Object.keys(value)).length === 0);

/**
 * `value` without what was left empty: no `undefined`, `null`, `''`, `{}` or `[]` inside it,
 * except where `base` (what was there before, if anything) has that same emptiness: a
 * `rules: []` or `emptyDir: {}` somebody wrote means something, and stays.
 */
export function prune(value, base) {
  if (value === undefined) return undefined;
  const same = (now) => (base !== undefined && empty(base) && JSON.stringify(base) === JSON.stringify(now) ? now : undefined);
  if (empty(value)) return same(value);
  if (Array.isArray(value)) {
    const kept = value.map((item, i) => prune(item, base?.[i])).filter((item) => item !== undefined);
    return kept.length ? kept : same([]);
  }
  if (typeof value === 'object') {
    const kept = Object.entries(value).map(([key, item]) => [key, prune(item, base?.[key])]);
    const said = kept.filter(([, item]) => item !== undefined);
    return said.length ? Object.fromEntries(said) : same({});
  }
  return value;
}

/** A resource as one writes it: no status, no revision. */
export function written(resource) {
  const { status, metadata = {}, ...rest } = resource;
  const { revision, ...meta } = metadata;
  return { ...rest, metadata: meta };
}

/** The resource a form's `doc` stands for: pruned (see [`prune`]; `base` is the resource as it was), but always with its metadata. */
export function resourceOf(doc, base) {
  const { apiVersion, kind, metadata } = doc;
  const spec = prune(doc.spec, base?.spec);
  return { apiVersion, kind, metadata: prune(metadata, base?.metadata) ?? {}, ...(spec === undefined ? {} : { spec }) };
}

/** A new resource of `kind` (an entry of `/v1/schemas`), with nothing said yet. */
export function blank(kind) {
  const metadata = kind.namespaced ? { name: '', namespace: 'default' } : { name: '' };
  return { apiVersion: kind.apiVersion, kind: kind.kind, metadata, spec: {} };
}

/** `Kind/namespace/name`, as the API names a resource. */
export function keyOf(resource) {
  const { name, namespace } = resource.metadata ?? {};
  return [resource.kind, namespace, name].filter((part) => part != null && part !== '').join('/');
}

/** What is at a dotted `path` of `value` (`spec.map`), or undefined. */
export function at(value, path) {
  return path.split('.').reduce((inner, key) => (inner == null ? undefined : inner[key]), value);
}

const firstLine = (text) => String(text).split('\n')[0];

/** A resource's status in a few words, as `kith get` says it. */
export function summary(resource) {
  const status = resource.status;
  if (!status || typeof status !== 'object') return '';
  if (Number.isInteger(status.ready) && Number.isInteger(status.replicas)) {
    const why = (status.containers ?? []).map((unit) => unit.message).find(Boolean);
    return `${status.ready}/${status.replicas} ready${why ? `: ${firstLine(why)}` : ''}`;
  }
  const state = status.state ?? status.controller?.state;
  const message = status.message ?? status.controller?.message;
  if (state && message && state !== 'succeeded') return `${state}: ${firstLine(message)}`;
  if (state && status.address) return `${state} at ${status.address}`;
  return state ?? status.address ?? '';
}

/** How a resource is doing, for its lamp: ok, wait, bad or none. */
export function health(resource) {
  const status = resource.status;
  if (!status || typeof status !== 'object') return 'none';
  const state = String(status.state ?? status.controller?.state ?? '');
  if (/error|fail|refused|unreachable/.test(state)) return 'bad';
  if (Number.isInteger(status.ready) && Number.isInteger(status.replicas)) {
    return status.ready >= status.replicas ? 'ok' : 'wait';
  }
  if (/order|pending|partial|running|wait/.test(state)) return 'wait';
  return state ? 'ok' : 'none';
}

/** The lamps of a resource that runs things: one `{ state }` per replica, ok, wait or bad. */
export function lamps(resource) {
  const units = resource.status?.containers;
  if (!Array.isArray(units)) return [];
  return units.map((unit) => ({
    state: unit.ready ? 'ok' : /fail|error|crash|exit/.test(String(unit.state)) ? 'bad' : 'wait',
  }));
}

/** A unified diff as lines with what each is: add, del, hunk, head or same. */
export function diffLines(diff) {
  const what = (line) =>
    line.startsWith('+++') || line.startsWith('---') ? 'head'
    : line.startsWith('@@') ? 'hunk'
    : line.startsWith('+') ? 'add'
    : line.startsWith('-') ? 'del'
    : 'same';
  return diff.replace(/\n$/, '').split('\n').map((text) => ({ text, what: what(text) }));
}
