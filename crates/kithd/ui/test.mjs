// node test.mjs KINDS.json: the form's functions over every kind `/v1/schemas` gives
// (the Rust test `ui_forms` writes that file from the real schemas and runs this).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { at, blank, diffLines, entriesCheck, health, keyOf, lamps, prune, resolve, resourceOf, shape, summary, written } from './forms.js';

const kinds = JSON.parse(readFileSync(process.argv[2], 'utf8'));
assert.ok(kinds.length > 10, 'every kind of kith is here');

// Every kind's whole schema can be walked, and nearly all of it is drawn as fields.
let fields = 0;
let raw = [];
const walk = (schema, root, path, depth = 0) => {
  assert.ok(depth < 24, `${path} does not end`);
  const { kind, schema: s } = shape(schema, root);
  fields++;
  if (kind === 'raw') raw.push(path);
  if (kind === 'object') for (const [key, inner] of Object.entries(s.properties)) walk(inner, root, `${path}.${key}`, depth + 1);
  if (kind === 'map') walk(s.additionalProperties, root, `${path}.*`, depth + 1);
  if (kind === 'array') walk(s.items, root, `${path}[]`, depth + 1);
  if (kind === 'enum') assert.ok(s.enum.length > 0, `${path} has choices`);
};
for (const kind of kinds) {
  const root = kind.schema;
  assert.equal(shape(root.properties.metadata, root).kind, 'object', `${kind.kind}: metadata is fields`);
  const spec = shape(root.properties.spec, root);
  assert.ok(['object', 'raw'].includes(spec.kind), `${kind.kind}: spec is ${spec.kind}`);
  walk(root.properties.metadata, root, `${kind.kind}.metadata`);
  walk(root.properties.spec, root, `${kind.kind}.spec`);
}
// (What is not drawn gets a JSON box; if that became most of it, the form would be for show.)
const unknown = raw.filter((path) => !/\.(status|values|schema|default|data|spec)$|\[\]$|\*$/.test(path));
assert.ok(raw.length < fields / 8, `too much is a JSON box: ${raw.length} of ${fields}: ${raw.join(' ')}`);
console.log(`${kinds.length} kinds, ${fields} fields, ${raw.length} as JSON boxes${unknown.length ? ` (${unknown.join(' ')})` : ''}`);

// A kind of one's own, as the server hands it over.
const game = kinds.find((kind) => kind.kind === 'GameServer');
assert.ok(game, 'the defined kind is among them');
const spec = shape(game.schema.properties.spec, game.schema);
assert.deepEqual(Object.keys(spec.schema.properties), ['map', 'players', 'mode', 'tags', 'env']);
assert.deepEqual(spec.schema.required, ['map']);
const kindsOf = Object.fromEntries(Object.entries(spec.schema.properties).map(([key, s]) => [key, shape(s, game.schema).kind]));
assert.deepEqual(kindsOf, { map: 'string', players: 'number', mode: 'enum', tags: 'array', env: 'map' });

// References and "or null".
const root = { $defs: { Port: { type: 'integer', minimum: 1 }, Loop: { $ref: '#/$defs/Loop' } } };
assert.deepEqual(resolve({ anyOf: [{ $ref: '#/$defs/Port' }, { type: 'null' }], description: 'd' }, root), {
  schema: { type: 'integer', minimum: 1, description: 'd' },
  nullable: true,
});
assert.deepEqual(resolve({ type: ['string', 'null'] }, root), { schema: { type: 'string' }, nullable: true });
assert.equal(shape({ $ref: '#/$defs/Loop' }, root).kind, 'raw');
assert.equal(shape({ oneOf: [{ const: 'a' }, { enum: ['b', 'c'] }] }, root).kind, 'enum');
assert.deepEqual(shape({ oneOf: [{ const: 'a' }, { enum: ['b', 'c'] }] }, root).schema.enum, ['a', 'b', 'c']);
assert.equal(shape({ anyOf: [{ type: 'string' }, { $ref: '#/$defs/Port' }] }, root).schema.orNumber, true);
assert.equal(shape({ anyOf: [{ type: 'string' }, { type: 'object' }] }, root).kind, 'raw');
assert.equal(shape({ type: 'object' }, root).kind, 'raw');
assert.equal(shape(true, root).kind, 'raw');

// What a form holds becomes the resource that is sent: empties are left out, `false` and 0 are not.
const doc = blank(game);
assert.deepEqual(doc, { apiVersion: 'games.example.com/v1', kind: 'GameServer', metadata: { name: '', namespace: 'default' }, spec: {} });
doc.metadata.name = 'one';
doc.metadata.labels = {};
doc.spec = { map: 'dust', players: 0, open: false, mode: '', tags: [], env: { A: '' }, deep: { deeper: [null, {}] } };
assert.deepEqual(resourceOf(doc), {
  apiVersion: 'games.example.com/v1',
  kind: 'GameServer',
  metadata: { name: 'one', namespace: 'default' },
  spec: { map: 'dust', players: 0, open: false },
});
assert.equal(prune({ a: [{}] }), undefined);
// What was empty on purpose stays so; what the form emptied goes.
const was = { rules: [], volume: { emptyDir: {} }, note: '', gone: 'x' };
assert.deepEqual(prune({ rules: [], volume: { emptyDir: {} }, note: '', gone: '', more: [] }, was), { rules: [], volume: { emptyDir: {} }, note: '' });
assert.deepEqual(resourceOf({ kind: 'K', metadata: { name: 'n' }, spec: { rules: [] } }, { spec: { rules: [] } }).spec, { rules: [] });
// A null a nullable field already held stays null; one the form never had is not made.
assert.deepEqual(resourceOf({ kind: 'K', metadata: { name: 'n' }, spec: { ttl: null, env: { A: null }, none: null } }, { spec: { ttl: null, env: { A: null } } }).spec, { ttl: null, env: { A: null } });
// Map rows: an empty or repeated name is an error on that row.
assert.deepEqual(entriesCheck([['a', 1], ['b', 2]]), [null, null]);
assert.equal(entriesCheck([['', 1]])[0].includes('Name it'), true);
assert.deepEqual(entriesCheck([['a', 1], ['a', 2], ['b', 3]]).map(Boolean), [true, true, false]);
assert.equal('spec' in resourceOf(blank(game)), false);
assert.equal(blank(kinds.find((kind) => kind.kind === 'Node')).metadata.namespace, undefined);

// A stored resource, as one would write it; its key, columns and status.
const live = {
  apiVersion: 'kith.dev/v1',
  kind: 'Workload',
  metadata: { name: 'web', namespace: 'shop', revision: 4 },
  spec: { replicas: 2 },
  status: { ready: 1, replicas: 2, containers: [{ ready: true, state: 'running' }, { ready: false, state: 'failed', message: 'no image\nmore' }] },
};
assert.deepEqual(written(live), { apiVersion: 'kith.dev/v1', kind: 'Workload', metadata: { name: 'web', namespace: 'shop' }, spec: { replicas: 2 } });
assert.equal(keyOf(live), 'Workload/shop/web');
assert.equal(keyOf({ kind: 'Node', metadata: { name: 'a' } }), 'Node/a');
assert.equal(at(live, 'spec.replicas'), 2);
assert.equal(at(live, 'spec.none.deeper'), undefined);
assert.equal(summary(live), '1/2 ready: no image');
assert.equal(health(live), 'wait');
assert.deepEqual(lamps(live), [{ state: 'ok' }, { state: 'bad' }]);
assert.equal(summary({ status: { state: 'ready', address: 'fd00::1' } }), 'ready at fd00::1');
assert.equal(summary({ status: { controller: { state: 'error', message: 'out of fuel' } } }), 'error: out of fuel');
assert.equal(health({ status: { controller: { state: 'error' } } }), 'bad');
assert.equal(health({ status: { state: 'served' } }), 'ok');
assert.equal(health({}), 'none');
assert.equal(summary({}), '');

// A diff, line by line.
const diff = '--- a (live)\n+++ a (desired)\n@@ -1,2 +1,2 @@\n spec:\n-  map: dust\n+  map: ice\n';
assert.deepEqual(diffLines(diff).map((line) => line.what), ['head', 'head', 'hunk', 'same', 'del', 'add']);
console.log('ok');
