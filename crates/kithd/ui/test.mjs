// node test.mjs [KINDS.json]: the page's own functions.
//  - always: the QR code of a peer's WireGuard configuration (qr.js) against a reference encoder,
//    and the Add a peer dialog (install.js), which keeps nothing in the browser;
//  - given KINDS.json, the form's functions over every kind `/v1/schemas` gives
//    (the Rust test `ui_forms` writes that file from the real schemas and runs this).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { at, blank, diffLines, entriesCheck, health, keyOf, lamps, prune, resolve, resourceOf, shape, summary, written } from './forms.js';
import { installPart } from './install.js';
import { MOST, draw as drawCode, qr } from './qr.js';
import { PANELS, RANGES, busiest, dashPart, format, hues, line, rangeOf, scale, tiles, times } from './dash.js';
import { STEPS, fixture } from './fixture.mjs';
// The Terminal and Files tabs have a file of their own: it runs as it is loaded.
import './shell.test.mjs';

// ── The QR code: the matrix a reference encoder makes ─────────────────────────────────
// Each fixture is `qrencode -8 -l L -m 0` (qrencode 4.1, ISO 18004 byte mode, the lowest
// error correction): its side, then each row as hex, a module a bit, dark a 1, a row padded
// to a whole digit. They cover versions 1, 5, 11 and 14; qr.js was also run against it over
// every length from 1 to 2953 bytes (all 40 versions), with no module different.
const WIREGUARD = '[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 100.89.2.3/32, fd8a:1c3f:5b9d:2::3/128\nDNS = 10.1.0.53\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = vpn.example.org:51821\nAllowedIPs = 192.168.0.0/16, fd12::/16, 100.89.0.1/32, fd8a:1c3f:5b9d::1/128, 10.1.0.53/32\nPersistentKeepalive = 25\n';
const SPREAD = Array.from({ length: 700 }, (_, i) => String.fromCharCode(33 + ((i * 7) % 90))).join('');
const FIXTURES = [
  ['hi', 'hi', '21', 'fe2bf8 820a08 baa2e8 ba0ae8 ba5ae8 827208 feabf8 00a000 efae20 613578 7fd778 301dd0 96b720 00a238 fee898 82e238 bacaa8 ba5550 baf768 82ddd0 fe9778'],
  ['kith x30', 'kith '.repeat(30), '45', 'fe9ccd3f8bf8 82b3c422d208 ba4f7ba552e8 ba50de955ae8 babccfaa3ae8 82e228ae8208 feaaaaaaabf8 00ed78a8a800 e6c33f9ef798 589f28c415a8 7b7fd6d4dd08 e84805acb2c0 87f27d6eb6c8 70732c9c5028 9a82d6d59ce8 5098d42b8280 3f5324a8e2d8 0d5a6ac55438 fbbdf08d49a8 18a6940ac9d0 2ff33fefff90 38a328c05888 dabc2add5af8 28f088daa8c0 9fef3fea9fd0 95c33a55c148 76addc514ae8 d8c56128bad8 4313369ef350 25b73ac41028 8e87d554cb88 0428042cbac0 b73e6beebd48 4c99369c4f28 0ad2df559a68 7958c12b9a88 9a332fa8ffc8 009268c548b8 fe59ea8d5aa8 8282988ac8d0 ba493fefff90 ba213dc05a90 ba8c355d4ef0 82a08cdab040 fed72eea94c8'],
  ['a WireGuard configuration', WIREGUARD, '65', 'fe1bc2f690ad1d3f8 8292cb82af5b78a08 ba790e90d2e83aae8 baa5da977b31c72e8 ba4625e3f4608cae8 82f64c3a3318aa208 feaaaaaaaaaaaabf8 00348376204d8e000 fb8c291bf803f7d50 4ccac3e31cb41e518 9af6e7833bc738330 b86e85cad2fb2f458 22ff759c6876c49f0 60f702f788ac430b0 b61311c67f0e24780 718286a790ac49708 1e0cbd0d3b60d3ef8 807586f318a5de5a8 3efd2d796082a0ad0 38d7e14e06e918a58 d3f22c115975879a8 a4c371a38c2017060 5af80c637045f4180 a8032bdad43cea400 a2a8bc1d7c25f0aa0 2d3547858dac9b5c8 fb20605e8b9bfca90 956764d3a0c37d508 6a8720d95b17a62f0 0c24df6208604b020 cfa7ca3be78f7afc0 98e0dd0223dd1a880 4a8abc1abb06a6aa8 c8cb46b634b40b8f8 4fa7529fed4275fb0 8003069266b96f6d0 d607cb149d77c0470 f09435e10db497990 fa1e05b191dea0880 9dd975a6fd4a88e50 b780bd509d01d6628 f96f038105a41f788 b291f69f07c671050 c52285a2e1d051ac8 93d030ca7c5180508 75c542a311e1866e0 b7f8346601caa2c20 3c59643910bf29700 ce53b90b7924d00f0 146d46f104244a1c8 0e2f24050a0634190 bdbef13ae6ee1b8d0 3fe02d861b3286d30 381071e35cf1df2d0 37c2db178e476c4a0 906c1958497c8e3d8 6a21bc5beb64b2fb8 00b547a23cb49b8f8 fed7808ab5427cab0 822365b223b69f8c8 baa120dfea1587f90 baf0dea43d6196d10 ba95e993681e60190 82f29f8f14cb5a190 fecda80b3d0487ba0'],
  ['700 bytes', SPREAD, '89', 'fe53c118a7a2b4464de7bf8 821a669e17c216cfdad9208 ba7d0a4223f0d9d3f1ec2e8 ba9ec623e9ddaf06ac0aae8 bac1365f9d2d57f91f852e8 824b5588acda2a2ceeb9208 feaaaaaaaaaaaaaaaaaabf8 000eac08a3782a237d6b000 c74f5d9fd86683e100550c0 f823c40dbe6f28039b20748 46428802f3e5a0eb09e0d40 b48918004eb8445fee70fd8 2e66ae4a4f8ec9313f154c0 30c474065165d9118898608 0203a0fb565e0cafced61d0 0445503b627e85d47b967b8 db6c0c2fcc55f621a25b730 903092555d29539a19b0470 eef08ad2db851dbc315cb08 d43d246abe796e617c2aec8 9b0c4cb35e67e3ef809da00 cc73dc1da76eba319a80fd0 4a79d081ff64e87a09f1c50 bcca282ed099e17bae31fc0 1e1ede5259cea83d3fd3750 20c22ce849245b1ba9ba2a8 1617a5df461ece3dcfd6090 b54fab25624f06563b927a8 cff14e2fcc14f3e9cadbfa0 98b770d8cd78d62239328d0 aaaa455acbec9eac215dac8 d88cf168fe5b6a21382e8c8 dfea6fbfbe21e7ef8c9df80 c553049b277ebbd1b882af0 22ba65413f08e9da19f5d90 a0220369708dfa5bae33440 5b1eac3139c8bb9db1db1d0 e8630ca7483447ba2bb3c28 a6d615830796dedd5fc7590 d18bef39004920923dd3a28 c78ebe06a812b3694ed33a8 04886ac6ccf8c1813b0a850 0a94e70d8b688ec5a10c5c8 c0c3f1e6fc5b567d3a4e4d8 820a6e0d3a21a6e70c15988 d10a058a32ffa39238b22f0 2607e579328865e71844d90 a16003a0f2eddcd1efd7450 6a92ec61bd88fbd3f15e1d8 98110c765c3540580b915f8 aed671bb09965ae55627460 a58f04b2906924025d71a38 d79e40033872b36106553e8 8c950a56dce1c0010308b70 4f997b1f83780ff5a80cfa8 08e2c0e8dc29523d5e4b8d8 0a8aad9afa45a2a76410ac8 988b4c08b2e7a63202b0890 5fe7712fb28063e7004dff0 25a0129053efd931cbdf450 96e28e5b7c8cfb137956b98 2da904135d2d54b81991bf8 1b4a9bba891a5064463e9f8 7da326d1b5eb15025921520 32ac6c32fe76c287861c470 058122585de196230128ae0 bfa5f94b85f845b4aa15ca8 c03c502b49a876b95c13640 0aeb2ca27f45c6ebe4b8058 85564c13abe673c90391b90 439af0aea2008a47015c770 204d12d051ceb9158b9ac48 86c6ce52facc9f3f79b7b90 704704f2c52cd4c23833bc8 8af49e22815bb27447be1a0 5db58bd1a5ca15201924d20 93b88e3bfe36c66f8e9c560 a11c50d8c5f0175320aabc0 9224c0578db0c6a4ba15d68 cc09bfab698c76991c156c0 92cd77bf9f03c7ebeab8fd8 00976498ebfe762921928b0 fedaf7fac2508aa7975dab0 82850de8b1d4ba348d988c8 ba4e842f9aca9ffff5bff90 ba676cbf44b8ce633a2a5c0 ba791e55e1d7ba95d3af5b0 82d2d3d607c867a59b642a8 feae2e181a30a14f0c955e0'],
];
const rowsOf = (matrix) => matrix
  .map((row) => row.map((on) => (on ? '1' : '0')).join('').padEnd(Math.ceil(row.length / 4) * 4, '0').match(/.{4}/g).map((bits) => parseInt(bits, 2).toString(16)).join(''))
  .join(' ');
for (const [what, text, side, rows] of FIXTURES) {
  const matrix = qr(text);
  assert.equal(matrix.length, Number(side), `${what}: the side`);
  assert.ok(matrix.every((row) => row.length === matrix.length), `${what}: square`);
  assert.equal(rowsOf(matrix), rows, `${what}: not the reference's matrix`);
}
// Too much is refused, not cut; the most it takes is a full version-40 code.
assert.equal(qr('x'.repeat(MOST)).length, 177);
assert.throws(() => qr('x'.repeat(MOST + 1)), /too long/);
// (UTF-8 bytes are counted, not letters.)
assert.throws(() => qr('€'.repeat(Math.floor(MOST / 3) + 1)), /too long/);

// Drawn: black on a white square with a quiet zone of four modules, whatever the theme.
{
  const matrix = qr(WIREGUARD);
  const fills = [];
  const canvas = { getContext: () => ({ set fillStyle(colour) { fills.push(['colour', colour]); }, fillRect: (...box) => fills.push(box) }) };
  drawCode(canvas, matrix, 5);
  assert.equal(canvas.width, (matrix.length + 8) * 5);
  assert.equal(canvas.height, canvas.width);
  assert.deepEqual(fills.slice(0, 3), [['colour', '#ffffff'], [0, 0, canvas.width, canvas.width], ['colour', '#000000']]);
  const dark = fills.filter((box) => box.length === 4 && box[2] === 5);
  assert.equal(dark.length, matrix.flat().filter(Boolean).length);
  assert.ok(dark.every(([x, y]) => x >= 20 && y >= 20 && x < canvas.width - 20 && y < canvas.width - 20), 'the quiet zone is clear');
}

// ── The Add a peer dialog: the configuration is shown once and kept nowhere ──────────────
// A page of fakes: `h` makes plain objects, `ask` runs what the dialog would on its Make
// button, and every way a script could keep something in the browser throws.
const trapped = (target, name) => Object.defineProperty(target, name, { configurable: true, get() { throw new Error(`the page touched ${name}`); }, set() { throw new Error(`the page set ${name}`); } });
for (const name of ['localStorage', 'sessionStorage', 'indexedDB', 'location', 'history']) trapped(globalThis, name);
globalThis.document = trapped({}, 'cookie');

const PRIVATE = 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=';
const peerDialog = async ({ fill, answer = { name: 'phone', node: 'a', level: 'guest', config: WIREGUARD }, nodes = ['a', 'b'] }) => {
  const pen = [];
  const h = (tag, props = {}, ...children) => ({
    tag,
    props,
    value: '',
    children: children.flat(3).filter((child) => child != null && child !== false),
    getContext: () => ({ set fillStyle(colour) { pen.push(colour); }, fillRect: (...box) => pen.push(box) }),
  });
  const text = (node) => (typeof node === 'string' ? node : node.children.map(text).join(' '));
  const find = (node, test, found = []) => {
    if (typeof node === 'string') return found;
    if (test(node)) found.push(node);
    node.children.forEach((child) => find(child, test, found));
    return found;
  };
  const resource = (kind, name, status) => ({ kind, metadata: { name }, status });
  const state = {
    resources: [
      resource('Node', 'a', { people: { endpoint: 'vpn.example.org:51821' } }),
      resource('Node', 'b', { state: 'ready' }),
      resource('AccessLevel', 'guest'),
      resource('AccessLevel', 'admins'),
      resource('RemotePeer', 'old'),
    ].filter((one) => one.kind !== 'Node' || nodes.includes(one.metadata.name)),
  };
  const clicks = new Map();
  const $ = (id) => ({ hidden: false, textContent: '', value: '', addEventListener: (_, run) => clicks.set(id, run), setAttribute() {}, removeAttribute() {}, replaceChildren() {} });
  const calls = [];
  const dialogs = [];
  const toasts = [];
  let finished;
  const done = new Promise((resolved) => { finished = resolved; });
  const ask = async (dialog) => {
    dialogs.push({ ...dialog, text: text(dialog.body), body: dialog.body });
    if (dialogs.length === 1) fill?.(dialog.body, find);
    return dialog.act ? dialog.act() : undefined;
  };
  const toast = (words, bad = false) => { toasts.push({ words, bad }); finished(); };
  const api = async (...call) => { calls.push(call); return answer; };
  installPart({ $, h, api, ask, toast, say() {}, state, may: () => true });
  clicks.get('peer-add')();
  await done;
  return { calls, dialogs, toasts, pen, find, text };
};
const filled = (name, node, level) => (body, find) => {
  const control = (id) => find(body, (one) => one.props.id === id)[0];
  control('peer-name').value = name;
  control('peer-node').value = node;
  control('peer-level').value = level;
};

{
  const { calls, dialogs, toasts, pen, find } = await peerDialog({ fill: filled(' phone ', 'a', 'guest') });
  assert.deepEqual(toasts, [{ words: 'phone is a peer of a.', bad: false }]);
  assert.deepEqual(calls, [['POST', 'peers', { name: 'phone', node: 'a', level: 'guest' }]], 'one call, with the name trimmed and nothing else');
  assert.equal(dialogs.length, 2, 'the question, then the answer');
  const [question, shown] = dialogs;
  // The question: only the nodes that told of a people device with an endpoint, and the levels, sorted.
  assert.equal(question.title, 'Add a peer');
  assert.deepEqual(find(question.body, (one) => one.props.id === 'peer-node')[0].children.map((one) => one.props.value), ['a']);
  assert.deepEqual(find(question.body, (one) => one.props.id === 'peer-level')[0].children.map((one) => one.props.value), ['admins', 'guest']);
  assert.ok(!question.text.includes('PrivateKey'), 'nothing is shown before kithd has made it');
  // The answer: said once, to whoever is looking, as a picture and as text.
  assert.ok(shown.title.includes('phone'));
  assert.ok(shown.text.includes('whoever has this picture is this peer'));
  assert.ok(shown.text.includes('Shown this once, and kept nowhere'));
  assert.equal(shown.yes, undefined, 'a Close button and nothing to make again');
  const [picture] = find(shown.body, (one) => one.tag === 'canvas');
  assert.ok(picture && picture.props.role === 'img' && picture.props['aria-label'].includes('QR code'));
  assert.equal(find(shown.body, (one) => one.tag === 'pre')[0].children[0], WIREGUARD, 'the text is there for a phone with no camera, or a laptop');
  // (The picture is drawn from the configuration it shows.)
  const matrix = qr(WIREGUARD);
  assert.equal(picture.width, (matrix.length + 8) * 5);
  assert.equal(pen.filter((box) => Array.isArray(box) && box.length === 4 && box[2] === 5).length, matrix.flat().filter(Boolean).length);
  // The private key is in the one dialog that shows it, and in no toast, no question, no call.
  assert.ok(shown.text.includes(PRIVATE));
  assert.ok(!question.text.includes(PRIVATE) && toasts.every((one) => !one.words.includes(PRIVATE)));
  assert.ok(!JSON.stringify(calls).includes(PRIVATE));
}

// A name that is a peer already is asked about first: one call, with replace, only after the yes.
{
  const { calls, dialogs, toasts, find } = await peerDialog({ fill: filled('old', 'a', 'guest'), answer: { name: 'old', node: 'a', level: 'guest', config: WIREGUARD } });
  assert.deepEqual(calls, [['POST', 'peers', { name: 'old', node: 'a', level: 'guest', replace: true }]], 'no call is made before the confirm');
  assert.equal(dialogs.length, 3, 'the question, the confirm, then the answer');
  const [, confirm, shown] = dialogs;
  assert.ok(confirm.title.includes('new key for old') && confirm.danger === true && confirm.yes === 'Give it a new key');
  assert.ok(confirm.text.includes('ends the old'));
  assert.ok(!confirm.text.includes(PRIVATE));
  assert.ok(shown.text.includes(PRIVATE));
  assert.deepEqual(toasts, [{ words: 'old is a peer of a.', bad: false }]);
  assert.equal(find(shown.body, (one) => one.tag === 'pre').length, 1);
}

// A configuration too long for a picture is still shown, as text.
{
  const { dialogs, find } = await peerDialog({ fill: filled('phone', 'a', 'guest'), answer: { name: 'phone', node: 'a', level: 'guest', config: 'x'.repeat(MOST + 1) } });
  assert.equal(find(dialogs[1].body, (one) => one.tag === 'canvas').length, 0);
  assert.ok(dialogs[1].text.includes('No picture: too long for a QR code'));
  assert.equal(find(dialogs[1].body, (one) => one.tag === 'pre').length, 1);
}

// An unfilled question calls nothing, and says what is missing.
{
  const { calls, dialogs, toasts } = await peerDialog({ fill: filled('  ', 'a', 'guest') });
  assert.deepEqual(calls, []);
  assert.equal(dialogs.length, 1);
  assert.deepEqual(toasts, [{ words: 'Name the peer.', bad: true }]);
}
// With no node telling of a people device, the dialog says how to have one.
{
  const { dialogs, calls } = await peerDialog({ nodes: ['b'], fill: filled('phone', '', 'guest') });
  assert.ok(dialogs[0].text.includes('start one with --people and --people-endpoint'));
  assert.deepEqual(calls, []);
}

// ── The dashboard (dash.js): its lines, scales, sums and order, over T-1111's /v1/metrics ──
const GiB = 2 ** 30;
const MiB = 2 ** 20;
const END = 1_800_000_000;

// The fixture is the contract's shape: every series of a node as long as the others, aligned to
// `end`, a gap a null, a node that did not answer `missing` with the whole shape of nothing
// (its arrays null, its sizes 0) and none of its Workloads.
for (const range of RANGES) {
  const metrics = fixture(range, END, { missing: ['gamma'] });
  assert.deepEqual(Object.keys(metrics).sort(), ['end', 'nodes', 'range', 'step', 'workloads']);
  assert.equal(metrics.range, range);
  assert.equal(metrics.step, STEPS[range]);
  const length = metrics.nodes.alpha.cpu.length;
  const { gamma } = metrics.nodes;
  assert.equal(gamma.missing, true);
  assert.deepEqual([gamma.cpus, gamma.memTotal, gamma.diskTotal], [0, 0, 0]);
  for (const series of ['cpu', 'mem', 'disk', 'diskRead', 'diskWrite', 'rx', 'tx', 'load1']) {
    assert.ok(gamma[series].length === length && gamma[series].every((value) => value === null), `gamma.${series}`);
  }
  assert.ok(Object.values(metrics.workloads).every((one) => one.node !== 'gamma'));
  assert.ok(length > 50, `${range}: a line, not a dot`);
  for (const [name, node] of Object.entries(metrics.nodes).filter(([, node]) => !node.missing)) {
    assert.ok(Number.isInteger(node.cpus) && node.memTotal > 0 && node.diskTotal > 0, name);
    for (const series of ['cpu', 'mem', 'disk', 'diskRead', 'diskWrite', 'rx', 'tx', 'load1']) {
      assert.equal(node[series].length, length, `${range} ${name}.${series}`);
      assert.ok(node[series].every((value) => value === null || (typeof value === 'number' && value >= 0)), `${name}.${series}`);
    }
    assert.ok(node.cpu.every((value) => value === null || value <= 1), 'cpu is a fraction of the node');
    assert.ok(node.mem.every((value) => value === null || value <= node.memTotal));
  }
  assert.ok(metrics.nodes.alpha.cpu.includes(null), 'alpha has a gap (a restart)');
  for (const [key, one] of Object.entries(metrics.workloads)) {
    // (`NS/NAME` on the first node by name, `NS/NAME@NODE` on each other.)
    assert.match(key, /^[^/@]+\/[^/@]+(@[^/@]+)?$/);
    if (key.includes('@')) assert.equal(key.split('@')[1], one.node);
    assert.ok(one.node in metrics.nodes && one.cpu.length === length && one.mem.length === length, key);
  }
  const at = times(metrics);
  assert.equal(at.length, length);
  assert.equal(at.at(-1), END);
  assert.equal(at[1] - at[0], metrics.step);
}
// (Ten-second points for an hour, five-minute ones for a day: T-1111's rings.)
assert.deepEqual([STEPS['1h'], STEPS['24h']], [10, 300]);

// The range control: four ranges, an hour unless another is asked for.
assert.deepEqual(RANGES, ['15m', '1h', '6h', '24h']);
assert.equal(rangeOf('6h'), '6h');
assert.equal(rangeOf('7d'), '1h');
assert.equal(rangeOf(undefined), '1h');

// A series as an SVG path: oldest on the left, newest at the right edge, top the most; a null
// lifts the pen, and a point with no neighbour is still drawn (a dot of the line's cap).
assert.equal(line([0, 1, null, 0.5], { width: 30, height: 10, max: 1 }), 'M0 10L10 0M30 5h0');
assert.equal(line([0.25, 0.5, 0.75], { width: 100, height: 40, max: 1 }), 'M0 30L50 20L100 10');
assert.equal(line([2, -1], { width: 10, height: 10, max: 1 }), 'M0 0L10 10', 'what is past the scale is drawn at its edge');
assert.equal(line([0.3], { width: 50, height: 10, max: 1 }), 'M50 7h0', 'one point is the newest');
assert.equal(line([null, null], { width: 50, height: 10, max: 1 }), '');
assert.equal(line([], { width: 50, height: 10, max: 1 }), '');
assert.equal(line([1, 2, 3], { width: 3, height: 3, min: 1, max: 3 }), 'M0 3L1.5 1.5L3 0');

// An axis: a fraction is 0 to 100 % in quarters; bytes and rates in whole binary units, in
// steps of 1, 2, 2.5 or 5 of them; nothing at all still has a scale.
assert.deepEqual(scale(0.42, 'pct'), { top: 1, ticks: [0, 0.25, 0.5, 0.75, 1] });
assert.deepEqual(scale(7.3 * GiB, 'bytes'), { top: 8 * GiB, ticks: [0, 2, 4, 6, 8].map((n) => n * GiB) });
assert.deepEqual(scale(1500, 'rate'), { top: 1536, ticks: [0, 512, 1024, 1536] });
assert.deepEqual(scale(3.1, 'num'), { top: 4, ticks: [0, 1, 2, 3, 4] });
assert.deepEqual(scale(0.37, 'num'), { top: 0.4, ticks: [0, 0.1, 0.2, 0.3, 0.4] });
assert.deepEqual(scale(0, 'rate'), { top: 1024, ticks: [0, 1024] });
assert.deepEqual(scale(null, 'num'), { top: 1, ticks: [0, 1] });
assert.deepEqual(scale(9 * MiB, 'rate').ticks.map((n) => format(n, 'rate')), ['0 B/s', '2.5 MiB/s', '5 MiB/s', '7.5 MiB/s', '10 MiB/s']);

// Units: the way a person says them.
assert.equal(format(0.423, 'pct'), '42%');
assert.equal(format(0.004, 'pct'), '0.4%');
assert.equal(format(1, 'pct'), '100%');
assert.equal(format(1.5 * GiB, 'bytes'), '1.5 GiB');
assert.equal(format(12 * MiB, 'bytes'), '12 MiB');
assert.equal(format(512, 'bytes'), '512 B');
assert.equal(format(0, 'bytes'), '0 B');
assert.equal(format(2.5 * MiB, 'rate'), '2.5 MiB/s');
assert.equal(format(0.25, 'num'), '0.25');
assert.equal(format(12.345, 'num'), '12.3');
for (const unit of ['pct', 'bytes', 'rate', 'num']) {
  assert.equal(format(null, unit), '–');
  assert.equal(format(undefined, unit), '–');
}

// Each node keeps its colour: in the order of their names, six hues, never one twice; a seventh
// node is drawn dim, not in the first's colour. A node that did not answer keeps its place.
{
  const names = ['beta', 'alpha', 'gamma', 'delta', 'eps', 'zeta', 'eta', 'theta'];
  const metrics = { nodes: Object.fromEntries(names.map((name) => [name, { missing: name === 'beta' }])) };
  assert.deepEqual(Object.fromEntries(hues(metrics)), { alpha: 1, beta: 2, delta: 3, eps: 4, eta: 5, gamma: 6, theta: 0, zeta: 0 });
}

// The tiles: nodes and workloads from the cluster's resources, CPU and memory from the metrics.
const resource = (kind, name, status) => ({ kind, metadata: { name, namespace: kind === 'Workload' ? 'default' : undefined }, status });
const RESOURCES = [
  resource('Node', 'alpha', { state: 'ready' }),
  resource('Node', 'beta', { state: 'ready' }),
  resource('Node', 'gamma', { state: 'unreachable' }),
  resource('Workload', 'web', { ready: 3, replicas: 3 }),
  resource('Workload', 'queue', { ready: 2, replicas: 2 }),
  resource('Workload', 'mail', { ready: 0, replicas: 2, notes: ['restarting'] }),
  resource('ConfigMap', 'site'),
];
{
  const metrics = fixture('1h', END, { missing: ['gamma'] });
  const { alpha, beta } = metrics.nodes;
  const sum = tiles(RESOURCES, metrics);
  assert.deepEqual(sum.nodes, { ready: 2, total: 3 });
  assert.deepEqual(sum.workloads, { ready: 2, total: 3 });
  assert.deepEqual(sum.replicas, { ready: 5, total: 7 });
  // (Of the nodes that answered: one that did not has no CPU to count, used or free.)
  assert.equal(sum.cpu.total, alpha.cpus + beta.cpus);
  assert.equal(sum.mem.total, alpha.memTotal + beta.memTotal);
  const last = alpha.cpu.length - 1;
  assert.ok(Math.abs(sum.cpu.used - (alpha.cpu[last] * alpha.cpus + beta.cpu[last] * beta.cpus)) < 1e-9);
  assert.equal(sum.mem.used, alpha.mem[last] + beta.mem[last]);
  assert.equal(sum.cpu.series.length, alpha.cpu.length);
  // (Where alpha has a gap, the sum is beta's alone: a dip that says so, not a hole.)
  const hole = alpha.cpu.indexOf(null);
  assert.ok(Math.abs(sum.cpu.series[hole] - beta.cpu[hole] * beta.cpus) < 1e-9);
  assert.deepEqual(sum.reporting.slice(hole - 1, hole + 1), [2, 1], 'how many nodes answered, point by point');
  // Without metrics: what the resources say, and no number made up.
  const none = tiles(RESOURCES, null);
  assert.deepEqual(none.nodes, { ready: 2, total: 3 });
  assert.deepEqual(none.cpu, { used: null, total: null, series: [] });
  assert.deepEqual(none.mem, { used: null, total: null, series: [] });
  assert.deepEqual(tiles([], { nodes: {}, workloads: {} }).cpu, { used: null, total: null, series: [] });
  // A node whose memory kithd could not read (null points, T-1111): not counted as 0 used of its
  // total, but left out of the memory tile; its CPU still counts.
  const blind = { ...metrics, nodes: { ...metrics.nodes, beta: { ...beta, mem: beta.mem.map(() => null) } } };
  const partly = tiles(RESOURCES, blind);
  assert.equal(partly.mem.total, alpha.memTotal);
  assert.equal(partly.mem.used, alpha.mem[last]);
  assert.equal(partly.cpu.total, alpha.cpus + beta.cpus);
  const unread = { ...blind, nodes: { beta: blind.nodes.beta } };
  assert.deepEqual(tiles(RESOURCES, unread).mem, { used: null, total: null, series: [] });
}

// The workloads, busiest first: by CPU now (the latest point that has one), then memory, then
// name. A Workload on several nodes (`NS/NAME@NODE`) is one row: its nodes' use summed.
{
  const workloads = {
    'a/x': { node: 'n', cpu: [0.9, 0.1, null], mem: [1, 2, null] },
    'a/y': { node: 'n', cpu: [0.5], mem: [1] },
    'a/z': { node: 'n', cpu: [0.5], mem: [9] },
    'a/w': { node: 'n', cpu: [null], mem: [null] },
    'a/v': { node: 'n', cpu: [0.5], mem: [9] },
  };
  const sorted = busiest({ workloads });
  assert.deepEqual(sorted.map((one) => one.key), ['a/v', 'a/z', 'a/y', 'a/x', 'a/w']);
  assert.deepEqual(sorted[3], { key: 'a/x', nodes: ['n'], cpu: 0.1, mem: 2, series: [0.9, 0.1, null] });
  assert.deepEqual(busiest(null), []);
  const spread = busiest({ workloads: {
    'a/s': { node: 'm', cpu: [0.2, null], mem: [5, null] },
    'a/s@n': { node: 'n', cpu: [0.3, 0.1], mem: [1, 2] },
  } });
  assert.deepEqual(spread, [{ key: 'a/s', nodes: ['m', 'n'], cpu: 0.1, mem: 2, series: [0.5, 0.1] }]);
  const rows = busiest(fixture('1h', END));
  assert.deepEqual(rows.map((one) => one.key), ['default/web', 'default/queue', 'default/mail']);
  assert.deepEqual(rows[0].nodes, ['alpha', 'beta']);
}

// The dashboard drawn into a page of fakes, against a kithd that keeps metrics and one that does not.
const dashboard = async (answer, { audit = [] } = {}) => {
  const made = (tag, props = {}, ...children) => ({
    tag,
    props,
    hidden: false,
    textContent: '',
    clientWidth: 640,
    children: children.flat(3).filter((child) => child != null && child !== false),
    setAttribute(name, value) { this.props[name] = value; },
    removeAttribute(name) { delete this.props[name]; },
    replaceChildren(...children) { this.children = children.flat(3).filter((child) => child != null && child !== false); this.textContent = ''; },
    append(...children) { this.children.push(...children.flat(3)); },
    addEventListener() {},
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 640, height: 160 }),
    style: { setProperty() {} },
  });
  const ids = new Map();
  const $ = (id) => ids.get(id) ?? ids.set(id, made('div', { id })).get(id);
  const words = (node) => (typeof node === 'string' ? node : [node.textContent, ...node.children.map(words)].join(' '));
  const find = (node, test, found = []) => {
    if (typeof node === 'string') return found;
    if (test(node)) found.push(node);
    node.children.forEach((child) => find(child, test, found));
    return found;
  };
  const calls = [];
  const api = async (method, what) => {
    calls.push([method, what]);
    if (what.startsWith('audit')) return audit;
    return answer(what);
  };
  const part = dashPart({ $, h: made, api, state: { resources: RESOURCES }, still: () => true });
  await part.refresh();
  return { $, part, calls, words, find };
};
const missingEndpoint = async () => { throw Object.assign(new Error('not found'), { status: 404 }); };
{
  // No /v1/metrics (a kithd from before T-1111): one calm line, the tiles kithd can still fill, no
  // red but what is down (the tiles' lamps of a node that is gone).
  const { $, calls, words, find } = await dashboard(missingEndpoint);
  assert.deepEqual(calls[0], ['GET', 'metrics?range=1h']);
  assert.match(words($('charts')), /no metrics yet/i);
  assert.equal(find($('charts'), (one) => one.tag === 'path').length, 0);
  assert.match(words($('tiles')), /2 of 3/);
  assert.match(words($('tiles')), /–/);
  for (const id of ['charts', 'busiest', 'dash-said']) {
    assert.equal(find($(id), (one) => /\bbad\b/.test(one.props.class ?? '')).length, 0, `${id}: nothing red`);
  }
}
{
  // Not allowed to read Nodes: said as calmly, with why.
  const { $, words } = await dashboard(async () => { throw Object.assign(new Error('forbidden'), { status: 403 }); });
  assert.match(words($('charts')), /may read Nodes/);
}
{
  // An identity that may read no namespace's Workloads gets `workloads: {}`: an empty table said
  // calmly, not an error; and memory or disk points kithd could not read are gaps, never 0.
  const metrics = fixture('1h', END);
  const { beta } = metrics.nodes;
  const holes = (values) => values.map((value, i) => (i % 7 === 3 ? null : value));
  const narrow = { ...metrics, workloads: {}, nodes: { ...metrics.nodes, beta: { ...beta, mem: holes(beta.mem), disk: holes(beta.disk) } } };
  const { $, words, find } = await dashboard(async () => narrow);
  assert.equal(find($('busiest'), (one) => one.tag === 'tr').length, 0);
  assert.match(words($('busiest')), /no workload you may see/i);
  assert.equal(find($('busiest'), (one) => /\bbad\b/.test(one.props.class ?? '')).length, 0);
  for (const id of ['mem', 'disk']) {
    const panel = find($('charts'), (one) => one.props['data-panel'] === id)[0];
    const drawn = find(panel, (one) => one.tag === 'path' && /\bs2\b/.test(one.props.class ?? ''))[0];
    // (Drawn as 0, a gap would be one unbroken line: one M.)
    assert.ok(drawn.props.d.split('M').length - 1 > 10, `${id}: beta's line lifts the pen at each gap`);
  }
}
{
  const metrics = fixture('1h', END, { missing: ['gamma'] });
  const audit = [
    { at: END - 600, who: 'alice', verb: 'apply', what: ['Workload/default/web'], ok: true },
    { at: END - 300, who: 'bob', verb: 'delete', what: ['ConfigMap/default/old'], ok: false, error: 'not yours' },
  ];
  const { $, part, calls, words, find } = await dashboard(async (what) => (what.startsWith('metrics') ? { ...metrics, range: what.split('=')[1] } : null), { audit });
  // A panel each, a line per node that answered (two in the panels of two: read and write, in and out).
  const panels = find($('charts'), (one) => one.tag === 'section');
  assert.deepEqual(panels.map((one) => one.props['data-panel']), PANELS.map((panel) => panel.id));
  for (const [panel, { id, series }] of panels.map((one, i) => [one, PANELS[i]])) {
    const drawn = find(panel, (one) => one.tag === 'path' && /\bseries\b/.test(one.props.class ?? ''));
    assert.equal(drawn.length, 2 * series.length, `${id}: alpha's and beta's`);
    assert.ok(drawn.every((one) => /\bs[12]\b/.test(one.props.class) && one.props.d.startsWith('M')), id);
    // (gamma is in the legend, said to be missing, and has no line.)
    assert.match(words(panel), /gamma.*no answer/);
  }
  assert.match(words($('charts')), /100%/, 'the CPU axis');
  for (const panel of panels) {
    // The axis's figures stand in a gutter at the left, and the lines start right of it: no line
    // runs through a figure.
    const plot = find(panel, (one) => one.tag === 'g')[0];
    const left = Number(/translate\((\d+(?:\.\d+)?) /.exec(plot.props.transform)?.[1]);
    const figures = find(panel, (one) => one.tag === 'text' && one.props['text-anchor'] === 'end' && one.props.class === 'tick figure');
    assert.ok(figures.length >= 2 && left >= 24, `${panel.props['data-panel']}: a gutter of ${left}`);
    assert.ok(figures.every((one) => one.props.x <= left - 4), `${panel.props['data-panel']}: every figure left of the lines`);
  }
  // Where a panel draws two measures, its title says which line is which: solid, then dotted.
  for (const [id, said] of [['io', /read.*write/], ['net', /in.*out/]]) {
    const head = find($('charts'), (one) => one.props['data-panel'] === id)[0].children[0];
    assert.match(words(head), said, id);
    assert.deepEqual(find(head, (one) => /\bswatch\b/.test(one.props.class ?? '')).map((one) => one.props.class), ['swatch', 'swatch second'], id);
  }
  // The tiles: sums of what answered.
  const { cpu } = tiles(RESOURCES, metrics);
  assert.match(words($('tiles')), new RegExp(format(cpu.used / cpu.total, 'pct')));
  // The workloads table: busiest first, each with its node.
  const rows = find($('busiest'), (one) => one.tag === 'tr').slice(1);
  assert.deepEqual(rows.map((row) => words(row.children[0]).trim()), ['default/web', 'default/queue']);
  // Recent events: newest first, a failed one said with its error.
  const recent = words($('recent'));
  assert.ok(recent.indexOf('bob') < recent.indexOf('alice'));
  assert.match(recent, /not yours/);
  // Another range: asked for, and drawn.
  const button = find($('ranges'), (one) => one.tag === 'button' && words(one).trim() === '6h')[0];
  await button.props.onclick();
  assert.deepEqual(calls.filter(([, what]) => what.startsWith('metrics')).map(([, what]) => what), ['metrics?range=1h', 'metrics?range=6h']);
  assert.equal(find($('ranges'), (one) => one.props['aria-pressed'] === 'true').map(words).join().trim(), '6h');
  part.show(false);
}

if (!process.argv[2]) {
  console.log('qr, the Add a peer dialog and the dashboard: ok');
  process.exit(0);
}
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
