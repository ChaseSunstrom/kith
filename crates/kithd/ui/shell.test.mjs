// The Terminal and Files tabs (shell.js), run by test.mjs: node ui/test.mjs.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { PROTOCOL, UPLOAD_MAX, above, ended, execPath, frame, inDir, plain, podName, shellPart, sizeText, socketUrl, tarOf, unframer, volumesOf } from './shell.js';

// The words of the wire: a pod's name, where its shell is, the frames, the tar of an upload.
assert.equal(PROTOCOL, 'v4.channel.k8s.io');
assert.deepEqual(['Workload', 'Job', 'NodeWorkload'].map((kind) => podName(kind, 'web', 2)), ['web-2', 'web-j2', 'web-n2']);
assert.equal(execPath('shop', 'web-0'), '../v1/exec/shop/web-0?command=sh&stdin=true&stdout=true&stderr=true');
assert.equal(execPath('a b', 'web-0', 'si/de'), '../v1/exec/a%20b/web-0?command=sh&stdin=true&stdout=true&stderr=true&container=si%2Fde');
assert.equal(socketUrl('../v1/exec/x/y-0?q=1', 'http://127.0.0.1:7/SECRET/ui/'), 'ws://127.0.0.1:7/SECRET/v1/exec/x/y-0?q=1');
assert.equal(socketUrl('../v1/exec/x/y-0', 'https://kith.example:7443/ui/'), 'wss://kith.example:7443/v1/exec/x/y-0');
assert.deepEqual([...frame(0, 'ls\n')], [0, 108, 115, 10]);
{
  // A character cut between two frames is whole when the second comes; each channel keeps its own.
  const read = unframer();
  const euro = new TextEncoder().encode('€');
  assert.equal(read(Uint8Array.from([1, euro[0], euro[1]])).text, '');
  assert.deepEqual(read(Uint8Array.from([1, euro[2], 33])), { channel: 1, text: '€!' });
  assert.deepEqual(read(Uint8Array.from([2, 98])), { channel: 2, text: 'b' });
}
assert.equal(plain('\u001b[1;31mred\u001b[0m\r\nok\u001b]0;title\u0007 \u0007x\u0000\ty'), 'red\nok x\ty');
assert.equal(ended('{"status":"Failure","message":"exit code 3"}'), 'exit code 3');
assert.equal(ended('{"status":"Success"}'), 'Success');
assert.equal(ended('  plain words '), 'plain words');
assert.equal(sizeText(5), '5 B');
assert.equal(sizeText(2048), '2.0 KiB');
assert.equal(sizeText(5 * 1024 * 1024 * 1024), '5.0 GiB');
assert.equal(inDir('', 'a'), 'a');
assert.equal(inDir('a/b', 'c'), 'a/b/c');
assert.deepEqual(['a/b', 'a', ''].map(above), ['a', '', '']);
{
  // A one-file tar is what tar reads: the name, the bytes and its mode, for a short name and a long one.
  const data = Uint8Array.from({ length: 700 }, (_, n) => n % 251);
  const long = `${'d'.repeat(60)}/${'e'.repeat(60)}/${'f'.repeat(60)}.txt`;
  for (const name of ['hello.txt', 'dir/sub/ü.bin', long]) {
    const made = tarOf(name, data, 1_700_000_000);
    assert.equal(made.length % 512, 0);
    assert.equal(execFileSync('tar', ['-tf', '-'], { input: made }).toString(), `${name}\n`);
    assert.deepEqual(new Uint8Array(execFileSync('tar', ['-xOf', '-'], { input: made })), data);
    assert.match(execFileSync('tar', ['-tvf', '-'], { input: made }).toString(), /^-rw-r--r-- .* 700 2023-11-14 /);
  }
  assert.equal(execFileSync('tar', ['-tf', '-'], { input: tarOf('/abs.txt', new Uint8Array(0)) }).toString(), 'abs.txt\n');
  assert.throws(() => tarOf(`${'x'.repeat(300)}`, data), /too long/);
  assert.throws(() => tarOf('', data), /no name/);
}
assert.deepEqual(volumesOf({ kind: 'Volume', metadata: { name: 'data' } }), ['data']);
assert.deepEqual(volumesOf({
  kind: 'Workload', metadata: { name: 'db' },
  spec: { replicas: 2, template: {
    containers: [{ volumeMounts: [{ volume: 'data', perReplica: true, path: '/d' }, { configMap: 'c', path: '/c' }, { volume: 'shared', path: '/s' }] }],
    initContainers: [{ volumeMounts: [{ volume: 'shared', path: '/s' }] }],
  } },
}), ['data-0', 'data-1', 'shared']);
assert.deepEqual(volumesOf({ kind: 'Workload', metadata: { name: 'x' }, spec: { template: { containers: [{}] } } }), []);

// The panes, drawn with fakes: a page of plain objects, a socket that is told what happens, a kithd that answers a listing.
const element = (tag, props = {}, ...children) => ({
  // (A select's value is its first option's until one is picked, as in a browser.)
  tag, props, value: tag === 'select' ? (children.flat(3)[0]?.textContent ?? '') : '', children: children.flat(3).filter((child) => child != null && child !== false), handlers: {}, scrollTop: 0, scrollHeight: 1,
  append(...more) { this.children.push(...more); },
  replaceChildren(...more) { this.children = more.flat(3).filter((child) => child != null && child !== false); },
  addEventListener(name, run) { this.handlers[name] = run; },
  get textContent() { return this.children.map((child) => (typeof child === 'string' ? child : child.textContent)).join(''); },
  set textContent(text) { this.children = [text]; },
});
const nodes = (node, test, found = []) => {
  if (typeof node === 'string') return found;
  if (test(node)) found.push(node);
  node.children.forEach((child) => nodes(child, test, found));
  return found;
};
const button = (pane, words) => nodes(pane, (node) => node.tag === 'button' && node.textContent === words)[0];
const later = () => new Promise((done) => setTimeout(done));
const toasted = [];

{
  const sockets = [];
  class Wire {
    constructor(url) { this.url = url; this.sent = []; this.readyState = 0; sockets.push(this); }
    send(bytes) { this.sent.push(bytes); }
    close() { this.readyState = 3; this.onclose?.(); }
  }
  const part = shellPart({ h: element, api: async () => ({}), ask: async () => undefined, toast: (...said) => toasted.push(said), socket: (to) => new Wire(to), blob: async () => new Blob([]), save() {} });
  const web = { kind: 'Workload', metadata: { name: 'web', namespace: 'shop' }, status: { containers: [{ name: 'main', replica: 0 }, { name: 'main', replica: 1 }, { name: 'side', replica: 1 }] } };
  const pane = part.terminalPane(web);
  const [unit, replica] = nodes(pane, (node) => node.tag === 'select');
  const [out, line] = [nodes(pane, (node) => node.tag === 'pre')[0], nodes(pane, (node) => node.tag === 'input')[0]];
  assert.equal(line.props.disabled, true, 'a line to type before any shell is open');
  [unit.value, replica.value] = ['side', '1'];
  button(pane, 'Open a shell').props.onclick();
  const wire = sockets[0];
  assert.equal(wire.url, '../v1/exec/shop/web-1?command=sh&stdin=true&stdout=true&stderr=true&container=side');
  assert.equal(wire.binaryType, 'arraybuffer');
  line.value = 'early';
  line.handlers.keydown({ key: 'Enter' });
  assert.deepEqual(wire.sent, [], 'nothing is sent before the shell is open');
  wire.readyState = 1;
  wire.onopen();
  assert.equal(line.disabled, false);
  assert.equal(button(pane, 'Close').hidden, false);
  wire.onmessage({ data: frame(1, 'hi \u001b[31mthere\u001b[0m\n').buffer });
  wire.onmessage({ data: frame(2, 'oops\n').buffer });
  wire.onmessage({ data: 'a text frame' });
  assert.match(out.textContent, /opening a shell in web-1\nhi there\noops\n$/);
  line.value = 'ls -l';
  line.handlers.keydown({ key: 'Enter' });
  line.value = 'pwd';
  line.handlers.keydown({ key: 'Enter' });
  assert.deepEqual(wire.sent.map((bytes) => [...bytes]), [[...frame(0, 'ls -l\n')], [...frame(0, 'pwd\n')]]);
  assert.match(out.textContent, /\n\$ ls -l\n\$ pwd\n$/);
  assert.equal(line.value, '');
  const key = (name) => line.handlers.keydown({ key: name, preventDefault() {} });
  key('ArrowUp');
  assert.equal(line.value, 'pwd');
  key('ArrowUp');
  assert.equal(line.value, 'ls -l');
  key('ArrowUp');
  assert.equal(line.value, 'ls -l');
  key('ArrowDown');
  key('ArrowDown');
  assert.equal(line.value, '');
  wire.onmessage({ data: frame(3, '{"status":"Failure","message":"command terminated with exit code 2"}').buffer });
  assert.match(out.textContent, /\n\[command terminated with exit code 2\]\n$/);
  // A flood is cut to the last of it.
  wire.onmessage({ data: frame(1, 'x'.repeat(300_000)).buffer });
  assert.ok(out.textContent.length <= 200_000);
  // A second shell ends the first; the pane going away ends it too.
  button(pane, 'Close').props.onclick();
  assert.match(out.textContent, /\[the shell is closed\]\n$/);
  assert.equal(line.disabled, true);
  assert.equal(button(pane, 'Open a shell').hidden, false);
  button(pane, 'Open a shell').props.onclick();
  const [, second] = sockets;
  second.readyState = 1;
  second.onopen();
  button(pane, 'Open a shell').props.onclick();
  assert.equal(second.readyState, 3, 'a new shell ends the old one');
  const [, , third] = sockets;
  part.end();
  assert.equal(third.readyState, 3, 'the pane replaced ends its shell');
  // A shell that never opened (refused: a browser is told no more than that) says what that is likely to be.
  const refused = sockets.at(-1);
  assert.match(out.textContent, /no shell: kithd refused it/);
  assert.equal(refused.readyState, 3);
  // A Job's pod and a NodeWorkload's are named as kithd names them; one replica needs no picking.
  const job = part.terminalPane({ kind: 'Job', metadata: { name: 'ask' }, status: { containers: [{ name: 'main' }] } });
  button(job, 'Open a shell').props.onclick();
  assert.equal(sockets.at(-1).url, '../v1/exec/default/ask-j0?command=sh&stdin=true&stdout=true&stderr=true&container=main');
  part.end();
}

{
  const calls = [];
  const saved = [];
  const dialogs = [];
  const listings = {
    '': { path: '', entries: [{ name: 'sub', kind: 'dir', size: 0, mtime: 0 }, { name: 'x', kind: 'file', size: 5, mtime: 0 }, { name: 'l', kind: 'link', to: '/etc/passwd', size: 0, mtime: 0 }, { name: 'p', kind: 'other', size: 0, mtime: 0 }], truncated: true },
    sub: { path: 'sub', entries: [{ name: 'a b.txt', kind: 'file', size: 2048, mtime: 0 }], truncated: false },
  };
  const api = async (...call) => {
    calls.push(call);
    if (call[0] === 'PUT') return { files: 1 };
    const asked = new URL(call[1], 'http://x/').searchParams.get('path');
    if (!(asked in listings)) throw new Error(`${asked}: no such directory`);
    return listings[asked];
  };
  const part = shellPart({
    h: element, api, toast: (...said) => toasted.push(said), socket() { throw new Error('no shell here'); },
    ask: async (dialog) => { dialogs.push(dialog); return dialog.act(); },
    blob: async (what) => { calls.push(['BLOB', what]); return new Blob(['bytes']); },
    save: (file, name) => saved.push([file, name]),
  });
  assert.match(part.filesPane({ kind: 'Workload', metadata: { name: 'x' }, spec: {} }).textContent, /mounts no Volume/);
  const pane = part.filesPane({ kind: 'Workload', metadata: { name: 'db', namespace: 'shop' }, spec: { replicas: 2, template: { containers: [{ volumeMounts: [{ volume: 'data', perReplica: true, path: '/d' }] }] } } });
  await later();
  assert.deepEqual(calls.at(-1), ['GET', 'volumes/shop/data-0/ls?path=']);
  const table = () => nodes(pane, (node) => node.tag === 'tbody')[0];
  assert.deepEqual(table().children.map((row) => row.children[0].textContent), ['sub/', 'x', 'l → /etc/passwd', 'p (not a file)']);
  assert.match(pane.textContent, /Only the first of them are shown/);
  assert.equal(table().children[1].children[1].textContent, '5 B');
  assert.equal(button(pane, 'Up'), undefined, 'no way up from the top');
  // Into a directory and its file, by a name with a space in it.
  button(pane, 'sub/').props.onclick();
  await later();
  assert.deepEqual(calls.at(-1), ['GET', 'volumes/shop/data-0/ls?path=sub']);
  assert.match(pane.textContent, /data-0:\/sub/);
  button(pane, 'a b.txt').props.onclick();
  await later();
  assert.deepEqual(calls.at(-1), ['BLOB', 'volumes/shop/data-0/files?path=sub%2Fa%20b.txt']);
  assert.equal(saved[0][1], 'a b.txt');
  assert.equal(await saved[0][0].text(), 'bytes');
  // A file goes up as a tar of it, after a question, into the directory in view; a big one does not go.
  const chooser = nodes(pane, (node) => node.tag === 'input')[0];
  chooser.files = [{ name: 'n.txt', size: 3, lastModified: 5000, arrayBuffer: async () => Uint8Array.from([1, 2, 3]).buffer }];
  await chooser.handlers.change();
  assert.equal(dialogs.length, 1);
  assert.equal(dialogs[0].title, 'Upload n.txt?');
  assert.match(dialogs[0].body.textContent, /\/sub\/n\.txt in data-0/);
  const put = calls.find((call) => call[0] === 'PUT');
  assert.equal(put[1], 'volumes/shop/data-0/files');
  assert.deepEqual(new Uint8Array(await put[2].arrayBuffer()), tarOf('sub/n.txt', Uint8Array.from([1, 2, 3]), 5));
  assert.deepEqual(toasted.at(-1), ['n.txt is in data-0.']);
  assert.deepEqual(calls.at(-1), ['GET', 'volumes/shop/data-0/ls?path=sub'], 'the listing is drawn again');
  chooser.files = [{ name: 'big', size: UPLOAD_MAX + 1, arrayBuffer: async () => assert.fail('a big file is not read') }];
  await chooser.handlers.change();
  assert.equal(dialogs.length, 1);
  assert.equal(toasted.at(-1)[1], true);
  assert.match(toasted.at(-1)[0], /kith volume cp/);
  // Up goes back; a directory kithd refuses says why, in the place of the table.
  button(pane, 'Up').props.onclick();
  await later();
  assert.deepEqual(calls.at(-1), ['GET', 'volumes/shop/data-0/ls?path=']);
  delete listings[''];
  const [volume] = nodes(pane, (node) => node.tag === 'select');
  volume.value = 'data-1';
  volume.props.onchange();
  await later();
  assert.deepEqual(calls.at(-1), ['GET', 'volumes/shop/data-1/ls?path=']);
  assert.match(pane.textContent, /no such directory/);
}
