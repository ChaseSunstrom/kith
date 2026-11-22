// The Terminal and Files tabs of a Workload (and the Files tab of a Volume): a shell in a
// replica over a WebSocket, and a Volume's files to list, download and upload. No library:
// the page's own code, speaking what `kubectl exec` speaks (kithd's /v1/exec, one byte of
// channel before each frame) and the calls `kith volume cp` makes (/v1/volumes/NS/NAME/ls
// and /files).
//
// The terminal is a line at a time, with no tty: a command is typed, sent with its newline, and
// what the shell prints comes back as text. What comes back is a replica's, other people's text:
// it goes into the page as text nodes only, with the escape codes of a terminal taken out.
// Nothing typed or shown is kept by the page: not its storage, not its address.

/** The subprotocol of `kubectl exec`'s stream: channel 0 is stdin, 1 stdout, 2 stderr, 3 the end. */
export const PROTOCOL = 'v4.channel.k8s.io';
/** The most a file sent from the page may be: the page holds it, and its tar, in memory. */
export const UPLOAD_MAX = 64 * 1024 * 1024;
/** The most of a session's output the page keeps on screen. */
const SCREEN = 200_000;
const MARKS = { Workload: '', Job: 'j', NodeWorkload: 'n' };
const enc = encodeURIComponent;

/** The name of the pod that replica `replica` of a `kind` named `name` is (kithd's own rule). */
export const podName = (kind, name, replica) => `${name}-${MARKS[kind] ?? ''}${replica}`;

/** Where the shell of a pod is, from the page (a path kithd's API is at). */
export function execPath(namespace, pod, unit) {
  const query = ['command=sh', 'stdin=true', 'stdout=true', 'stderr=true'];
  if (unit) query.push(`container=${enc(unit)}`);
  return `../v1/exec/${enc(namespace)}/${enc(pod)}?${query.join('&')}`;
}

/** A path of the page as the WebSocket's address: the same place, `ws` or `wss`. */
export function socketUrl(path, base) {
  const url = new URL(path, base);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  return url.href;
}

/** What is typed, as a frame for a channel. */
export function frame(channel, text) {
  const body = new TextEncoder().encode(text);
  const out = new Uint8Array(body.length + 1);
  out[0] = channel;
  out.set(body, 1);
  return out;
}

/** A reader of frames: `{ channel, text }` of each, a character cut between two frames made whole. */
export function unframer() {
  const decoders = new Map();
  return (data) => {
    const bytes = new Uint8Array(data);
    if (!decoders.has(bytes[0])) decoders.set(bytes[0], new TextDecoder());
    return { channel: bytes[0], text: decoders.get(bytes[0]).decode(bytes.subarray(1), { stream: true }) };
  };
}

/** Text from a terminal with its escape codes and other controls taken out (a tab and a newline stay). */
export function plain(text) {
  return String(text)
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?/g, '')
    .replace(/\r\n/g, '\n')
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '');
}

/** What the end of a session said (channel 3: a Status as JSON), as one line. */
export function ended(text) {
  try {
    const status = JSON.parse(text);
    return status.message ?? status.reason ?? status.status ?? 'ended';
  } catch {
    return text.trim() || 'ended';
  }
}

/** A file as a tar of that one file (ustar), as `PUT /files` takes it: `path` is its name in the Volume. */
export function tarOf(path, bytes, mtime = 0) {
  const name = new TextEncoder().encode(path.replace(/^\/+/, ''));
  if (!name.length || name.includes(0)) throw new Error('That is no name for a file.');
  if (bytes.length >= 2 ** 33) throw new Error('A file of 8 GiB or more does not go in one tar.');
  let [prefix, base] = [name.subarray(0, 0), name];
  if (name.length > 100) {
    // (A name too long for the header's name is cut at a slash: the rest goes in its prefix.)
    const cut = name.findIndex((byte, at) => byte === 47 && at > 0 && at <= 155 && name.length - at - 1 <= 100 && at < name.length - 1);
    if (cut < 0) throw new Error('That name is too long for a tar.');
    [prefix, base] = [name.subarray(0, cut), name.subarray(cut + 1)];
  }
  const head = new Uint8Array(512);
  const number = (at, width, value) => head.set(new TextEncoder().encode(value.toString(8).padStart(width - 1, '0')), at);
  head.set(base, 0);
  number(100, 8, 0o644);
  number(108, 8, 0);
  number(116, 8, 0);
  number(124, 12, bytes.length);
  number(136, 12, Math.max(0, Math.floor(mtime)));
  head.fill(32, 148, 156);
  head[156] = 48;
  head.set(new TextEncoder().encode('ustar\u000000'), 257);
  head.set(prefix, 345);
  const sum = head.reduce((total, byte) => total + byte, 0);
  head.set(new TextEncoder().encode(`${sum.toString(8).padStart(6, '0')}\u0000 `), 148);
  const padded = Math.ceil(bytes.length / 512) * 512;
  const out = new Uint8Array(512 + padded + 1024);
  out.set(head, 0);
  out.set(bytes, 512);
  return out;
}

/** The Volumes a Workload mounts (one for each replica of a per-replica one), or a Volume's own name. */
export function volumesOf(resource) {
  if (resource.kind === 'Volume') return [resource.metadata.name];
  const template = resource.spec?.template ?? {};
  const mounts = [...(template.containers ?? []), ...(template.initContainers ?? [])].flatMap((unit) => unit.volumeMounts ?? []);
  const replicas = Array.from({ length: Math.max(1, Number(resource.spec?.replicas) || 1) }, (_, n) => n);
  return [...new Set(mounts.filter((mount) => mount.volume).flatMap((mount) => (mount.perReplica ? replicas.map((n) => `${mount.volume}-${n}`) : [mount.volume])))];
}

/** A path inside a Volume: `dir` and a `name` in it. */
export const inDir = (dir, name) => (dir ? `${dir}/${name}` : name);
/** The directory above `dir`. */
export const above = (dir) => dir.split('/').slice(0, -1).join('/');

export function sizeText(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let [value, at] = [bytes / 1024, 0];
  while (value >= 1024 && at < units.length - 1) [value, at] = [value / 1024, at + 1];
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[at]}`;
}

/**
 * The two panes. `socket(path)` opens the WebSocket for a path of the API, `blob(what)` reads a
 * file's bytes, `save(blob, name)` hands it to the browser's download, and `ask` is the board's dialog.
 */
export function shellPart({ h, api, ask, toast, socket, blob, save }) {
  let session = null;
  /** End the shell in view, if there is one: a pane that is replaced does not leave one open. */
  const end = () => {
    const open = session;
    session = null;
    open?.close();
  };

  function terminalPane(resource) {
    const { kind, metadata: { name, namespace = 'default' } } = resource;
    const units = [...new Set((resource.status?.containers ?? []).map((unit) => unit.name))];
    const replicas = [...new Set((resource.status?.containers ?? []).map((unit) => unit.replica ?? 0))].sort((a, b) => a - b);
    const pick = (label, options) => {
      const select = h('select', {}, options.map((option) => h('option', {}, String(option))));
      return [h('label', { class: 'dim' }, `${label} `, select), select];
    };
    const [[unitLabel, unit], [replicaLabel, replica]] = [pick('unit', units), pick('replica', replicas.length ? replicas : [0])];
    const out = h('pre', { class: 'logs', tabindex: '0', 'aria-label': 'Shell output' });
    const line = h('input', { type: 'text', class: 'line', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Command', placeholder: 'a command, then Enter', disabled: true });
    const open = h('button', { type: 'button', class: 'small', onclick: () => connect() }, 'Open a shell');
    const close = h('button', { type: 'button', class: 'small', hidden: true, onclick: () => end() }, 'Close');
    const earlier = [];
    let [back, length] = [0, 0];
    const write = (text) => {
      out.append(text);
      length += text.length;
      if (length > SCREEN * 1.5) {
        out.textContent = out.textContent.slice(-SCREEN);
        length = SCREEN;
      }
      out.scrollTop = out.scrollHeight;
    };
    const toggle = (on) => {
      line.disabled = !on;
      open.hidden = on;
      close.hidden = !on;
    };
    function connect() {
      end();
      const pod = podName(kind, name, replica.value || 0);
      const socketOf = socket(execPath(namespace, pod, unit.value));
      const read = unframer();
      let opened = false;
      write(`\nopening a shell in ${pod}\n`);
      socketOf.binaryType = 'arraybuffer';
      socketOf.onopen = () => {
        opened = true;
        toggle(true);
        line.focus?.();
      };
      socketOf.onmessage = (event) => {
        if (typeof event.data === 'string') return;
        const { channel, text } = read(event.data);
        if (channel === 1 || channel === 2) write(plain(text));
        else if (channel === 3) write(`\n[${plain(ended(text))}]\n`);
      };
      socketOf.onclose = () => {
        if (session === socketOf) session = null;
        toggle(false);
        write(opened ? '\n[the shell is closed]\n' : '\n[no shell: kithd refused it, or the replica is not running]\n');
      };
      session = socketOf;
    }
    line.addEventListener('keydown', (event) => {
      if (event.key === 'ArrowUp' || event.key === 'ArrowDown') {
        back = Math.min(earlier.length, Math.max(0, back + (event.key === 'ArrowUp' ? 1 : -1)));
        line.value = back ? earlier[earlier.length - back] : '';
        return event.preventDefault?.();
      }
      if (event.key !== 'Enter' || !session || session.readyState !== 1) return;
      const typed = line.value;
      if (typed && earlier.at(-1) !== typed) earlier.push(typed);
      back = 0;
      line.value = '';
      write(`$ ${typed}\n`);
      session.send(frame(0, `${typed}\n`));
    });
    return h('div', { class: 'logs-box' },
      h('div', { class: 'tools' }, units.length > 1 && unitLabel, replicaLabel, open, close,
        h('span', { class: 'dim' }, 'A line at a time: no tty, so no editor or prompt.')),
      out, line);
  }

  function filesPane(resource) {
    const namespace = resource.metadata.namespace ?? 'default';
    const volumes = volumesOf(resource);
    if (!volumes.length) return h('p', { class: 'dim' }, `${resource.metadata.name} mounts no Volume.`);
    const volume = h('select', { onchange: () => go('') }, volumes.map((one) => h('option', {}, one)));
    const shown = h('div', { class: 'files' });
    const where = h('span', { class: 'dim' });
    const base = () => `volumes/${enc(namespace)}/${enc(volume.value || volumes[0])}`;
    let dir = '';
    const fail = (error) => toast(error.message, true);

    async function download(path, name) {
      save(await blob(`${base()}/files?path=${enc(path)}`), name);
    }

    async function go(path) {
      try {
        const listed = await api('GET', `${base()}/ls?path=${enc(path)}`);
        dir = path;
        where.textContent = `${volume.value || volumes[0]}:/${path}`;
        const rows = listed.entries.map((entry) => {
          const mine = inDir(dir, entry.name);
          const cell = entry.kind === 'dir' ? h('button', { type: 'button', class: 'link', onclick: () => go(mine) }, `${entry.name}/`)
            : entry.kind === 'file' ? h('button', { type: 'button', class: 'link', onclick: () => download(mine, entry.name).catch(fail) }, entry.name)
            : h('span', { class: 'dim' }, entry.kind === 'link' ? `${entry.name} → ${entry.to}` : `${entry.name} (not a file)`);
          return h('tr', {}, h('td', {}, cell),
            h('td', { class: 'num' }, entry.kind === 'file' ? sizeText(entry.size) : ''),
            h('td', { class: 'dim' }, new Date(entry.mtime * 1000).toLocaleString()));
        });
        shown.replaceChildren(
          dir && h('button', { type: 'button', class: 'small', onclick: () => go(above(dir)) }, 'Up'),
          h('table', {}, h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Name'), h('th', { scope: 'col', class: 'num' }, 'Size'), h('th', { scope: 'col' }, 'Modified'))),
            h('tbody', {}, rows)),
          !rows.length && h('p', { class: 'dim' }, 'Empty.'),
          listed.truncated && h('p', { class: 'dim' }, 'Only the first of them are shown.'));
      } catch (error) {
        shown.replaceChildren(h('p', { class: 'bad' }, error.message));
      }
    }

    const chooser = h('input', { type: 'file', 'aria-label': 'File to upload' });
    chooser.addEventListener('change', async () => {
      const file = chooser.files?.[0];
      if (!file) return;
      try {
        if (file.size > UPLOAD_MAX) throw new Error(`${file.name} is over ${sizeText(UPLOAD_MAX)}: \`kith volume cp\` takes larger ones.`);
        const path = inDir(dir, file.name);
        const tar = tarOf(path, new Uint8Array(await file.arrayBuffer()), (file.lastModified ?? 0) / 1000);
        await ask({
          title: `Upload ${file.name}?`,
          body: h('p', {}, `${sizeText(file.size)} go to /${path} in ${volume.value || volumes[0]}. A file of that name there is replaced.`),
          yes: 'Upload',
          act: () => api('PUT', `${base()}/files`, new Blob([tar])),
        }).then((done) => done && toast(`${file.name} is in ${volume.value || volumes[0]}.`));
        await go(dir);
      } catch (error) {
        fail(error);
      } finally {
        chooser.value = '';
      }
    });
    go('');
    return h('div', { class: 'files-box' },
      h('div', { class: 'tools' }, volumes.length > 1 && h('label', { class: 'dim' }, 'volume ', volume), where, chooser), shown);
  }

  return { terminalPane, filesPane, end };
}
