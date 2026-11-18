// The Install part of the board: the steps of bringing another machine in, as stops on a
// rail: a join token, netboot, a new recovery key. Each is one of `kith`'s calls (`kith node
// token`, `kith node netboot`, `kith node recovery`), asked first, and what a call shows once
// (the token, the key) is shown in a dialog and kept by nothing once it is closed: not the
// page's storage, not its address, not a variable that outlives the dialog.
//
// What is drawn is kithd's text and the operator's own: text nodes only, as the board does.

/** The `join:` block of kith-install.yaml for a token: what the website's installer page writes. */
export function joinBlock(address, token) {
  return `join:\n  address: ${address}\n  token: ${JSON.stringify(token)}\n`;
}

/** How long is left of netboot, said: "28 minutes", "40 seconds". */
export function minutesLeft(seconds) {
  if (seconds < 90) return `${seconds} seconds`;
  const minutes = Math.round(seconds / 60);
  return `${minutes} minutes`;
}

/** The cards asked for, as the call takes them: commas between, nothing else. */
export function cards(text) {
  return text.split(/[\s,]+/).filter(Boolean).join(',');
}

export function installPart({ $, h, api, ask, toast, say, state }) {
  let timer = null;
  let shown = false;

  const nodes = () => state.resources.filter((resource) => resource.kind === 'Node');
  const names = (kind) => state.resources.filter((resource) => resource.kind === kind).map((resource) => resource.metadata.name).sort();

  /** A select's options, as they are now, with what was chosen kept if it is still there. */
  function fill(select, options) {
    const kept = select.value;
    select.replaceChildren(...options.map(([value, text]) => h('option', { value }, text)));
    if (options.some(([value]) => value === kept)) select.value = kept;
  }

  /** The nodes' addresses, and the nodes that keep a key: from what the board already holds. */
  function draw() {
    const addresses = nodes()
      .filter((node) => node.status?.address)
      .sort((a, b) => a.metadata.name.localeCompare(b.metadata.name))
      .map((node) => [node.status.address, `${node.status.address}  (${node.metadata.name})`]);
    fill($('token-at'), addresses.length ? addresses : [['', 'no node says its address']]);
    const keyed = names('NodeKey');
    fill($('recovery-node'), keyed.length ? keyed.map((name) => [name, name]) : [['', 'no node keeps its state encrypted']]);
    $('recovery-make').disabled = keyed.length === 0;
  }

  // ── A secret, shown once ──────────────────────────────────────────────────────────

  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast('Copied.');
    } catch {
      toast('The browser would not copy: select it, and copy it by hand.', true);
    }
  }

  const secret = (warning, label, text, big = false) => h('div', { class: 'secret' },
    h('p', { class: 'warning', role: 'alert' }, warning),
    h('label', {}, label),
    h('pre', { class: big ? 'key' : '', tabindex: 0 }, text),
    h('div', { class: 'tools' }, h('button', { type: 'button', class: 'small', onclick: () => copy(text) }, 'Copy')),
  );

  // ── 01: a join token ──────────────────────────────────────────────────────────────

  async function token() {
    const trust = $('token-trust').value;
    const address = $('token-at').value || 'ADDRESS:PORT';
    say($('token-check'), '');
    const made = await ask({
      title: 'Make a join token?',
      body: h('p', {}, `A machine with it can join this cluster as ${trust === 'worker' ? 'a worker, which only runs what it is given' : 'a control node, which votes and may do everything'}, for the next hour. Whoever holds it can do that: show it to nobody you would not let in.`),
      yes: 'Make the token',
      danger: trust === 'control',
      act: () => api('POST', `tokens?trust=${trust}`),
    });
    if (!made) return;
    await ask({
      title: 'A join token',
      body: secret(
        'Shown this once, and good for an hour. It is kept nowhere: close this and it is gone.',
        'join: for kith-install.yaml, the answers file of the installer (the website\'s installer page writes the rest)',
        joinBlock(address, made.token),
      ),
    });
  }

  // ── 02: netboot ───────────────────────────────────────────────────────────────────

  function drawNetboot(got) {
    const on = got.on === true;
    $('netboot-said').textContent = on
      ? `on, ${minutesLeft(got.secondsLeft)} left, disk ${got.disk}${got.encrypt ? ', encrypted' : ''}`
      : 'off';
    $('netboot-on').closest('.stop').classList.toggle('on', on);
    $('netboot-off').hidden = !on;
    $('netboot-on').textContent = on ? 'Turn on again' : 'Turn on';
    $('netboot-machines').replaceChildren(...(got.machines ?? []).map((machine) => h('li', {},
      h('code', {}, machine.mac),
      h('span', { class: machine.served ? 'ok' : 'dim' }, machine.served ? 'was sent the installer' : 'waiting for it to start'),
    )));
  }

  async function refresh() {
    try {
      drawNetboot(await api('GET', 'netboot'));
      say($('netboot-check'), '');
    } catch (error) {
      $('netboot-said').textContent = '';
      say($('netboot-check'), error.message, 'bad');
    }
  }

  async function netbootOn() {
    const [file] = $('netboot-file').files;
    const macs = cards($('netboot-macs').value);
    const minutes = Number($('netboot-minutes').value);
    const disk = $('netboot-disk').value.trim();
    const wrong = (field, why) => {
      for (const id of ['file', 'macs', 'minutes', 'disk']) $(`netboot-${id}`).removeAttribute('aria-invalid');
      if (why) $(`netboot-${field}`).setAttribute('aria-invalid', 'true');
      say($('netboot-check'), why || '', 'bad');
      return Boolean(why);
    };
    if (wrong('file', !file && 'Choose the boot file: kith-netboot.efi.')
      || wrong('macs', !macs && 'Give the network cards\' addresses of the machines to install.')
      || wrong('minutes', !(Number.isInteger(minutes) && minutes >= 1 && minutes <= 60) && 'Minutes are 1 to 60.')
      || wrong('disk', !/^[A-Za-z0-9]+$/.test(disk) && 'The disk is a name such as nvme0n1, or only.')) return;
    const query = new URLSearchParams({ macs, minutes: String(minutes), disk });
    if ($('netboot-encrypt').checked) query.set('encrypt', 'true');
    const count = macs.split(',').length;
    const got = await ask({
      title: 'Turn netboot on?',
      body: h('div', { class: 'plan' },
        h('p', {}, `For ${minutes} minutes this node answers ${count === 1 ? 'the machine' : `${count} machines`} that start from the network with these cards, and installs kith on each. ${disk === 'only' ? 'Each one\'s only disk is' : `Disk ${disk} of each is`} erased, and what it held is gone.`),
        h('pre', {}, macs.split(',').join('\n')),
      ),
      yes: 'Turn on',
      danger: true,
      act: () => api('PUT', `netboot?${query}`, file),
    });
    if (got) {
      drawNetboot(got);
      toast('Netboot is on.');
    }
  }

  async function netbootOff() {
    const got = await ask({
      title: 'Turn netboot off?',
      body: h('p', {}, 'No machine is answered after this, and one that has not yet been sent the installer will not be.'),
      yes: 'Turn off',
      danger: true,
      act: () => api('DELETE', 'netboot'),
    });
    if (got) {
      drawNetboot(got);
      toast('Netboot is off.');
    }
  }

  // ── 03: a recovery key ────────────────────────────────────────────────────────────

  async function recovery() {
    const node = $('recovery-node').value;
    if (!node) return;
    const made = await ask({
      title: `A new recovery key for ${node}?`,
      body: h('p', {}, `The recovery key ${node} has now stops working at once: a disk or a note that holds it opens nothing. The new one is shown once.`),
      yes: 'Make a new key',
      danger: true,
      act: () => api('POST', `lock/${encodeURIComponent(node)}/recovery`),
    });
    if (!made) return;
    await ask({
      title: `The recovery key of ${made.node}`,
      body: secret(
        `Write it down now, somewhere safe. It is shown this once and kept nowhere. The old key no longer works.`,
        `recovery key of ${made.node}`,
        made.recovery,
        true,
      ),
    });
  }

  // ── The part, in and out of view ──────────────────────────────────────────────────

  const failing = (what) => (error) => say($(what), error.message, 'bad');
  $('token-make').addEventListener('click', () => token().catch(failing('token-check')));
  $('netboot-on').addEventListener('click', () => netbootOn().catch(failing('netboot-check')));
  $('netboot-off').addEventListener('click', () => netbootOff().catch(failing('netboot-check')));
  $('recovery-make').addEventListener('click', () => recovery().catch(failing('recovery-check')));

  /** Netboot counts down: asked again every few seconds while it is in view. */
  async function poll() {
    window.clearTimeout(timer);
    if (!shown) return;
    if (!document.hidden) await refresh();
    timer = window.setTimeout(poll, 5000);
  }

  return {
    draw,
    show(on) {
      if (on === shown) return;
      shown = on;
      $('install').hidden = !on;
      document.querySelector('.board').hidden = on;
      if (on) $('install-link').setAttribute('aria-current', 'page');
      else $('install-link').removeAttribute('aria-current');
      if (on) draw();
      poll();
    },
  };
}
