// The installer's page: the form writes kith-install.yaml, the answers kithd's installer reads
// (crates/kithd/src/install.rs, `Answers`), and says what is wrong with one before the stick has it.
// Nothing typed here is sent anywhere or kept: the page makes no request, and the form is never submitted.
const $ = (q, el = document) => el.querySelector(q);
const $$ = (q, el = document) => [...el.querySelectorAll(q)];
const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;
const form = $("#answers"), pre = $("#yaml"), url = $("#installUrl");
const f = name => form.elements[name];

// Motion can be stopped, as on the front page.
const motion = $("#motion");
motion.hidden = calm;
motion.onclick = () => {
  const paused = document.documentElement.classList.toggle("paused");
  motion.setAttribute("aria-pressed", paused);
};

// What the installer accepts, as it checks it (install.rs, init.rs, policy.rs): said here first.
const octets = s => { const p = s.split("."); return p.length === 4 && p.every(o => /^(0|[1-9][0-9]{0,2})$/.test(o) && +o <= 255); };
const ipv6 = s => { try { return /^[0-9a-fA-F:.]{2,45}$/.test(s) && !!new URL(`http://[${s}]`); } catch { return false; } }; // the browser's own parser, as the installer's is a real one
const KEYS = ["exec-units", "root-containers", "unconfined", "node-network", "vms", "vm-paths", "passthrough", "host-paths", "run", "wipe"];
const CLASSES = ["gpu", "display", "input", "audio", "usb", "camera", "other"];
const policyWord = w => w === "hardened" || KEYS.includes(w) || (w.startsWith("no-") && KEYS.includes(w.slice(3)))
  || (w.startsWith("devices=") && (w === "devices=all" || w.slice(8).split("+").filter(Boolean).every(c => CLASSES.includes(c))));

// A value is written as it is when YAML would read it back as the same text, and in quotes when it
// might be a number, a truth or a null (a hostname `123`, a disk `n`).
const WORDS = /^(true|false|null|yes|no|on|off|y|n|~)$/i;
const plain = s => /^[A-Za-z0-9]([A-Za-z0-9._:/,-]*[A-Za-z0-9._/,-])?$/.test(s) && !WORDS.test(s) && !Number.isFinite(Number(s))
  && !/^[0-9_:]+(\.[0-9_]*)?$/.test(s) && !/^0[box]/i.test(s);
const text = s => (plain(s) ? s : JSON.stringify(s));

// The form as the answers it makes: the lines of the file, and what is wrong or missing (in the file's order).
function compile() {
  const lines = [], errors = [];
  const val = name => f(name).value.trim();
  const wrong = (field, msg) => errors.push({ field, msg, wrong: true });
  const missing = (field, msg) => errors.push({ field, msg, wrong: false });

  const disk = f("diskKind").value;
  if (disk === "only") lines.push("disk: only");
  else if (disk === "name") {
    const name = val("diskName");
    if (!name) missing("diskName", "name the disk, or choose another way to name it.");
    else if (name === "only") wrong("diskName", "\"only\" is the first choice above, not a disk's name.");
    else if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)) wrong("diskName", "a disk's name is letters, digits and . _ - as the kernel names it (sda, nvme0n1).");
    else lines.push(`disk: ${text(name)}`);
  } else {
    const serial = val("diskSerial");
    if (!serial) missing("diskSerial", "give the disk's serial, which the installer lists beside each disk.");
    else if (!/^[\x20-\x7e]+$/.test(serial)) wrong("diskSerial", "a serial is printable ASCII.");
    else lines.push(`disk: ${JSON.stringify("serial:" + serial)}`);
  }

  const host = val("hostname");
  if (host && !/^[a-z0-9-]{1,63}$/.test(host)) wrong("hostname", "a name is lower-case letters, digits and -, up to 63: a DNS label.");
  else if (host) lines.push(`hostname: ${text(host)}`);

  if (f("ipKind").value === "static") {
    const parts = val("ipAddress").split("/"), [address, bits = ""] = parts, way = val("ipGateway");
    if (!val("ipAddress")) missing("ipAddress", "give the fixed address, as 10.0.0.5/24.");
    else if (parts.length !== 2 || !octets(address) || !/^(0|[1-9][0-9]?)$/.test(bits) || +bits > 32) wrong("ipAddress", "the address is ADDRESS/BITS, as 10.0.0.5/24.");
    else if (way && !octets(way)) wrong("ipGateway", "the way out is an IPv4 address, as 10.0.0.1.");
    else lines.push(`ip: ${text(val("ipAddress") + (way ? "," + way : ""))}`);
  }

  const dns = val("dns");
  if (dns && !octets(dns) && !ipv6(dns)) wrong("dns", "the DNS server is an IP address, as 10.0.0.1.");
  else if (dns) lines.push(`dns: ${text(dns)}`);

  if (f("clusterKind").value === "join") {
    const address = val("joinAddress"), token = val("joinToken");
    let bad = false;
    if (!address) (bad = true, missing("joinAddress", "give the address of one of the cluster's nodes."));
    else if (!/^[A-Za-z0-9.:\[\]-]+$/.test(address) || !/:[0-9]{1,5}$/.test(address) || address.startsWith("-")) (bad = true, wrong("joinAddress", "a node's address is ADDRESS:PORT, as 10.0.0.7:7443."));
    if (!token) (bad = true, missing("joinToken", "give the join token."));
    else if (!/^[A-Za-z0-9.-]+$/.test(token) || token.startsWith("-")) (bad = true, wrong("joinToken", "that is not a join token: \"kith node token\" on the cluster makes them."));
    if (!bad) lines.push("join:", `  address: ${text(address)}`, `  token: ${JSON.stringify(token)}`);
  }

  if (f("encrypt").checked) lines.push("encrypt: true");

  const release = val("releaseKey");
  if (release) {
    const keys = release.split(",").map(key => key.trim());
    if (keys.length > 8 || !keys.every(key => /^[0-9a-fA-F]{64}$/.test(key))) wrong("releaseKey", "a release key is 64 hex digits; one to eight, with commas between.");
    else lines.push(`releaseKey: ${JSON.stringify(keys.join(","))}`);
  }

  if (f("lanReleases").checked) lines.push("lanReleases: true");

  const policy = f("policyKind").value;
  if (policy === "hardened") lines.push("nodePolicy: hardened");
  else if (policy === "custom") {
    const words = val("policyWords").replace(/\s+/g, "").split(",").filter(Boolean);
    const unknown = words.find(w => !policyWord(w));
    if (!words.length) missing("policyWords", "say a word of the policy, or choose another.");
    else if (unknown) wrong("policyWords", `"${unknown}" is not a word of the policy: see "Which words".`);
    else lines.push(`nodePolicy: ${text(words.join(","))}`);
  }
  return { lines, errors };
}

// Draw the file: the keys in the accent, and a line that has changed flashes once.
const el = (tag, cls) => Object.assign(document.createElement(tag), { className: cls });
let shown = [], touched = new Set(), stamp = 0;
function draw(lines, first) {
  pre.replaceChildren(...lines.map((line, i) => {
    const span = el("span", "l"), m = /^(\s*)([A-Za-z]+:)(.*)$/.exec(line);
    if (m) {
      const key = el("span", "k");
      key.textContent = m[2];
      span.append(m[1], key, m[3]);
    } else span.textContent = line;
    span.append("\n");
    if (!first && shown[i] !== line) span.classList.add("new");
    return span;
  }));
  shown = lines;
}

// A field says what is wrong with it under itself; a missing one only after it has been left.
function mark(input, say) {
  const field = input.closest(".field"), id = `${input.id}-err`;
  let note = $(`#${id}`);
  if (say && !note) (note = el("p", "err"), note.id = id, field.append(note));
  if (note) say ? (note.textContent = say) : note.remove();
  input.setAttribute("aria-invalid", !!say);
  say ? input.setAttribute("aria-describedby", id) : input.removeAttribute("aria-describedby");
}

const said = $("#say"), lamp = $("#lamp"), cmd = $("#cmdline"), cmdsay = $("#cmdsay");
let ready = false, last = "";
function render(first) {
  const { lines, errors } = compile();
  ready = !errors.length;
  for (const branch of $$(".branch")) {
    const [name, value] = branch.dataset.when.split("=");
    branch.classList.toggle("open", f(name).value === value);
  }
  const visible = e => e.wrong || touched.has(e.field);
  for (const input of $$('input[type="text"]', form)) {
    const e = errors.find(e => e.field === input.name);
    mark(input, e && visible(e) ? e.msg.replace(/^./, c => c.toUpperCase()) : "");
  }
  for (const part of $$("section.part[id]", form)) part.classList.toggle("bad", errors.some(e => visible(e) && f(e.field).closest("section") === part));

  const yaml = lines.join("\n") + "\n";
  draw(lines, first);
  $("#sum").textContent = `${lines.length} ${lines.length === 1 ? "line" : "lines"}, ${new Blob([yaml]).size} bytes`;
  lamp.className = `lamp ${!errors.length ? "ok" : errors.some(e => e.wrong) ? "bad" : "wait"}`;
  said.className = `status${errors.some(e => e.wrong) ? " bad" : ""}`;
  said.textContent = errors.length ? `Not yet: ${errors[0].msg}` : "Ready: this is the whole file.";
  for (const id of ["get", "copy"]) $(`#${id}`).disabled = !ready;
  pin(yaml);
}

// The pin for a URL: the file's own sha-256, made in the page by the browser (it needs a secure page).
async function pin(yaml) {
  const mine = ++stamp, address = url.value.trim();
  const fine = !address || /^https?:\/\/[^\s#]+$/.test(address);
  mark(url, fine ? "" : "The address is http:// or https://, then the host and the file, with no # and no spaces.");
  let hex = "HEX", note = "The digest is of the file as it is now: a change to an answer changes it. `sha256sum kith-install.yaml` prints the same.";
  if (!ready) note = "The digest is made when the answers are complete.";
  else if (!crypto.subtle) note = "This page is not a secure one (https, or localhost), so the browser will not make the digest here: `sha256sum kith-install.yaml` prints it, and goes after #sha256=.";
  else hex = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(yaml)))].map(b => b.toString(16).padStart(2, "0")).join("");
  if (mine !== stamp) return; // a later change has made its own
  const line = `kith.install=${address && fine ? address : "http://HOST/FILE"}#sha256=${hex}`;
  if (line !== last && last) (cmd.classList.remove("live"), void cmd.offsetWidth, cmd.classList.add("live"));
  last = line;
  cmd.textContent = line;
  cmdsay.textContent = note.replaceAll("`", "");
}

let timer;
const toast = say => {
  const t = $("#toast");
  t.textContent = say;
  t.classList.add("on");
  clearTimeout(timer);
  timer = setTimeout(() => t.classList.remove("on"), 4000);
};
const file = () => pre.textContent;

form.addEventListener("submit", e => e.preventDefault()); // Enter in a field must not put the token in the address bar
form.addEventListener("input", () => render());
form.addEventListener("change", () => render());
form.addEventListener("focusout", e => { if (e.target.name) (touched.add(e.target.name), render()); });
url.addEventListener("input", () => pin(file()));

$("#get").onclick = () => {
  if (!ready) return;
  const link = Object.assign(document.createElement("a"), { download: "kith-install.yaml", href: URL.createObjectURL(new Blob([file()], { type: "text/yaml" })) });
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 4000);
  toast("kith-install.yaml: save it on the stick's first partition.");
};
$("#copy").onclick = async () => {
  if (!ready) return;
  try {
    await navigator.clipboard.writeText(file());
    toast("Copied.");
  } catch {
    getSelection().selectAllChildren(pre); // (a page that may not use the clipboard: it is chosen for Ctrl+C)
    toast("The file is selected: press Ctrl+C.");
  }
};
$("#example").onclick = ({ currentTarget }) => {
  form.reset();
  for (const [name, value] of Object.entries(JSON.parse(currentTarget.dataset.example))) {
    typeof value === "boolean" ? (f(name).checked = value) : (f(name).value = value);
  }
  touched.clear();
  render();
  toast("An example: change what is yours.");
};
$("#reset").onclick = () => {
  form.reset();
  touched.clear();
  render();
  toast("Started over.");
};
render(true);

// The rail fills with the blue line as far as the page has been read; the step you are at is the solid stop.
const rail = $("main"), parts = $$("section.part[id]");
function run() {
  document.documentElement.classList.toggle("scrolled", scrollY > 8);
  rail.style.setProperty("--run", Math.max(0, Math.min(1, (scrollY + innerHeight * 0.55 - rail.offsetTop) / rail.offsetHeight)));
  const here = parts.filter(part => part.getBoundingClientRect().top <= innerHeight * 0.4).pop();
  for (const part of parts) part.classList.toggle("here", part === here);
  for (const a of $$(".bar nav a")) here && a.hash === `#${here.id}` ? a.setAttribute("aria-current", "true") : a.removeAttribute("aria-current");
}
addEventListener("scroll", run, { passive: true });
addEventListener("resize", run);
run();

// A part rises when it is first seen.
const seen = new IntersectionObserver(entries => {
  for (const entry of entries) {
    if (!entry.isIntersecting) continue;
    seen.unobserve(entry.target);
    entry.target.classList.add("seen");
  }
}, { rootMargin: "0px 0px -12% 0px" });
document.documentElement.classList.add("js");
$$("[data-see]").forEach(part => (calm ? part.classList.add("seen") : seen.observe(part)));
