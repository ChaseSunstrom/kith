// What moves on kith's page. Every figure is in the HTML already, or in #measured
// (docs/numbers.json, put there by ci/site_numbers.py): this file only draws them.
const N = JSON.parse(document.getElementById("measured").textContent);
const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;
const $ = (q, el = document) => el.querySelector(q);
const $$ = (q, el = document) => [...el.querySelectorAll(q)];

// Everything that moves can be stopped: the two stories wait, and what is drawn holds still.
let paused = false;
const motion = $("#motion");
motion.hidden = calm;
motion.onclick = () => {
  paused = !paused;
  document.documentElement.classList.toggle("paused", paused);
  motion.setAttribute("aria-pressed", paused);
  motion.textContent = paused ? "Play" : "Pause";
  for (const svg of $$("svg")) paused ? svg.pauseAnimations() : svg.unpauseAnimations();
};
const wait = ms => new Promise(done => setTimeout(done, ms));
const sleep = async ms => {
  await wait(ms);
  while (paused) await wait(200);
};

// A count runs up to its number once; with less motion it is only written with its commas.
function count(el) {
  const to = Number(el.textContent), digits = (el.textContent.split(".")[1] || "").length;
  const said = n => n.toLocaleString("en", { minimumFractionDigits: digits, maximumFractionDigits: digits });
  if (!Number.isFinite(to)) return;
  if (calm) return void (el.textContent = said(to));
  const from = performance.now();
  (function step(now) {
    const part = Math.min(1, (now - from) / 900);
    el.textContent = said(to * (1 - (1 - part) ** 3));
    if (part < 1) requestAnimationFrame(step);
  })(from);
}

// Bars: a value over its budget.
for (const row of $$(".row[data-v]")) row.style.setProperty("--v", Math.min(1, N[row.dataset.v] / N[row.dataset.of]) || 0);

// Beside k3s: drawn only when the comparison's runs are in the numbers.
const versus = [
  ["At rest", [
    ["Memory in use on an idle node: the first node, or the server", "control", "MB"],
    ["Memory in use on an idle node: another node, or an agent", "worker", "MB"],
    ["CPU in use on an idle node: the first node, or the server", "cpu", "% of a CPU"],
    ["CPU in use on an idle node: another node, or an agent", "cpu2", "% of a CPU"],
    ["On the first node's disk at the end", "disk", "MB"],
  ]],
  ["Starting and changing", [
    ["From switching a machine on to a node that is ready", "ready", "s"],
    ["From apply to a ready container, its image on the node", "apply", "s"],
    ["One workload of 30 replicas: until all are ready", "scale", "s"],
    ["20 workloads at once: until all are ready", "burst", "s"],
    ["A change to a workload of 6 replicas: until all 6 run it", "roll", "s"],
    ["A container that exits: until it runs again", "crash", "s"],
    ["A Job that does nothing: until it has succeeded", "job", "s"],
  ]],
  ["When a node is lost", [
    ["Until its replica is ready on another, as each system comes", "lost", "s"],
    ["The same, each told to wait about a minute", "lost60", "s"],
  ]],
  ["Through a Service to 3 web servers", [
    ["Requests a second, a connection each (more is better)", "rps", "a second"],
    ["Requests a second over connections that are kept (more is better)", "kept", "a second"],
    ["Of those requests, half took under", "p50", "ms"],
    ["and 99 in 100 under", "p99", "ms"],
  ]],
].map(([group, rows]) => [group, rows.filter(([, what]) => N[`cmp.kith.${what}`] != null && N[`cmp.k3s.${what}`] != null)]).filter(([, rows]) => rows.length);
if (versus.length) {
  $("#versus-said").textContent = `kith ${N.version} and k3s ${N["cmp.k3s.version"]} as it comes (on Alpine, which alone has ${N["cmp.k3s.before"]} MB in use before k3s starts), three QEMU machines each, the same workloads on both. The middle of ${N["cmp.runs"]} runs (a node lost and told to wait a minute: one run each), on a machine that was doing other work. Each pair has its own scale; a shorter bar is less, which is better in every row but the two that say otherwise.`;
  // Only this file's own words and numbers from #measured go in: nothing a reader typed.
  $("#versus-chart").innerHTML = versus.map(([group, rows]) => `<section><h4>${group}</h4>` + rows.map(([name, what, unit]) => {
    const kith = N[`cmp.kith.${what}`], k3s = N[`cmp.k3s.${what}`], most = Math.max(kith, k3s);
    const bar = (who, n, other) => `<span>${who}</span><div class="track"><i class="${other}" style="--v:${n / most}"></i></div><b>${n.toLocaleString("en")} <small>${unit}</small></b>`;
    return `<div class="vs"><p>${name}</p>${bar("kith", kith, "")}${bar("k3s", k3s, "other")}</div>`;
  }).join("") + "</section>").join("");
  $("#versus").hidden = false;
}

// Where the code is: a bar of lines for each crate, and its tests.
const crates = Object.entries(N.by_crate || {}).sort((a, b) => b[1][0] - a[1][0]);
if (crates.length) {
  $("#where-chart").innerHTML = crates.map(([name, [lines, tests]]) =>
    `<div class="row"><p><code>${name}</code></p><div class="track"><i style="--v:${lines / crates[0][1][0]}"></i></div><b>${lines.toLocaleString("en")} <small>lines, ${tests} tests</small></b></div>`).join("");
  $("#where").hidden = false;
}

// The system calls the filter refuses, each struck out in turn.
if (N["refused.names"]) {
  $("#calls").innerHTML = N["refused.names"].map((name, i) => `<s style="--i:${i}">${name}</s>`).join(" ");
  $("#wall").hidden = false;
}

// The terminal: a command, a pause as it runs, then what it said.
let at = 200;
for (const line of $$("#term .line")) line.style.setProperty("--at", `${(at += line.classList.contains("out") ? 110 : 750)}ms`);

// The rail fills with the blue line as far as the page has been read.
const rail = $("main"), parts = $$(".part[id]");
function run() {
  document.documentElement.classList.toggle("scrolled", scrollY > 8);
  rail.style.setProperty("--run", Math.max(0, Math.min(1, (scrollY + innerHeight * 0.55 - rail.offsetTop) / rail.offsetHeight)));
  // The part you are in: its stop breathes, and the nav says so.
  const here = parts.filter(part => part.getBoundingClientRect().top <= innerHeight * 0.4).pop();
  for (const part of parts) part.classList.toggle("here", part === here);
  for (const a of $$(".bar nav a")) here && a.hash === `#${here.id}` ? a.setAttribute("aria-current", "true") : a.removeAttribute("aria-current");
}
addEventListener("scroll", run, { passive: true });
addEventListener("resize", run);
run();

// A part rises when it is first seen, and its counts run then.
const reveal = part => {
  part.classList.add("seen");
  $$("[data-count]", part).forEach(count);
};
const seen = new IntersectionObserver(entries => {
  for (const entry of entries) {
    if (!entry.isIntersecting) continue;
    seen.unobserve(entry.target);
    reveal(entry.target);
  }
}, { rootMargin: "0px 0px -12% 0px" });
// Only now are the parts hidden until seen: had anything above failed, the page would stand as written.
document.documentElement.classList.add("js");
// Asked for less motion: every part is shown at once, without waiting to be scrolled to.
$$("[data-see]").forEach(part => (calm ? reveal(part) : seen.observe(part)));

// Pulse: gamma leads and is lost; the other two pick alpha; gamma's replica starts on beta; gamma returns.
async function pulse() {
  const panel = $("#pulse"), node = name => $(`[data-node=${name}]`, panel), lamp = $("#moved");
  const show = (state, nodes, replicas, lead, on, lit) => {
    panel.dataset.state = state;
    $("#pulse-said").textContent = `${nodes} of 3 nodes up, ${replicas} of 3 replicas ready`;
    $("#leader").textContent = lead || "none: the other two are choosing";
    $("#web-on").textContent = on;
    lamp.className = `lamp ${lit}`;
    for (const name of ["alpha", "beta", "gamma"]) node(name).classList.toggle("leads", name === lead);
    node("gamma").classList.toggle("gone", state === "lost" && nodes < 3);
  };
  for (;;) {
    show("up", 3, 3, "gamma", "on alpha, beta and gamma", "ok");
    await sleep(4200);
    // (An unreachable node's replica is ready in the count until the node has been gone long enough.)
    show("lost", 2, 3, "", "on alpha, beta and gamma, which is unreachable", "ok");
    await sleep(1700);
    show("lost", 2, 3, "alpha", "on alpha, beta and gamma, which is unreachable", "ok");
    await sleep(2200);
    show("lost", 2, 2, "alpha", "on alpha and beta; gamma's is starting on beta", "wait");
    await sleep(1400);
    show("lost", 2, 3, "alpha", "on alpha, and two on beta", "ok");
    await sleep(3200);
    show("up", 3, 3, "alpha", "on alpha, and two on beta", "ok");
    await sleep(3600);
    panel.classList.add("cut"); // and from the top
    await sleep(400);
    panel.classList.remove("cut");
  }
}

// The disk: an update goes into the other slot; every third one does not come up, and the node goes back.
async function disk() {
  const panel = $("#disk"), slot = name => $(`.slot.${name}`, panel), steps = $$(".steps li", panel);
  const say = (step, text) => {
    $("#disk-said").textContent = text;
    steps.forEach((li, i) => li.classList.toggle("now", i === step));
  };
  let runs = "a";
  for (let round = 1; ; round++) {
    const other = runs === "a" ? "b" : "a", next = slot(other), fails = round % 3 === 0;
    say(-1, `running slot ${runs}`);
    await sleep(2600);
    next.classList.add("writing");
    say(0, `writing the update into slot ${other}`);
    await sleep(2600);
    next.classList.add("trying");
    for (let attempt = 1; attempt <= (fails ? 3 : 1); attempt++) {
      say(1, `restarted into slot ${other}: try ${attempt} of 3`);
      await sleep(1500);
    }
    next.classList.remove("trying", "writing");
    if (fails) {
      next.classList.add("failed");
      say(3, `slot ${other} did not come up in 3 tries: this is slot ${runs}, which ran before it`);
      await sleep(3600);
      next.classList.remove("failed");
    } else {
      slot(runs).classList.remove("runs");
      next.classList.add("runs");
      say(2, `slot ${other} is good`);
      runs = other;
      await sleep(3000);
    }
  }
}

// The map at the top, and a machine lost from it: where each of its replicas starts instead. Each goes to the machine with
// the fewest, among those that have a place free. Nothing is changed here: the caller moves them (or, with less motion, at once).
const label = (map, name) => $(`text[data-node=${name}]`, map).textContent;
const machines = map => new Set($$(".rep.on", map).map(rep => rep.parentNode.dataset.node)).size;
const gone = (map, name, is) => $$(`[data-node=${name}]`, map).forEach(el => el.classList.toggle("gone", is));
const lost = (map, who, total) => `hello: ${$$(".rep.on", map).length} of ${total} replicas ready, on ${machines(map)} machines; ${who} is lost`;
function lose(map, name) {
  const taken = new Set(), moves = [];
  const free = g => $$(".rep", g).find(rep => !rep.classList.contains("on") && !taken.has(rep));
  const used = g => $$(".rep", g).filter(rep => rep.classList.contains("on") || taken.has(rep)).length;
  for (const from of $$(".rep.on", $(`.reps[data-node=${name}]`, map))) {
    const to = $$(".reps", map).filter(g => g.dataset.node !== name && free(g)).sort((a, b) => used(a) - used(b))[0], slot = free(to);
    taken.add(slot);
    moves.push([from, slot, to.dataset.node]);
  }
  return moves;
}

// The map at the top: a change to hello rolls through its replicas. A dot runs the line from the hub to
// a machine, and that machine's replicas each wait while a new one starts, so the count dips by one at a time.
async function live() {
  const map = $("#live .map"), said = $("#live-said"), names = $$(".reps", map).map(g => g.dataset.node), wave = $(".wave", map), ready = () => $$(".rep.on", map).length, total = ready();
  const fly = (line, ms) => new Promise(done => {
    const len = line.getTotalLength();
    let t = 0, last = performance.now();
    wave.style.opacity = 1;
    (function step(now) {
      if (!paused) t += (now - last) / ms;
      last = now;
      const at = line.getPointAtLength(len * Math.min(1, t));
      wave.setAttribute("cx", at.x);
      wave.setAttribute("cy", at.y);
      if (t < 1) return void requestAnimationFrame(step);
      wave.style.opacity = 0;
      done();
    })(last);
  });
  // One machine is lost: its replicas still count as ready for a while, then each starts on another machine.
  let next = names.length - 1;
  const fail = async () => {
    do next = (next + 1) % names.length; while (!$(`.reps[data-node=${names[next]}] .rep.on`, map));
    const name = names[next], who = label(map, name), moves = lose(map, name);
    gone(map, name, true);
    said.textContent = `hello: ${ready()} of ${total} replicas ready; ${who} is unreachable, and its ${moves.length} still count`;
    await sleep(3200);
    moves.forEach(([from]) => from.classList.remove("on"));
    for (const [, slot, to] of moves) {
      said.textContent = `hello: ${ready()} of ${total} replicas ready; ${who}'s replica is starting on ${label(map, to)}`;
      await fly($(`#m-${to}`), 600);
      slot.classList.add("wait");
      await sleep(900);
      slot.classList.replace("wait", "on");
    }
    said.textContent = lost(map, who, total);
    await sleep(4200);
    gone(map, name, false);
    said.textContent = `hello: ${ready()} of ${total} replicas ready; ${who} is back, with nothing on it`;
    await sleep(3000);
  };
  await sleep(2600); // the map draws itself first
  map.classList.add("go");
  await sleep(3000);
  for (let revision = 2; ; revision++) {
    for (const node of $$(".reps", map)) {
      await fly($(`#m-${node.dataset.node}`), 600);
      for (const rep of $$(".rep.on", node)) {
        rep.classList.replace("on", "wait");
        said.textContent = `hello: ${ready()} of ${total} replicas ready, rolling to revision ${revision}`;
        await sleep(700);
        rep.classList.replace("wait", "on");
      }
    }
    said.textContent = `hello: ${ready()} of ${total} replicas ready, revision ${revision}, on ${machines(map)} machines`;
    await sleep(5000);
    await fail();
  }
}

if (!calm) pulse(), disk(), live();
// With less motion the story is not told, only where it ends: the old PC lost, its replicas started on the others.
if (calm) {
  const map = $("#live .map"), total = $$(".rep.on", map).length;
  for (const [from, slot] of lose(map, "old")) from.classList.remove("on"), slot.classList.add("on");
  gone(map, "old", true);
  $("#live-said").textContent = lost(map, label(map, "old"), total);
}
