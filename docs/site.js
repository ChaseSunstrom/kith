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
  ["Memory in use on an idle node: the first node, or the server", "control", "MB"],
  ["Memory in use on an idle node: another node, or an agent", "worker", "MB"],
  ["From apply to a ready container, its image on the node", "apply", "s"],
  ["A node lost: until its replica is ready on another, as each system comes", "lost", "s"],
  ["The same, each told to wait about a minute", "lost60", "s"],
].filter(([, what]) => N[`cmp.kith.${what}`] != null && N[`cmp.k3s.${what}`] != null);
if (versus.length) {
  $("#versus-said").textContent = `kith ${N.version} and k3s ${N["cmp.k3s.version"]} (on Alpine), three QEMU machines each. The middle of ${N["cmp.runs"]} runs; shorter is less.`;
  // Only this file's own words and numbers from #measured go in: nothing a reader typed.
  $("#versus-chart").innerHTML = versus.map(([name, what, unit]) => {
    const kith = N[`cmp.kith.${what}`], k3s = N[`cmp.k3s.${what}`], most = Math.max(kith, k3s);
    const bar = (who, n, other) => `<span>${who}</span><div class="track"><i class="${other}" style="--v:${n / most}"></i></div><b>${n} <small>${unit}</small></b>`;
    return `<div class="vs"><p>${name}</p>${bar("kith", kith, "")}${bar("k3s", k3s, "other")}</div>`;
  }).join("");
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
const rail = $("main");
function run() {
  document.documentElement.classList.toggle("scrolled", scrollY > 8);
  rail.style.setProperty("--run", Math.max(0, Math.min(1, (scrollY + innerHeight * 0.55 - rail.offsetTop) / rail.offsetHeight)));
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

if (!calm) pulse(), disk();
