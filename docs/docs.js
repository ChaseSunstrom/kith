"use strict";
// The guide's pages: the bar's line once you scroll, the heading you are at lit in the rail, and a search over the
// headings (docs/guide/search.json, made by ci/site_docs.py). Without it the pages read the same; only the search is gone.
const $ = (sel, from = document) => from.querySelector(sel);
const $$ = (sel, from = document) => [...from.querySelectorAll(sel)];
const root = document.documentElement.dataset.root || "";

const scrolled = () => document.documentElement.classList.toggle("scrolled", scrollY > 8);

// On a narrow screen the pages start shut, under their summary.
const rail = $(".rail");
// Above that width the summary is hidden, so the pages are always open there.
if (rail) {
  const narrow = matchMedia("(max-width: 960px)");
  const fit = () => { rail.open = !narrow.matches; };
  fit();
  narrow.addEventListener("change", fit);
}

// Spy: the last heading above the top of the window is the one you are in.
const heads = $$(".page :is(h2, h3)[id]");
const inRail = new Map($$(".inner a").map(a => [a.hash.slice(1), a]));
let here = null, queued = false;
function spy() {
  queued = false;
  scrolled();
  let now = null;
  for (const h of heads) if (h.getBoundingClientRect().top <= 140) now = h; else break;
  if (now === here) return;
  here = now;
  for (const a of inRail.values()) a.removeAttribute("aria-current");
  const a = now && inRail.get(now.id);
  if (!a) return;
  a.setAttribute("aria-current", "location");
  const side = $(".side");
  if (side && side.scrollHeight > side.clientHeight) {
    const box = side.getBoundingClientRect(), at = a.getBoundingClientRect();
    if (at.top < box.top + 40 || at.bottom > box.bottom - 40) side.scrollTop += at.top - box.top - box.height / 2;
  }
}
// The reading line: the page's line fills with blue as far as you have read (to 55% down the window), and each h2 passed is blue.
const page = $(".page"), h2s = $$(".page h2"), reading = document.createElement("i");
reading.className = "reading";
reading.setAttribute("aria-hidden", "true");
if (page) page.append(reading);
let lastRun = "";
function readLine() {
  if (!page) return;
  const box = page.getBoundingClientRect(), tops = h2s.map((h) => h.getBoundingClientRect().top); // every rect read before any write
  const run = Math.max(0, Math.min(1, (innerHeight * 0.55 - box.top) / box.height)).toFixed(3);
  if (run !== lastRun) { lastRun = run; reading.style.setProperty("--run", run); }
  h2s.forEach((h, i) => h.classList.toggle("read", tops[i] < innerHeight * 0.55));
}
const frame = () => { queued = false; spy(); readLine(); };
addEventListener("scroll", () => { if (!queued) { queued = true; requestAnimationFrame(frame); } }, { passive: true });
addEventListener("resize", readLine);
readLine();
spy();

// Copy: a button above each block of code writes its text to the clipboard and says Copied for 1.5 s. The trailing
// newline is left off, so a command pasted into a terminal waits for you.
async function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
  const was = document.activeElement, area = document.createElement("textarea"); // a page opened from a file, or over plain http, has no clipboard API
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.cssText = "position:fixed;top:0;left:0;opacity:0";
  document.body.append(area);
  area.select();
  const ok = document.execCommand("copy");
  area.remove();
  if (was && was.focus) was.focus();
  if (!ok) throw new Error("copy refused");
}
const said = document.createElement("p"); // one polite line for a screen reader: the button's own label stays "Copy"
said.className = "sr";
said.setAttribute("role", "status");
document.body.append(said);
for (const pre of $$(".page pre")) {
  pre.tabIndex = 0; // a block that scrolls sideways must be reachable by keyboard
  const wrap = document.createElement("div"), button = document.createElement("button");
  wrap.className = "code";
  button.type = "button";
  button.className = "copy";
  button.textContent = "Copy";
  let timer = 0;
  button.addEventListener("click", async () => {
    let msg = "Copied";
    try { await copyText(pre.textContent.replace(/\n+$/, "")); } catch { msg = "Not copied"; }
    button.textContent = msg;
    said.textContent = msg;
    button.dataset.state = msg === "Copied" ? "done" : "failed";
    clearTimeout(timer);
    timer = setTimeout(() => { button.textContent = "Copy"; said.textContent = ""; delete button.dataset.state; }, 1500);
  });
  pre.replaceWith(wrap);
  wrap.append(button, pre);
}

// Search: every word typed must be in the heading or the page's title.
const form = $(".find"), box = $("#q"), found = $(".found"), side = $(".side");
if (form && box && found) {
  fetch(root + "guide/search.json").then(r => r.ok ? r.json() : Promise.reject()).then(index => {
    form.hidden = false;
    const words = q => q.toLowerCase().split(/\s+/).filter(Boolean);
    const score = (e, ws) => {
      const h = e.h.toLowerCase(), t = e.t.toLowerCase();
      let s = 0;
      for (const w of ws) {
        if (h.includes(w)) s += h.startsWith(w) || h.includes(" " + w) ? 3 : 2;
        else if (t.includes(w)) s += 1;
        else return 0;
      }
      return s - (e.h ? 0 : 0.5);
    };
    const show = () => {
      const ws = words(box.value);
      found.replaceChildren();
      side.classList.toggle("finding", ws.length > 0);
      found.hidden = !ws.length;
      if (!ws.length) return;
      const hits = index.map(e => [score(e, ws), e]).filter(([s]) => s > 0).sort((a, b) => b[0] - a[0]).slice(0, 14);
      if (!hits.length) {
        const none = document.createElement("li");
        none.className = "none";
        none.textContent = "No heading says that.";
        return void found.append(none);
      }
      for (const [, e] of hits) {
        const li = document.createElement("li"), a = document.createElement("a"), b = document.createElement("b"), s = document.createElement("span");
        a.href = root + e.u;
        b.textContent = e.h || e.t;
        s.textContent = e.h ? e.t : "page";
        a.append(b, s);
        li.append(a);
        found.append(li);
      }
    };
    box.addEventListener("input", show);
    form.addEventListener("submit", ev => ev.preventDefault()); // Enter opens the first hit (below); the form never goes anywhere
    const lit = link => { $$("li", found).forEach(li => li.classList.toggle("on", li.contains(link))); };
    found.addEventListener("focusin", ev => lit(ev.target.closest("a")));
    box.addEventListener("keydown", ev => {
      const links = $$("a", found), at = links.indexOf(document.activeElement);
      if (ev.key === "Escape") { box.value = ""; show(); }
      else if (ev.key === "ArrowDown" && links.length) { ev.preventDefault(); links[Math.min(links.length - 1, at + 1)].focus(); }
      else if (ev.key === "Enter" && links.length) links[0].click();
    });
    found.addEventListener("keydown", ev => {
      const links = $$("a", found), at = links.indexOf(document.activeElement);
      if (ev.key === "ArrowDown") { ev.preventDefault(); links[Math.min(links.length - 1, at + 1)].focus(); }
      else if (ev.key === "ArrowUp") { ev.preventDefault(); (at > 0 ? links[at - 1] : box).focus(); }
      else if (ev.key === "Escape") box.focus();
    });
    addEventListener("keydown", ev => {
      if (ev.key === "/" && !ev.metaKey && !ev.ctrlKey && !/^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName)) { ev.preventDefault(); box.focus(); }
    });
  }).catch(() => {});
}
