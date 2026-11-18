// kith beside k3s, drawn: a bar pair for each comparison row, and the same numbers as a table. Used by the front
// page (#versus) and by the guide's numbers page. Every figure is read from #measured (docs/numbers.json, put
// there by ci/site_numbers.py); the words here are this file's own, and nothing a reader typed goes in.
(() => {
  const host = document.getElementById("versus-chart"), data = document.getElementById("measured");
  if (!host || !data) return;
  const N = JSON.parse(data.textContent);
  const $ = q => document.querySelector(q);
  // One group for each unit: a row's two bars are on one scale, and rows in other units never share one.
  const groups = [
    ["Memory in use", "MB", [
      ["On an idle node: the first node, or the server", "control"],
      ["On an idle node: another node, or an agent", "worker"],
      ["What each replica of 30 adds", "each"],
    ]],
    ["CPU in use on an idle node", "% of a CPU", [
      ["The first node, or the server", "cpu"],
      ["Another node, or an agent", "cpu2"],
    ]],
    ["On the first node's disk at the end", "MB", [["Written to it", "disk"]]],
    ["Starting, changing and losing a node", "s", [
      ["From switching a machine on to a node that is ready", "ready"],
      ["From apply to a ready container, its image on the node", "apply"],
      ["One workload of 30 replicas: until all are ready", "scale"],
      ["20 workloads at once: until all are ready", "burst"],
      ["A change to a workload of 6 replicas: until all 6 run it", "roll"],
      ["A container that exits: until it runs again", "crash"],
      ["A Job that does nothing: until it has succeeded", "job"],
      ["A node lost: until its replica is ready on another, as each system comes", "lost"],
      ["The same, each told to wait about a minute", "lost60"],
    ]],
    ["Requests through a Service to 3 web servers (more is better)", "a second", [
      ["A connection each", "rps"],
      ["Over connections that are kept", "kept"],
    ]],
    ["How long those requests took", "ms", [
      ["Half took under", "p50"],
      ["99 in 100 under", "p99"],
    ]],
  ].map(([title, unit, rows]) => [title, unit, rows.filter(([, key]) => N[`cmp.kith.${key}`] != null && N[`cmp.k3s.${key}`] != null)]).filter(([, , rows]) => rows.length);
  if (!groups.length) return; // no comparison run in the numbers: nothing is drawn, and the section stays shut
  const say = n => n.toLocaleString("en");
  const at = (who, key) => N[`cmp.${who}.${key}`];

  $("#versus-said").textContent = `kith ${N.version} and k3s ${N["cmp.k3s.version"]} as it comes (on Alpine, which alone has ${N["cmp.k3s.before"]} MB in use before k3s starts), three QEMU machines each, the same workloads on both. The middle of ${N["cmp.runs"]} runs (a node lost and told to wait a minute: one run each), on a machine that was doing other work. Each pair of bars is on one scale, and each group has its own unit; a shorter bar is less, which is better in every row but the two that say otherwise.`;

  const lane = (who, n, most, other) => `<span>${who}</span><div class="lane ${other}"><div class="track" aria-hidden="true"><i class="${other}" style="--v:${n / most}"></i></div><b style="--v:${n / most}">${say(n)}</b></div>`;
  host.innerHTML = groups.map(([title, unit, rows]) => `<section><h4>${title} <small>(${unit})</small></h4>` + rows.map(([name, key]) => {
    const kith = at("kith", key), k3s = at("k3s", key), most = Math.max(kith, k3s) || 1;
    return `<div class="vs" role="img" aria-label="${name}: kith ${say(kith)} ${unit}, k3s ${say(k3s)} ${unit}"><p>${name}</p>${lane("kith", kith, most, "")}${lane("k3s", k3s, most, "other")}</div>`;
  }).join("") + "</section>").join("");

  // The key, above the bars; and the same numbers as a table, under them.
  host.insertAdjacentHTML("beforebegin", `<p class="legend" aria-hidden="true"><span><i></i>kith</span><span class="other"><i></i>k3s</span></p>`);
  host.insertAdjacentHTML("afterend", `<details class="vs-table"><summary>The same numbers as a table</summary><div class="scroll"><table><thead><tr><th scope="col">Row</th><th scope="col">Unit</th><th scope="col">kith</th><th scope="col">k3s</th></tr></thead><tbody>` +
    groups.map(([title, unit, rows]) => `<tr><th scope="rowgroup" colspan="4">${title}</th></tr>` + rows.map(([name, key]) => `<tr><th scope="row">${name}</th><td>${unit}</td><td>${say(at("kith", key))}</td><td>${say(at("k3s", key))}</td></tr>`).join("")).join("") + `</tbody></table></div></details>`);

  const part = $("#versus");
  part.hidden = false;
  document.documentElement.classList.add("js");
  // The front page's part is revealed by its own script (site.js); elsewhere the bars run when they come into view.
  if (part.closest("[data-see]")) return;
  if (matchMedia("(prefers-reduced-motion: reduce)").matches || !("IntersectionObserver" in window)) return void part.classList.add("seen");
  const seen = new IntersectionObserver(entries => {
    if (entries.some(e => e.isIntersecting)) {
      seen.disconnect();
      part.classList.add("seen");
    }
  }, { rootMargin: "0px 0px -12% 0px" });
  seen.observe(part);
})();
