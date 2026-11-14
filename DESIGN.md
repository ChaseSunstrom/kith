# kith web UI: design

The UI kithd serves at `/ui/` (`crates/kithd/ui/`). It should feel like the
cluster's own front panel: the kith mark come alive, for the person who runs
the cluster and wants to see what is running and change one thing. It must
never be mistaken for a terminal theme or a generic admin template.

## Interview
1. Who and when: the cluster's operator, a minute after `kith apply` or an alert (assumed)
2. Feels like: the logo's little network, lit and moving, above a clean desk (user: "more modern and animated … with the logo", "not dark green")
3. Never: a green-on-black console; a wizard (user, and assumed)

## Direction
**Line map.** kith's mark is a small network map (a hub, four stops, three lines), and
everything kith shows is drawn the way the mark is: in ink on paper, with one blue line
for what is live. Ink `#16181d`, paper `#f6f5f1`, and the blue (PLAN.md §11) stay.
Structure is made of lines and stops, not of boxes: a 3 px stroke with a ring where
something is, a filled blue ring where it is live, a dashed red ring where it is gone.
Corners are square; nothing glows, nothing casts a shadow, nothing is a gradient.
The face is Overpass (after the lettering of road signs; SIL OFL, served from the page's
own host), 800 for what you are going to and 400 for the rest.
Runner-ups, both built and both rejected by the user: Instrument (a mono, mint-on-black
mixing desk: "dated", "dark green"), and Front panel (Inter on navy with rounded
bordered panels, pills and a glow: "very generic AI"). The website wears Line map; the
web UI still wears Front panel, which the sections below describe, until it is redrawn.

## Knobs
- Type: a sans for the interface (Inter where the machine has it, as the wordmark uses; else the system's), a monospace only for what is code: YAML, diffs, logs, table values. Base 14 px; sizes 11 / 12 / 14 / 20; weights 400 and 600. System stacks because the page may load nothing from outside the cluster (CSP, air-gapped nodes).
- Colour: dark is ink with paper text; light is paper with ink text (`prefers-color-scheme`). `--accent` is the brand blue: live, ready, selected, the one primary action, added diff lines. `--warn` (amber) is waiting; `--bad` (red) is errors, deletions, removed diff lines. No green anywhere. `--glow` is the accent at low alpha: selection, focus rings, the one light at the top left.
- Density: unit 4 px; table rows 34 px; panel padding 16 px.
- Shape: panels radius 10, controls 6, pills for counts and tags; 1 px `--line` borders; shadows only on what floats (dialog, toasts).
- Motion: hover and focus 140 ms; panels rise in once at load (360 ms, staggered); a tab's underline grows; a pane's content arrives (220 ms); the dialog opens with a short lift; toasts slide in; a changed row flashes once. Continuous motion is kept to what is live: the mark's hub and the link light send out a ring, packets run the mesh in Pulse, ready replicas breathe, waiting ones blink. Under `prefers-reduced-motion` all of it is still and the packets are not drawn: states are told by colour and shape alone.
- Focus: a 2 px accent outline, or an accent border with a glow ring on text controls.

## Signature moves
1. The mark, alive: it draws itself at load and its hub keeps a pulse; the same hub-and-nodes figure is the Pulse panel, with the cluster's real nodes and packets running between them.
2. Replica lamps: every running thing's replicas as a row of pills that breathe (ready), blink (waiting) or stay red (failed), from the same watch the tables use.

## States
- Empty: one dim line in the panel saying what would be here and how to make one.
- Loading: the link light blinks amber; panels keep their last data.
- Error: a red line where the action was, in the server's own words.
- Done: a toast bottom right, gone in 4 s; the changed row flashes.

## Banned
- Green as a state colour; a monospace interface; emoji or icon fonts; modal wizards; blurred gradient blobs.
- Defaults to avoid 1, 3, 5, 7, 12.

## Allowed exceptions
- Default 2 (a system typeface): Inter is the brand's, but nothing may be fetched; the stack names it first and falls back to the system's sans.

## The website (`docs/`, GitHub Pages)

One page about kith for someone who has not run it yet, in Line map. Nothing on it comes
from another host (the typeface is in `docs/fonts/`).

- The rail: the stem of the k in the bar goes on down the left of the page as a 3 px line, and each part of the page is a stop on it. The line turns blue as far as the page has been read.
- Paper first: light is paper with ink, dark is ink with paper (`prefers-color-scheme`); tokens in `docs/site.css`. Sizes 13 / 15 / 17 / 21 / 28 / 48, the title up to 100 px; a column of at most 1120 px; 128 px between parts.
- Figures hang from a 3 px rule with their name under it. Code sits in a flat sunken block. Replicas are stops on a short line. A measure is a line run out to a ring, and its budget is the tick where the line would end. The kinds are nine lines with a stop for each kind.
- Numbers: every figure is measured by `ci/site_numbers.py` into `docs/numbers.json` and written into the page by it (`data-n`); the charts are drawn from the same file. A figure nobody measured is not on the page.
- Motion: what is in a part rises once when it is first seen; lines run out to their value, stops pop in, counts run up once. Three things keep moving because they show something that does: the mark with what runs along its lines, a cluster that loses its leader and recovers, and a node that updates into its other slot. Under `prefers-reduced-motion` everything is in its final state and nothing loops.
- States: without JavaScript the page is whole (the numbers are in the HTML); the comparison with k3s is shown only when `docs/numbers.json` has its runs.
- Banned here: rounded panels, pills, glows, gradients, shadows, a phrase of the title tinted in the accent, Inter.
