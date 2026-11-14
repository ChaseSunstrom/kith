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
bordered panels, pills and a glow: "very generic AI"). The website and the web UI both
wear Line map.

## Knobs
- Type: Overpass for the interface, served by kithd itself (31 KB, a Latin subset, in the binary: the page may load nothing from outside the cluster; CSP `font-src 'self'`), then the system's sans. A monospace only for what is code: YAML, diffs, logs, table values, what a description puts in backticks. Sizes 13 / 15 / 21; weights 400, 700 and 800 (the heavy one for what you are in: a part's title, the open kind, the open row).
- Colour: paper with ink text first; dark is ink with paper text (`prefers-color-scheme`). `--accent` is the brand blue: live, ready, selected, the one primary action, added diff lines. `--warn` (amber) is waiting; `--bad` (red) is errors, deletions, removed diff lines. No green anywhere. `--sunken` is the paper a shade down: fields, code, a row under the pointer. `--hair` is the hairline between rows.
- Density: unit 4 px; table rows 36 px; parts 28 px apart, columns 36 px.
- Shape: square. A part hangs from a 3 px ink rule and has no box. A field is a sunken strip on a 1 px ink line; a button is a 3 px ink frame that fills with ink under the pointer, and the one that acts is the blue. A stop is a 14 px ring with a 3 px stroke: ink when something is there, filled blue when live or chosen, amber when waiting, a broken red ring when gone. No radius but a stop's, no shadow, no gradient, no glow, no pill.
- Motion: hover and focus 140 ms; parts rise in once at load (360 ms, 60 ms apart); a tab's blue line grows from the left; a pane's content arrives (220 ms); the dialog opens with a short lift; toasts slide in; a changed row flashes once. Continuous motion is kept to what is live: the mark's hub sends out a ring, packets run the lines in Pulse, ready replicas and the link's stop beat, waiting ones blink. Under `prefers-reduced-motion` all of it is still and the packets are not drawn: states are told by colour and shape alone.
- Focus: a 2 px accent outline; a text field's ink line turns blue and thickens.

## Signature moves
1. The rail: the mark's stem goes on down the page as the line the kinds are stops on. A ring where the cluster has some of that kind, a tick where it has none, the blue stop where you are.
2. Pulse as a line map: the hub, one trunk out of it and a 45° branch to every node's stop, with packets on the lines; under each thing that runs, a short line with a stop for every replica. From the same watch the tables use.
3. Branches: an open group of fields hangs from an ink line at its left, and a group inside it from another; the changed lines of a diff carry a blue or a red line the same way.

## States
- Empty: one dim line in the part saying what would be here and how to make one.
- Loading: the link's stop blinks amber; parts keep their last data.
- Error: a red line where the action was, in the server's own words; a field in error has a red line under it.
- Done: a toast in ink at the bottom right, gone in 4 s; the changed row flashes.

## Banned
- Green as a state colour; a monospace interface; emoji or icon fonts; modal wizards.
- Rounded bordered panels, pills, glows, gradients, shadows, upper-case letter-spaced labels, Inter: what made Front panel read as a template.
- Defaults to avoid 1, 3, 5, 7, 12.

## Allowed exceptions
- None: the face is the page's own now.

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
