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
The brand (PLAN.md §11) leads: ink `#16181d`, paper `#f6f5f1`, accent `#5b8cff`,
and the mark, a "k" drawn as a hub with nodes. Audacity bold.
Runner-up: Instrument (a mono, mint-on-black mixing desk), built first and rejected by the user as dated and green.
Taste words: modern, animated → modern owns type, colour and shape; animated gets motion and the mark.

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
