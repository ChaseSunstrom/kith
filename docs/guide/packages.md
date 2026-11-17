# Packages and Sources

## Packages

A package is a directory of resource templates with default values
([`packages/web`](../../packages/web) is one):

```text
package.yaml          name, version, description, kithVersion, dependencies
values.yaml           the default values
values.schema.json    what values may be (optional)
templates/*.yaml      resources, as templates; files named _something are only included
NOTES                 what to tell whoever installed it (optional; a template too)
```

```sh
kith package lint packages/web
kith package render packages/web --name shop -n store --set replicas=3 -f mine.yaml
kith package render packages/web --name shop | kith apply -f -
```

- Templates are Jinja ([minijinja](https://docs.rs/minijinja)). They see
  `values` (the defaults, with each `-f` file and then each `--set` on top,
  merged key by key), `release.name`, `release.namespace`, `package.name`,
  `package.version`, `name` (a name for the release's resources:
  `shop-web`) and `labels`. `{{ value | toYaml | indent(4) }}` writes a value
  as YAML, `{{ value | tojson }}` quotes one that could be anything, and
  `required(value, "why")` stops with `why` when there is none. Using a value
  that is not there is an error, and so is a template that never ends or
  writes more than 1 MB. A template reads nothing but its package (links in
  the package's directory are not followed), and `namespace()` is not there.
- What comes out is checked like any resource (an error shows the rendered
  text's line), put in the release's namespace unless it names one, and
  labelled `kith.dev/release` and `kith.dev/package`.
- Values are checked against `values.schema.json`, of which kith knows
  `type`, `properties`, `required`, `additionalProperties`, `items`, `enum`
  and the `minimum`/`maximum` family; `lint` says so about any other keyword.

### Releases

A cluster installs a package itself: push the package, apply a `Release`.

```sh
kith package push packages/web      # the package, as Package/web-0.1.0 in the store
kith apply -f release.yaml
kith get release/shop -n store -o yaml   # status: state, version, resources, notes
```

```yaml
apiVersion: kith.dev/v1
kind: Release
metadata: { name: shop, namespace: store }
spec:
  package: { name: web, version: 0.1.0 }   # no version: the newest pushed
  values: { replicas: 3 }
```

- The node that leads the store renders the package and applies what comes
  out; a change to the Release, to the package or to shared values is rendered
  and applied again, and what is no longer rendered is deleted. Deleting the
  Release deletes what it installed. `kith rollback release/shop --to N`
  goes back to an earlier Release, and so to what that installed.
- Values, later over earlier: the package's defaults, the key `values` (YAML)
  of the ConfigMap `kith-system/kith-values`, the same in the Release's
  namespace, the Release's `spec.values`.
- What a release installed is annotated `kith.dev/owned-by` with the Release's
  key and listed in the Release's status; only what is both is deleted when
  it is no longer rendered, and everything so annotated goes when the Release
  does (so `kith apply` refuses a resource annotated as a Release's when
  there is no such Release). A release does not take over a resource that is
  there already and not its own, stays in its own namespace, and makes
  nothing that is in no namespace (a Node, a Package), no Release or Source,
  and no `kith-values` ConfigMap; any of these (or a template that fails) is
  `state: error` with the reason in `message`, and what was installed before
  stays as it was.
- A Release acts with the rights of whoever applied it (or rolled it back),
  which kithd writes down on it as `kith.dev/written-by`; what a client says
  there is not taken. Each time it renders, every resource is asked for as if
  that writer applied it, and so is what it reaches (a Backup's Volume and
  Secret, a Share's Volume, a CronJob's Jobs), and the deletion of each one no
  longer rendered. One refusal and nothing is applied: `state: error`, with a
  message such as `Secret/store/db: Release/store/shop was applied by alice,
  and alice may not apply Secret in namespace store: no Role bound to it
  allows that`. A writer who loses a right, or whose Identity is deleted,
  stops the next render, not what is installed. A Release (and a Source) acts
  as the Identity that applied it only while that Identity has the key it had
  then: kithd writes the print of the key down beside the name
  (`kith.dev/written-key`). After a new certificate for the Identity, or an
  Identity made again under the same name, it makes nothing new and says to
  apply it again; so does a Release from before kithd wrote this down.
- `version` is one version (`1.2.0`) or a range (`^1.2`, `>=1, <3`); none is
  any version that is not a pre-release. A Release goes on the newest
  package that fits and stays on it; with `autoUpgrade: true` it follows
  newer ones as they come. Pushing a version again replaces it.

### Repositories

Packages travel as OCI artifacts in any registry, signed:

```sh
kith package keygen signing.key        # the secret into the file; prints the public key
kith package push packages/web --to oci://registry.example/packages --key signing.key
kith package pull oci://registry.example/packages web 0.1.0 --public-key 3f9c…
```

```yaml
apiVersion: kith.dev/v1
kind: Repository
metadata: { name: ours }
spec: { url: oci://registry.example/packages, publicKey: 3f9c… }
---
apiVersion: kith.dev/v1
kind: Release
metadata: { name: shop }
spec:
  package: { repo: ours, name: web, version: ^0.1 }
  autoUpgrade: true
```

- The package `web` is the repository `packages/web` there, each version a
  tag. The artifact is one blob (the package's files) and a signature
  (Ed25519, over the package's name, version and the blob's SHA-256) as the
  annotation `dev.kith.signature`.
- For a Release that names a Repository (applied by someone who may `apply`
  Packages: without that right nothing is fetched, and the Release's status
  says so), the node that leads the store asks the registry for the versions, fetches the newest that fits, checks it
  against the Repository's `publicKey` and stores it as a Package (annotated
  `kith.dev/repository`); the Release installs only Packages from its
  Repository. A package that is unsigned or signed with another key is
  refused, and the Repository's status says so (`state: error`, `message`).
  A newer version that does not check out is passed over for the newest
  that does (the status says which). A Repository without a `publicKey`
  takes packages as they come: they are trusted on the word of whoever answers
  at its `url`. Change a Repository's `url` or `publicKey`
  and what was fetched before is no longer taken for its: it is fetched and
  checked again.
- A Package keeps its last 3 revisions (other kinds keep 100), because it
  carries its files; push a new version rather than rolling far back.
- A Release renders a Package pushed by hand with no more than its pusher's
  rights, besides its own writer's: what the Package makes, and what it no longer
  makes, is asked of whoever pushed it, as of whoever applied the Release. Where
  the pusher may not, nothing new is made, what was installed stays, and the
  Release's status says whose right fell short. A Package pushed before kithd
  wrote the pusher down renders nothing new until it is pushed again. One fetched
  from a Repository has no pusher, and this check does not apply to it: it is
  trusted by the Repository's key (with none, on the word of whoever answers at its
  `url`), so whoever may apply a Repository gives the rights of every Release that
  names it. Only kithd's fetcher says a Package was fetched (`kith.dev/repository`):
  an apply or a Source's file that carries it is refused, and a Release takes it as
  fetched only from the Repository it names.
- A version is fetched once: pushing it to the registry again changes
  nothing here. A registry can also keep quiet about newer versions; the
  signature says a package is the publisher's, not that it is the newest.
- Registries are asked when a Release wants something new and every
  `--repository-poll` seconds (300) for Releases with `autoUpgrade`.
- `kith` reaches a registry through kithd (push and pull need a running
  kithd). No registry logins yet; plain HTTP only to a registry on the same
  machine.

Not yet: `dependencies` are read and nothing more; no hooks, no looking up
what is in the cluster from a template, no registry credentials.

### A desktop is a package

kith has no desktop of its own, and a node nobody gives one stays headless.
Four example packages show the shape ([`packages/hyprland`](../../packages/hyprland),
[`packages/gnome`](../../packages/gnome), [`packages/kiosk`](../../packages/kiosk),
[`packages/kith-panel`](../../packages/kith-panel)):

```sh
kith get seat                       # office-pc-seat0
kith get seat office-pc-seat0 -o yaml > seat.yaml   # add under metadata.labels: kith.dev/namespaces: desktop
kith apply -f seat.yaml             # the seat is given to the namespace desktop
kith package render packages/hyprland --name office -n desktop \
  --set seat=office-pc-seat0 --set image=registry.example/me/hyprland:1 | kith apply -f -
```

- The seat must name the namespace the session is in (`desktop` above) in its
  `kith.dev/namespaces` label, or the session's claim is refused and its `status.message`
  says so: a seat nobody labelled is `kith-system`'s alone ([Who may claim
  what](hardware.md#claiming-hardware)).

- Each session package renders a `DeviceClaim` for the seat (exclusive) and a
  `Workload` of one replica that holds it; see [Hardware](hardware.md#hardware) for what
  a seat is. `reserve` is the container's CPUs and memory.
- kith ships no desktop images: `image` names one you built or trust. The
  session's container is told `KITH_SEAT`, `KITH_USER`, and (Hyprland, GNOME)
  `KITH_APPS` and `KITH_DOTFILES`; the kiosk runs `command`. It runs as the image's
  `User`, like any container ([What a container is kept from](workloads.md#what-a-container-is-kept-from)):
  give the image the user the session is to be, since it is not started as root to become
  one. The seat's device nodes are that user's (on kith OS).
- `kith-panel` is a `Workload` for a panel image that is a window of a seat's session:
  it holds a claim on `seat` with `access: client`
  ([an app as a workload of its own](hardware.md#hardware)), so it runs on the seat's node, is told
  `KITH_SEAT`, and finds the session's Wayland socket at `display`.
- The session packages set `XDG_RUNTIME_DIR=/run/seat`, the seat's own directory: the
  sockets a compositor and PipeWire make there are what a seat's apps connect to.
- Delete the release and the node is headless again.

## Sources (GitOps)

A `Source` keeps what is in a git repository (or an OCI artifact) applied:

```yaml
apiVersion: kith.dev/v1
kind: Source
metadata: { name: cluster, namespace: kith-system }
spec:
  git: { url: https://example.org/ops/cluster.git, rev: main }
  path: clusters/home        # the YAML and JSON files under it
  intervalSeconds: 60
  prune: true                # delete what the source no longer has
  approval: manual           # hold each new revision until approved [auto]
```

```sh
kith get source/cluster -n kith-system -o yaml   # status: state, revision, pending, drift
kith source approve cluster -n kith-system       # apply the revision that waits
kith source push conf --to oci://registry.example/sources/conf:v1   # for `spec.oci`
```

- The node that leads the store fetches the source every `intervalSeconds`
  (5 at least) and applies its resources, marked `kith.dev/owned-by` like a
  Release's. A resource that names no namespace goes in the Source's. A
  Source applies only into its own namespace; one in `kith-system` applies
  anywhere and any kind. Either way it applies only what whoever applied it
  may apply, as a Release does (above): so its repository's authors can make
  whatever that writer can, and no more. A Release or a Source it makes acts
  with the same writer's rights. It does not take over what
  is there and not its own; of two Sources that name one resource the one
  that has it keeps it (the first by name, if they come together) and the
  other says `error`. Sources are fetched several at
  once, and one that keeps failing is fetched less and less often (its
  interval doubled each time, to an hour).
- `status.state` is `synced` (at `revision`), `pending` (`pending.revision`
  waits for `kith source approve`, with what it would change) or `error`
  (with `message`; what was applied stays). When the source moves on, a
  manual Source waits again.
- What a Source applied and someone changed since is put back, and listed in
  `status.drift`: the source is what is true. Deleting a Source deletes what
  it applied.
- git is the node's `git` program (it must be installed), over `https://`
  or `ssh://` only, with no credentials but what ssh has; nothing is checked
  out, so links in a repository are skipped (`status.skipped`), and a
  source is 2000 files and 4 MB at most. git is run by `sh` (under `ulimit -f`)
  and writes no file over 256 MB; a repository that takes more is dropped.
- Only a Source in `kith-system` is fetched over `ssh://` (it is the node's
  own keys that open the door) or from this node and its own networks
  (loopback, private, link-local and shared addresses, by whatever name;
  any address one of this machine's cards has or a Node of the cluster
  advertises too).
  Any other Source is fetched from the very address that was checked: a name
  that answers differently a moment later, or a redirect, leads nowhere else
  (git follows none and needs to be 2.37 or newer; a registry's redirects
  and token host are each checked the same way).
- An approval is for a revision: a Source whose `path` or `prune` you change
  applies the revision already approved the new way.

Not yet: signed-commit verification, credentials for private repositories.
