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

- `kithVersion` is a semver range in Cargo's syntax (`>=1.2`, `>=1, <3`, `^1.2`; not npm's `||`) of the kith versions the package supports. A Release
  of a package the running kithd does not fit is in state `error`, saying both versions, and
  installs nothing; with none, any kithd will do. `kith package push` and `render` warn when
  the `kith` itself does not fit, and go on.
- Templates are Jinja ([minijinja](https://docs.rs/minijinja)). They see `values` (the defaults,
  then each `-f` file, then each `--set`, merged by key), `release.name`, `release.namespace`,
  `package.name`, `package.version`, `name` (the release's resource name: `shop-web`) and
  `labels`. `toYaml` and `tojson` write a value (`{{ v | toYaml | indent(4) }}`); `required(v,
  "why")` stops with `why` when there is none. `lookup(kind, namespace, name)` is the spec of a
  live resource, `{}` when there is none (`(lookup('Secret', release.namespace, 'db').data |
  default({})).password`): only in the release's own namespace, and only of kinds whoever applied
  the Release may `get` and, for a package pushed here rather than fetched from the Release's
  Repository, its pusher may `get` too (the template is the pusher's: it reads no more than they
  may, as its output makes no more); with `kith package render` nothing is live. The Release is
  rendered again when a resource it looked up, a Role or binding, or the Identity of its writer
  or pusher changes; a namespace over 1 MB of specs fails the lookup. A missing value, a template that never ends or writes over 1 MB is an error. A template reads only its package; `namespace()` is not there.
- Output is checked like any resource (an error shows the rendered line), put in the release's
  namespace unless it names one, and labelled `kith.dev/release` and `kith.dev/package`.
- `values.schema.json` may use `type`, `properties`, `required`, `additionalProperties`, `items`,
  `enum` and the `minimum`/`maximum` family; `lint` says so about any other keyword.

### Releases

A cluster installs a package itself: push the package, apply a `Release`.

```sh
kith package push packages/web      # the package, as Package/web-0.1.0 in the store
kith apply -f release.yaml
kith get release/shop -n store -o yaml   # status: state, version, resources, notes, pending, history, pinned
```

```yaml
apiVersion: kith.dev/v1
kind: Release
metadata: { name: shop, namespace: store }
spec:
  package: { name: web, version: 0.1.0 }   # no version: the newest pushed
  values: { replicas: 3 }
```

| | |
|---|---|
| Rendering | The node that leads the store renders and applies again on a change to the Release, the package or shared values, and deletes what is no longer rendered (all of it, with the Release). `kith rollback release/shop --to N` goes back to an earlier Release, with the package version it had then (see `status.pinned`). An edit of an `autoUpgrade: true` Release back to an earlier spec (a rollback by hand, or `autoUpgrade` off and on again, or `replicas` 2, 3, 2) pins it the same way; to follow the newest again, change any field. |
| Values | Later over earlier: the package's defaults, the key `values` (YAML) of the ConfigMap `kith-system/kith-values`, the same in the Release's namespace, the Release's `spec.values`. |
| `version` | One version (`1.2.0`) or a range (`^1.2`, `>=1, <3`); none is any version that is not a pre-release. A Release stays on the newest package that fits; `autoUpgrade: true` follows newer ones, unless its spec is again an earlier revision's (a rollback, or an edit back to how it was, the toggle off and on again too): then it is pinned to the version it had, and a change to any field makes it follow again (see `status.pinned`). Pushing a version again replaces it. |
| `status.pending` | What moving a Release that stays on its version to the newest package that fits would do: `{version, apply: [keys new or changed], delete: [keys no longer rendered]}`, or `{version, error}` when that version does not render; null when it follows or is current, so a Release held by `status.pinned` has no preview. It is the difference of the two renders, so a hand edit does not change it. Each Release that stays on its version (`autoUpgrade` not true) with a newer fitting package costs one extra render. |
| `status.history` | The versions installed, `{version, revision, at}` (the Release's revision, unix seconds), newest last, the last ten; a spec edit at the same version adds none, a move back to an older one adds one. A Release installed before this version gets its first entry when kithd is upgraded, so its `at` is that time. |
| `status.pinned` | True when a Release with `autoUpgrade: true` has a spec equal to an earlier revision's (a `kith rollback`, or an edit back to how it was; a change to labels or annotations alone is not one). It then holds the version `status.history` has for that revision, and a newer package does not move it; what a later version rendered is no longer rendered and goes. If that package is gone, `state: error` says there is no Package NAME VERSION and nothing is deleted. A spec that equals no earlier revision follows the newest again, so to follow after a rollback, change the spec (a value, say). Only the last ten installs are remembered: a rollback to a revision older than that holds nothing (one that is made keeps its version). A Release that does not follow keeps its version as before, and is never pinned. |
| Hooks | A Job a package renders with the annotation `kith.dev/hook` set to `pre-install`, `post-install`, `pre-upgrade` or `post-upgrade` is a hook: not one of the Release's resources (it is not listed in `status.resources`), but made at its point, and the Release waits for it to succeed (`state: hooks`, `message: waiting for Job/ns/name`). A pre hook is made alone, before the rest of the package; a post hook once the rest is there. An install is a Release with nothing installed yet; an upgrade is a move to another version. A hook that fails is `state: error` naming its Job and saying what the Job said, and a pre hook that fails leaves everything else as it was; delete the Job to run it again. A hook is not run again while the version and its rendered spec are as it ran for; a new version or a changed spec runs it again, the old Job deleted first, and so does a hook Job deleted by hand. A hook Job a version's render does not name is deleted when the Release is at that version, so coming back to the version that had it runs it again. A hook Job otherwise stays until the Release is deleted (no weights, no delete policies), including those of a point not asked this time. A pre hook is asked only while the version is changing: one changed at the version already installed does not run until the next version. A hook that sets no `timeoutSeconds` can be waited for forever: set one. Delete hooks are not built. |
| What it owns | What a release installed is annotated `kith.dev/owned-by` with the Release's key and listed in its status; only what is both is deleted when no longer rendered (`kith apply` refuses a resource annotated as a Release's when there is no such Release). |
| What it refuses | To take over what is there and not its own, to leave its namespace, to make a Node, Package, Release, Source or `kith-values` ConfigMap. This, or a failing template, is `state: error` with the reason in `message`; what was installed stays. |
| Whose rights | A Release acts with the rights of whoever applied it (or rolled it back), which kithd writes down as `kith.dev/written-by`; what a client says there is not taken. Each render asks for every resource, what it reaches (a Backup's Volume and Secret, a Share's Volume, a CronJob's Jobs) and each deletion as if that writer applied it. |
| A refusal | One refusal and nothing is applied: `state: error`, `Secret/store/db: Release/store/shop was applied by alice, and alice may not apply Secret in namespace store: no Role bound to it allows that`. A writer who loses a right or is deleted stops the next render, not what is installed. |
| The writer's key | A Release (and a Source) also needs its writer's key as it was then (`kith.dev/written-key`): after a new certificate, an Identity made again, or for a Release from before this was written, nothing new is made until it is applied again. |

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

| | |
|---|---|
| Layout | The package `web` is the repository `packages/web`, each version a tag: one blob (the package's files) and an Ed25519 signature over name, version and the blob's SHA-256, as the annotation `dev.kith.signature`. |
| Fetching | A Release that names a Repository must be applied by someone who may `apply` Packages (else nothing is fetched and the status says so). The node that leads the store fetches the newest version that fits, checks it against the `publicKey` and stores it as a Package (annotated `kith.dev/repository`). Registries are asked when a Release wants something new and every `--repository-poll` seconds (300) for Releases with `autoUpgrade`. |
| Checking | An unsigned or wrongly signed package is refused (the Repository's `state: error`); a newer version that fails is passed over for the newest that passes. With no `publicKey`, whoever answers at the `url` is trusted. Changing either re-fetches and re-checks everything. |
| Versions | A version is fetched once; pushing it again changes nothing here. A signature says a package is the publisher's, not the newest: a registry can hide newer ones. A Package keeps its last 3 revisions (other kinds 100): push a new version rather than rolling far back. |
| Pushed by hand | A Release renders it with its pusher's rights as well as its writer's: what the Package makes and no longer makes is asked of the pusher too. Where the pusher may not, nothing new is made, what was installed stays, and the status says whose right fell short (a Package pushed before kithd wrote the pusher down renders nothing new until pushed again). |
| Fetched | It has no pusher: the Repository's key is its trust, so whoever may apply a Repository gives the rights of every Release that names it. Only kithd's fetcher sets `kith.dev/repository`: an apply or a Source's file that carries it is refused. |
| Reaching a registry | `kith` goes through kithd. Plain HTTP only to a registry on the same machine. |
| Many versions | A package's tags are read page by page, as far as the registry's `Link: <…>; rel="next"` headers go (up to 50 pages and 50 000 tags; more is an error). A next page on another host or port than the registry's is refused. |
| Credentials | `spec: { url: …, credentials: { namespace: ops, secret: registry } }` names a Secret whose `username` and `password` kithd sends as Basic auth to the registry, or to the token service it names. The Secret is read with the rights of whoever applied the Repository (it must be allowed to `get` it; a Repository applied before kithd wrote that down reads none until applied again). Fetching uses them; `kith package push` stays anonymous, and so do `oci://` Sources. |

Not yet: `dependencies` are read and nothing more; no delete hooks, no `lookup` outside the release's
namespace or in `.kith` files, no registry credentials for pushing or for Sources.

### A desktop is a package

kith has no desktop of its own: a node nobody gives one stays headless. Four example packages
show the shape ([`packages/hyprland`](../../packages/hyprland),
[`packages/gnome`](../../packages/gnome), [`packages/kiosk`](../../packages/kiosk),
[`packages/kith-panel`](../../packages/kith-panel)):

```sh
kith get seat                       # office-pc-seat0
kith get seat office-pc-seat0 -o yaml > seat.yaml   # add under metadata.labels: kith.dev/namespaces: desktop
kith apply -f seat.yaml             # the seat is given to the namespace desktop
kith package render packages/hyprland --name office -n desktop \
  --set seat=office-pc-seat0 --set image=registry.example/me/hyprland:1 | kith apply -f -
```

- The seat's `kith.dev/namespaces` label must name the session's namespace (`desktop` above), or
  the claim is refused and its `status.message` says so: an unlabelled seat is `kith-system`'s
  alone ([Who may claim what](hardware.md#claiming-hardware)).
- A session package renders an exclusive `DeviceClaim` for the seat and a one-replica `Workload`
  that holds it ([Hardware](hardware.md#hardware)); `reserve` is its CPUs and memory. It sets
  `XDG_RUNTIME_DIR=/run/seat`, where the apps find the compositor's and PipeWire's sockets.
- kith ships no desktop images: `image` names one you built or trust. It is told `KITH_SEAT`,
  `KITH_USER` and (Hyprland, GNOME) `KITH_APPS` and `KITH_DOTFILES`; the kiosk runs `command`. It
  runs as the image's `User` and is never started as root to become one ([What a container is
  kept from](workloads.md#what-a-container-is-kept-from)): give the image the user the session
  is to be. The seat's device nodes are that user's (on kith OS).
- `kith-panel` is a `Workload` for a panel image that is a window of a seat's session: it holds
  a claim on `seat` with `access: client` ([an app as a workload of its
  own](hardware.md#hardware)), runs on the seat's node and finds the Wayland socket at `display`.
- Delete the release and the node is headless again.

A desktop with no screen, in a browser: [`packages/selkies`](../../packages/selkies) runs
[Selkies](https://github.com/selkies-project/selkies)' desktop image (pinned, Ubuntu, software
rendering) as a pod behind a Service on port 8080, its login the user `ubuntu` and the `password`
key of a Secret you make first. The image writes under `/` as it starts, so it is a pod; and its
own password is a published one, so the package names a Secret and renders none:

```sh
kith apply -f - <<< '{"apiVersion": "kith.dev/v1", "kind": "Secret", "metadata": {"name": "selkies-password"}, "spec": {"data": {"password": "YOURS"}}}'
kith package render packages/selkies --name desk | kith apply -f -
```

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

- A resource that names no namespace goes in the Source's. A Source applies only into its own
  namespace; one in `kith-system` applies anywhere and any kind. Either way
  it applies only what whoever applied it
  may apply, as a Release does (above): its repository's authors can make whatever that writer
  can, and no more. A Release or a Source it makes acts with the same writer's rights.

| | |
|---|---|
| Fetching | The node that leads the store fetches the source every `intervalSeconds` (5 at least) and applies its resources, marked `kith.dev/owned-by` like a Release's. Sources are fetched several at once; one that keeps failing is fetched less often (its interval doubles each time, to an hour). |
| Conflicts | It does not take over what is there and not its own. Of two Sources that name one resource the one that has it keeps it (the first by name, if they come together); the other says `error`. |
| `status.state` | `synced` (at `revision`), `pending` (`pending.revision` waits for `kith source approve`, with what it would change) or `error` (with `message`; what was applied stays). When the source moves on, a manual Source waits again. |
| Approval | It is for a revision: a Source whose `path` or `prune` you change applies the revision already approved the new way. |
| Drift | What a Source applied and someone changed since is put back and listed in `status.drift`: the source is what is true. Deleting a Source deletes what it applied. |
| git | The node's `git` program, over `https://` or `ssh://` only, with no credentials but what ssh has. Nothing is checked out, so links in a repository are skipped (`status.skipped`); a source is 2000 files and 4 MB at most. git runs under `ulimit -f` and writes no file over 256 MB. |
| Addresses | Only a Source in `kith-system` is fetched over `ssh://` (the node's own keys open the door) or from this node and its own networks (loopback, private, link-local and shared addresses, by whatever name; any address of this machine's cards or a Node's advertised). Any other Source is fetched from the very address that was checked: a name that answers differently a moment later, or a redirect, leads nowhere else (git follows none and needs 2.37 or newer; a registry's redirects and token host are checked the same way). |

Not yet: signed-commit verification, credentials for private repositories.
