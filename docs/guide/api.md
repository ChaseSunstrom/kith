# Resources and the language

## kith.dev/v1 is stable

From kith 1.0, a `kith.dev/v1` file that 1.0 takes is taken by every later build.

| | |
| --- | --- |
| **Held by test** | `crates/kith-api/v1.schema.json` is the JSON Schema of every built-in kind (what `kith schema KIND` prints). `cargo test -p kith-api stable` compares the code with it: a gone field or kind, a changed type, a newly required field and a new limit on a value fail the build. |
| **Growth** | A new optional field, a new kind and one more allowed value pass once the file is written again (`KITH_BLESS=1 cargo test -p kith-api stable`), so every change to what v1 takes is in a diff somebody reads. A change that would refuse a v1 file waits for `kith.dev/v2`. |
| **Held by review** | What a schema cannot say: what an omitted field means, checks across fields, and the few values kith reads by hand (a quantity such as `512Mi`, a placement preference). |
| **Not promised** | The fields of `status` (controllers write them), kinds you define (their schema is yours), and what commands print for people (`-o yaml` and `-o json` print resources, which are promised). |
| **YAML, strictly** | kith reads a strict subset of YAML (and JSON). Duplicate keys, anchors, aliases, tags and unknown fields are errors. Only `true`/`false`, `null`/`~` and decimal numbers are special: `no`, `on`, `Yes`, `0x10` and `012` are strings. A string field is taken as written (`version: 1.0` is `"1.0"`). |

## kith's own language

When YAML says one thing five times with a word changed, a `*.kith` file can work it out: named
values, functions, `if`, lists, records, imports. It gives the resources a YAML file would,
checked by the same code: `kith apply`, `lint` and `diff` take it wherever they take YAML, and
`kith eval FILE` prints what it gives. Every YAML file stays valid.

```kith
// web.kith: a workload and the service in front of it.
let app = "web";
let ports = { http: 80, metrics: 9090 };

fn container(image, env = {}) = {
    name: app,
    image,
    ports: [for p in entries(ports): { name: p.key, port: p.value }],
    env: [for e in entries(env): { name: e.key, value: e.value }],
};

[
    Workload {
        metadata: { name: app, labels: { app } },
        spec: {
            replicas: 3,
            template: { containers: [container("docker.io/library/nginx:1.27-alpine", { MODE: "production" })] },
        },
    },
    Service {
        metadata: { name: app },
        spec: { selector: { app }, ports: [{ port: 80, targetPort: "http" }] },
    },
]
```

A kind's name before a record makes it a resource of that kind; a kind of your own is a record
with its own `apiVersion`. A file gives one resource, a list of them (nested lists flattened) or
`null`. A `null` field or item is left out, which makes a part optional (`expose: if host != ""
then { host, via: "edge" } else null`). A mistake is refused where it was said, with the path
into the resource:

```
web.kith:16:23: Workload.spec.replicas: invalid type: string "three", expected u32
  |             replicas: "three",
  |                       ^
```

### Syntax

| | |
| --- | --- |
| **A file** | `let NAME = expr;` and `fn NAME(params) = expr;` lines, then one expression. |
| **Expressions** | `if c then a else b`; `\|x, y = 1\| expr` (a function without a name); `f(a, b)`, `r.name`, `l[i]`; `Kind { … }` (a resource); `{ let …; fn …; expr }` (names for one value only); a list item `for x in xs if c: expr` or `..other`. A parameter may have a default (`fn f(a, b = 1)`). |
| **Values** | `null`, `true`, `false`, whole numbers, numbers with a fraction, strings, lists, records, functions. Nothing changes once it has a name. Comments run from `//` to the end of the line. |
| **Strings** | In double quotes; `${…}` puts a value in (`"${app}-${n}"`); escapes are `\n \t \r \" \\ \$`. Three quotes open a multi-line string, which loses the indentation its closing quotes stand at. |
| **Records** | `{ app }` is `{ app: app }`; `..base` puts another record's fields in, and a later field replaces one it brought; `[key]: value` works the name out. A name said twice in one record is a mistake. |
| **`??`** | Gives its right side when the left is `null` or names a field or item that is not there: `values.replicas ?? 1`. |
| **Operators** | Loosest first: `??`, `\|\|`, `&&`, `== != < <= > >=`, `+ -`, `* / %`, then prefix `!` and `-`. `+` adds numbers and joins strings and lists; `/` of two whole numbers is a whole number; `==` compares whole values. |
| **`import "./lib.kith"`** | Gives what that file gives (usually a record of functions). The path is from the importing file, ends in `.kith` and stays inside the directory of the file `kith` was given. An import cycle is refused. |

The builtins:

| | |
| --- | --- |
| `len(x)` | how many items a list, fields a record or characters a string has |
| `map(list, f)` | a list of f(item) for each item |
| `filter(list, f)` | the items f(item) is true of |
| `range(n) or range(from, to)` | the whole numbers from 0 (or `from`) up to, not including, the last |
| `sort(list)` | a list of strings or a list of numbers, the smallest first |
| `keys(record)` | its fields' names, in order |
| `values(record)` | its fields' values, in order |
| `entries(record)` | a list of { key, value }, one for each field |
| `record(list)` | a record from a list of { key, value } |
| `has(x, y)` | whether a record has the field y, a list the item y or a string the text y |
| `merge(a, b)` | record a with b's fields over it, records inside merged the same way |
| `join(list, between)` | its items as one string |
| `split(string, at)` | the pieces of a string between each `at` |
| `replace(string, from, to)` | the string with every `from` made `to` |
| `string(x)` | a number, true or false as text |
| `int(x)` | a whole number from a string or from a number with a fraction (which is cut off) |
| `json(x)` | a value written out as JSON |
| `yaml(x)` | a value written out as YAML |
| `b64(string)` | its bytes in base64 |
| `error(message)` | stops here with that message |

A file cannot read the machine, the time or the network, so it gives the same resources
everywhere. It is refused at 500,000 steps, 3,000 levels of nesting (a function calling itself
gets a thousand calls or so) or 1 MB of output, so kithd can run a registry package's files.

A package's `templates/` may hold `.kith` files instead of or beside YAML templates, with a YAML
template's names (`values`, `release`, `package`, `name`, `labels`); a file named `_*` is only
for importing. [`packages/web-kith`](../../packages/web-kith) is
[`packages/web`](../../packages/web) written this way. Its `templates/service.kith`:

```kith
// The Service in front of the server and, if there is a page, the page.
[
    Service {
        metadata: { name },
        spec: {
            selector: { app: name },
            ports: [{ port: 80, targetPort: "http" }],
            expose: if (values.expose.host ?? "") != ""
                then { host: values.expose.host, via: "edge" }
                else null,
        },
    },
    if (values.page ?? "") != "" then ConfigMap {
        metadata: { name: "${name}-page" },
        spec: { data: { "index.html": values.page } },
    } else null,
]
```

For editors, `kith-lsp` (`cargo build --release -p kith-lsp`; nothing else needs it) is a
language server for `.kith` files. It reports errors as you type with `kith lint`'s messages,
offers kinds, the fields of the kind the cursor is in (from `kith schema`), builtins and the
file's names, and says what each is when pointed at. In a package's `templates/` it knows a
template's names, with `values` from `values.yaml`. Any LSP editor starts it with no arguments.
In Neovim:

```lua
vim.filetype.add({ extension = { kith = "kith" } })
vim.api.nvim_create_autocmd("FileType", {
  pattern = "kith",
  callback = function() vim.lsp.start({ name = "kith-lsp", cmd = { "kith-lsp" } }) end,
})
```

## Kinds of your own

A `KindDefinition` makes a new kind, whose resources are applied, listed, watched, kept with
history and deleted like any other. What a kind *does* is up to a controller that watches it.

```yaml
apiVersion: kith.dev/v1
kind: KindDefinition
metadata: { name: gameserver }
spec:
  group: games.example.com   # a domain of yours; with version, the apiVersion
  version: v1
  kind: GameServer
  namespaced: true           # [true]
  schema:                    # of the spec; the same subset as a package's values
    type: object
    required: [map]
    additionalProperties: false
    properties:
      map: { type: string }
      players: { type: integer, minimum: 1, maximum: 64 }
  columns:                   # what `kith get gameserver` shows
    - { name: Map, path: spec.map }
---
apiVersion: games.example.com/v1
kind: GameServer
metadata: { name: one }
spec: { map: dust, players: 8 }
```

| | |
| --- | --- |
| **Checks** | The store checks every write of such a resource against the schema and names what is wrong by path (`spec.players: it must be at most 64`). In one `kith apply`, put the definition first. A changed schema is checked at the next write of each resource; what is stored stays. |
| **Commands** | `kith get`, `delete`, `history`, `rollback` and `schema` take the kind's name in any case; `kith schema` lists the cluster's kinds after kith's. One definition per kind. While resources of a kind exist, its definition cannot be deleted, renamed to another kind or moved between namespaced and cluster-wide. |
| **Who applies** | A Source or package may apply resources of a defined kind; a Source in `kith-system` may bring the definition along. Not yet: several versions of a kind side by side, a schema for `status`. |

### Controllers and admission, in WebAssembly

A kind can carry a **controller** (says what should exist because of each resource) and an
**admission** hook (asked before a write). Both are WebAssembly modules kithd runs itself, with
no container, image or credentials: a function from JSON to JSON that reaches nothing else.

```rust
// sdk/kith-controller/examples/gameserver has all of it
use kith_controller::{Admit, Reconcile, Reconciled, Value, json};

fn reconcile(input: Reconcile) -> Result<Reconciled, String> {
    let name = input.resource["metadata"]["name"].as_str().ok_or("no name")?;
    Ok(Reconciled {
        status: json!({ "state": "ready" }),
        resources: vec![json!({
            "apiVersion": "kith.dev/v1", "kind": "ConfigMap",
            "metadata": { "name": format!("{name}-config") },
            "spec": { "data": { "map": input.resource["spec"]["map"] } },
        })],
    })
}

fn admit(input: Admit) -> Result<Option<Value>, String> {
    if input.resource["spec"]["map"] == "lava" {
        return Err("the map lava is closed".into());   // refused, with this reason
    }
    Ok(None)                                           // as it is; Some(resource) changes it
}

kith_controller::controller!(reconcile);
kith_controller::admission!(admit);
```

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown    # a cdylib depending on sdk/kith-controller
kith controller set GameServer --controller game.wasm --admission game.wasm
```

`kith controller set` puts the module in the KindDefinition (`spec.controller.wasm`,
`spec.admission.wasm`, base64), so it is replicated, versioned and rolled back with the cluster.

| | |
| --- | --- |
| **Controller** | Runs on the node that leads the store, whenever the resource, the module or something the resource owns changes. Given `{resource, owned}`, answers `{status, resources}`. The resources are made in the resource's namespace as its own (annotated `kith.dev/owned-by`), put back if changed or removed, removed when no longer answered, and removed with their owner. It may make anything namespaced except a Release or a Source, including resources of other defined kinds, whose controllers then run in turn. |
| **Status** | Its `status` fields are recorded on the resource, with `resources` (what it owns) and `controller`: `{state: ok, observedRevision}` or `{state: error, message}`. A failed run changes nothing and is tried again when something changes. |
| **Admission** | Asked about every apply of a resource of the kind through kithd, whoever makes it (`kith apply`, a Source, a Release, a controller), with `{resource, old}`. It may refuse (`refused by GameServer's admission: the map lava is closed`, also on `--dry-run`) or change the spec, labels and annotations; the result is checked against the schema like any write. A hook that fails refuses the write. A rollback is asked too (what it refuses does not come back; what it would change comes back as it was); a delete is not. |
| **Limits** | Each ends that one call with the reason: a module of at most 1 MiB, 50 million instructions' worth of fuel, 16 MiB of memory, 1 MiB of input and of answer. A module that imports anything does not start. Each call starts from a fresh instance: nothing is remembered. At most four modules run at once; a controller answers at most 64 resources. |
| **Rights** | A controller acts as whoever applied its KindDefinition (kith writes that one's name and key on it), not whoever applied a resource of the kind: what it answers is made, and what it no longer answers removed, only where that one may apply and delete it in the resource's namespace, and the resource's status says whose right fell short. So the right to apply a custom kind's resources is the right to what its controller makes of them. A KindDefinition applied before this makes nothing new until applied again. |
| **Grant** | Whoever may write KindDefinitions may run code in every namespace through them: grant that as you would admin. |
| **Good to know** | Applying a KindDefinition's YAML without its `controller`/`admission` removes them: keep the YAML and module together, or run `kith controller set` after. `kith --store FILE`, which works on a file without kithd, runs neither. A module sees one resource and what it owns; a controller that has to look further is a Workload using the API. |
| **Other languages** | Export `memory`, `kith_alloc(len: u32) -> ptr`, and `kith_reconcile` / `kith_admit` as `(ptr: u32, len: u32) -> u64`: JSON in at `ptr`, the answer's `ptr << 32 \| len` out, `{"ok": …}` or `{"error": "why"}`. |
