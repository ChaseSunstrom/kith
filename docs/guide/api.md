# Resources and the language

## kith.dev/v1 is stable

```sh
cargo test -p kith-api stable          # the kinds take every file v1.schema.json says they took
```

Every resource says `apiVersion: kith.dev/v1`, and from kith 1.0 that is a
promise: a file that 1.0 takes is taken by every later build.

- `crates/kith-api/v1.schema.json` is the JSON Schema of every built-in kind
  (what `kith schema KIND` prints), and the test above compares the code with
  it. A field or a kind that is gone, a type that changed, a field that is
  newly required and a new limit on a value are each named, and fail the
  build.
- Kinds grow: a new field nobody has to give, a new kind, one more value a
  field takes. Those pass once the file is written again
  (`KITH_BLESS=1 cargo test -p kith-api stable`), so every change to what v1
  takes is in a diff somebody reads.
- A change that would refuse a v1 file waits for a `kith.dev/v2`.

A schema does not say everything: what a field means when it is left out,
the checks across fields, and the few values kith reads by hand (a quantity
such as `512Mi`, a placement preference) are held by review, not by that
test. Not
promised: the fields of `status` (controllers write them, and they change),
kinds you define yourself (their schema is yours), and what the commands
print for people (`-o yaml` and `-o json` print resources, which are).

## YAML, strictly

kith reads a strict subset of YAML (and JSON, which is a subset of that):

- duplicate keys are an error;
- anchors, aliases and tags are errors;
- `no`, `on`, `Yes`, `0x10` and `012` are strings; only `true`/`false`, `null`/`~`, and decimal numbers are special;
- where a field is a string, the text is taken as written, so `version: 1.0` is `"1.0"`;
- unknown fields are errors.

## kith's own language

YAML says what there is. When the same thing is said five times with one word changed, a
file named `*.kith` can work it out instead: values with names, functions, `if`, lists and
records built from other lists and records, and other files imported. What such a file
gives is the resources a YAML file would have held, checked by the same code, so
`kith apply`, `kith lint` and `kith diff` take a `.kith` file wherever they take YAML (in a
directory too, beside YAML files), and `kith eval FILE` prints what it gives, as YAML.
Nothing has to be written in it: every YAML file stays as valid as it was.

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

A kind's name before a record makes it a resource of that kind (`apiVersion` and `kind` are
written for you); a kind of your own is a record that says its own `apiVersion`. A file
gives one resource, a list of them (lists inside it are taken apart), or `null`. What is
`null` is left out: a field that is `null` is not written and neither is a `null` item of a
list, which is how a part is made optional (`expose: if host != "" then { host, via: "edge" } else null`).

A mistake is refused where it was said, with the path into the resource, whether the
value was written there or worked out three functions away:

```
web.kith:16:23: Workload.spec.replicas: invalid type: string "three", expected u32
  |             replicas: "three",
  |                       ^
```

### All of it

```
file    = { "let" NAME "=" expr ";" | "fn" NAME "(" params ")" "=" expr ";" } expr
params  = [ NAME [ "=" expr ] { "," NAME [ "=" expr ] } ]
expr    = "if" expr "then" expr "else" expr
        | "|" params "|" expr                      a function without a name
        | expr OP expr                             ??  ||  &&  == != < <= > >=  + -  * / %
        | ( "!" | "-" ) expr
        | expr "." NAME | expr "[" expr "]" | expr "(" [ expr { "," expr } ] ")"
        | "import" STRING                          what another file gives
        | KIND "{" fields "}"                      a resource of that kind
        | "{" fields "}" | "[" items "]" | "(" expr ")"
        | "{" { let | fn } expr "}"                names for one value only
        | STRING | NUMBER | "true" | "false" | "null" | NAME
fields  = [ field { "," field } [ "," ] ]
field   = NAME ":" expr | NAME | STRING ":" expr | "[" expr "]" ":" expr | ".." expr
items   = [ item { "," item } [ "," ] ]
item    = expr | ".." expr | "for" NAME "in" expr [ "if" expr ] ":" expr
```

- **Values** are `null`, `true` and `false`, whole numbers and numbers with a fraction,
  strings, lists, records and functions. Nothing changes once it has a name.
- **Strings** are in double quotes; `${…}` puts a value in (`"${app}-${n}"`), and
  `\n \t \r \" \\ \$` are the escapes. Three quotes open a string of several lines, which
  loses the indentation its closing quotes stand at.
- **Records**: `{ app }` is `{ app: app }`; `..base` puts another record's fields in, and a
  field said after it replaces the one it brought; `[key]: value` works the field's name
  out. A name said twice in one record is a mistake.
- **`??`** gives its right side when the left is `null` or names a field or an item that is
  not there: `values.replicas ?? 1`.
- **Operators** bind as listed above, loosest first. `+` adds numbers and joins strings
  and lists; `/` of two whole numbers is a whole number; `==` compares whole values.
- **`import "./lib.kith"`** gives what that file gives (usually a record of functions). The
  path is from the importing file, ends in `.kith` and stays inside the directory of the
  file `kith` was given; a file that imports itself, through others or not, is refused.
- **Comments** run from `//` to the end of the line.

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

A file cannot read the machine it is evaluated on, the time or the network, so the same
file gives the same resources everywhere. It is held, too: it ends in 500,000 steps,
nested 3,000 deep (a function that calls itself gets a thousand calls or so down) and 1 MB
of output, or is refused, which is what lets kithd evaluate a package's files from a
registry.

### In a package

A package's `templates/` may hold `.kith` files instead of (or beside) YAML templates:
each gives resources as above and has the names a YAML template has (`values`, `release`,
`package`, `name`, `labels`). A file whose name starts with `_` is only there to be
imported. [`packages/web-kith`](../../packages/web-kith) is [`packages/web`](../../packages/web)
written this way, and gives the same resources. Its `templates/service.kith`:

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

### In an editor

`kith-lsp` is a language server for `.kith` files (`cargo build --release -p kith-lsp`; it
is its own small program, and nothing else of kith needs it). It says what is wrong as you
type, by the same messages `kith lint` gives; offers the kinds, the fields of the kind the
cursor is inside (from the same schemas `kith schema` prints), the builtins and the file's
own names; and says what a field or a builtin is when pointed at. A file in a package's
`templates/` is read with the names a template has, its `values` the package's own
`values.yaml`. Any editor that speaks LSP starts it with no arguments, for files named
`*.kith`. In Neovim:

```lua
vim.filetype.add({ extension = { kith = "kith" } })
vim.api.nvim_create_autocmd("FileType", {
  pattern = "kith",
  callback = function() vim.lsp.start({ name = "kith-lsp", cmd = { "kith-lsp" } }) end,
})
```

## Kinds of your own

A `KindDefinition` makes a new kind. Resources of it are applied, listed,
watched, kept with their history and deleted like any other; what a kind
*does* is up to a controller that watches it.

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

- The store checks every write of such a resource against the schema, and
  says what is wrong by path (`spec.players: it must be at most 64`). In one
  `kith apply`, put the definition before what is of its kind.
- `kith get`, `delete`, `history`, `rollback` and `schema` take the kind's
  name in any case, like kith's own; `kith schema` lists the cluster's kinds
  after kith's.
- One definition per kind. A definition cannot be deleted, renamed to another
  kind or moved between namespaced and cluster-wide while resources of its
  kind exist. A changed schema is checked at the next write of each resource;
  what is stored stays as it is.
- A Source or a package may apply resources of a defined kind; a Source in
  `kith-system` may bring the definition along.

Not yet: several versions of a kind side by side, a schema for `status`.

### Controllers and admission, in WebAssembly

A kind can carry code: a **controller** that says what should exist because
of each resource of the kind, and an **admission** hook that is asked before
one is written. Both are WebAssembly modules that kithd runs itself, with no
container, image or credentials: a function from JSON to JSON that can reach
nothing else.

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

`kith controller set` puts the module in the kind's KindDefinition
(`spec.controller.wasm`, `spec.admission.wasm`, base64), so it is replicated,
kept in history and rolled back like the rest of the cluster's state.

- **The controller** runs on the node that leads the store, whenever the
  resource, the module, or something the resource owns changes. It is given
  `{resource, owned}` and answers `{status, resources}`. The resources are
  made so in the resource's namespace as its own (annotated
  `kith.dev/owned-by`), put back if someone changes or removes them, removed
  when no longer answered, and removed with their owner. It may make anything
  namespaced except a Release or a Source, including resources of other
  defined kinds, whose controllers then run in turn.
- Its `status` fields are recorded on the resource, with `resources` (what it
  owns) and `controller`: `{state: ok, observedRevision}` or `{state: error,
  message}`. A run that fails changes nothing and is tried again when
  something changes.
- **Admission** is asked about every apply of a resource of the kind through
  kithd, whoever makes it (`kith apply`, a Source, a Release, a controller),
  with `{resource, old}`. It may refuse (`refused by GameServer's admission:
  the map lava is closed`, also on `--dry-run`) or change the spec, labels
  and annotations; what it makes of the resource is then checked against the
  schema like any write. A hook that fails refuses the write.
- **Limits**, each ending that one call with the reason: a module of at most
  1 MiB, 50 million instructions' worth of fuel, 16 MiB of memory, 1 MiB of
  input and of answer. A module that imports anything does not start. Each
  call starts from a fresh instance: nothing is remembered between calls.
- Whoever may write KindDefinitions may run code in every namespace through
  them: grant that as you would grant admin.
- A controller acts as whoever applied its KindDefinition (kith writes that one
  down, name and key, on the KindDefinition), not as whoever applied a resource
  of the kind: what it answers is made, and what it no longer answers removed,
  only where that one may apply and delete it in the resource's namespace, and the
  resource's status says whose right fell short. So the right to apply a custom
  kind's resources is the right to what its controller makes of them in that
  namespace. A KindDefinition applied before this makes nothing new until it is
  applied again.

Things to know: a rollback is asked of admission too (what it refuses does
not come back; what it would change comes back as it was); a delete is not
asked. At most four modules run at once, and a controller answers at most 64
resources. Applying
a KindDefinition's YAML again without its `controller`/`admission` removes
them (keep the YAML and the module together, or run `kith controller set`
after). `kith --store FILE`, which works on a file without kithd, runs
neither. A module sees one resource and what it owns; a controller that has
to look further is a Workload using the API.

In another language: export `memory`, `kith_alloc(len: u32) -> ptr`, and
`kith_reconcile` / `kith_admit` as `(ptr: u32, len: u32) -> u64`: JSON in at
`ptr`, and the answer's `ptr << 32 | len` out, `{"ok": …}` or `{"error":
"why"}`.
