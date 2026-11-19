# A FIDO2 key as a way into a node's state

Status: design, nothing built (T-0863). This record settles what [adr-unlock.md](adr-unlock.md)
left as "FIDO2: deferred", item by item, so that the build can be cut into slices that each
stand alone. Where the code differs from a line here, the code is the word. A decision here
that a build finds wrong is changed here, in the same commit.

What it is for: a person at a node's console (a screen and keyboard, or a serial line) opens the
node's encrypted state by touching a security key, as they would by typing a passphrase.
The ways into the state that exist are the key on disk, the TPM seal, the PIN, the cluster's key,
the recovery key and the passphrase ([adr-unlock.md](adr-unlock.md)). A key is one more of them. It adds
no way for a program: it needs a hand on the node.

## What is checked, and what is not

Every claim about code cites a line of the tree at the commit this record was written on. Three
claims are not checked, and are marked **unverified** where they are used: whether
`x86_64_defconfig` already gives the kernel the HID options (the kernel tree is built outside the
repository), what size the client will add to kithd (no build was made for this record), and how a
real key answers (no real key was touched, and none will be: the tests use a stand-in).

## 1. The CTAP2 client

[adr-unlock.md](adr-unlock.md) (the FIDO2 section) lists it: CTAPHID over `/dev/hidraw*` (initialization,
channels, 64-byte reports, keep-alives), a CBOR subset written here, `getInfo`, `clientPIN`
getKeyAgreement (ECDH P-256), `makeCredential` with the `hmac-secret` extension to enrol a key,
and `getAssertion` with `hmac-secret` at the console. Re-checked against what the tree has:

- **ECDH P-256 and SHA-256/HMAC: ring, already linked** (`crates/kithd/Cargo.toml:42`).
  `ring::agreement` does P-256 ECDH; `ring::hmac` and `ring::digest` do the rest.
  adr-unlock's "ring has no raw AES" still holds, and it does not matter here.
- **AES-256-CBC: no new crate.** adr-unlock names the `cbc` crate on top of `aes`. The `aes`
  crate is a dependency already (`Cargo.toml:65`, `default-features = false`) and `tpm.rs:28`
  and `tpm.rs:146` already drive its block cipher by hand for the TPM's CFB. CBC is a loop of
  XOR and one block each way (`BlockCipherEncrypt`, and the decrypt trait from the same
  `aes::cipher`); about 25 lines, and a `cbc` dependency is avoided.
  Its test is a KAT of the loop on NIST's vectors: SP 800-38A's CBC-AES256 example (a chosen IV)
  and the AESAVS CBC vectors (which use a zero IV, as `hmac-secret` does). The CTAP2
  specification publishes no CBC or ECDH test vectors, so none is claimed.
- **ECDH is tested only as far as it can be.** `ring::agreement` cannot import a fixed private
  key (an ephemeral key is generated and used once), so a known-answer ECDH is not possible
  through ring. What is tested is the derivation from the shared secret's x coordinate (SHA-256
  of it, the protocol 1 key) on a fixed x. The independent check of the whole exchange is one
  real key, tried by the owner (section 2).
- **PIN protocol 1 only, a limit and not a recommendation.** Protocol 1 (the SHA-256 of the ECDH
  x coordinate as the key, a zero IV, the first 16 bytes of an HMAC) is what every CTAP2.0 key
  must have. Protocol 2 exists partly for FIPS, and protocol 1 on a key that has both is
  **unsupported** by the specification's own direction, not a guarantee of it. This record
  does not claim that keys with protocol 2 still list protocol 1. A key that lists only
  protocol 2 is refused with a message naming `pinUvAuthProtocols`. **Protocol 2 is required
  before any release**, or the owner accepts the limit in writing (open, section 8).
- **A key that already has a PIN set is probably not enrolled by v1.** v1 asks for a touch
  (user presence) only; a key with a PIN set answers `makeCredential` without `pinUvAuth` with
  `PIN_REQUIRED` (unverified: no real key was touched). Either the enrolment uses `pinUvAuth`
  (getPinToken, which is the key's-own-PIN item of section 8, and needs protocol 2 above), or
  it is listed as a limit: **v1 enrols a key without a PIN, and says so when it is refused.**
- **CBOR: a subset of what is written once** and shared by the client and the stand-in:
  unsigned and negative integers, byte and text strings, arrays and maps with definite lengths,
  and `bool`. It refuses indefinite lengths, tags, floats and nesting deeper than 8. A key's answer
  is untrusted bytes, so the decoder is bounded: a CTAPHID message is at most 7609 bytes, and no
  allocation is made from a length before it is checked against the bytes left.
- **No libfido2.** It is C, and kithd links no C (the musl build, `ci/musl.sh`).
- **What it does not do:** the key's own PIN, resident keys, `credProtect`, U2F. See "What it
  leaves open".

Estimated size and where it goes: section 5.

## 2. The software authenticator behind uhid

Nothing in the repository can test a key. The tests need an authenticator that is not
a person's key and is not a real device: a program in the guest that makes a HID device appear
and answers the client's CTAPHID frames. Candidates, checked:

| Candidate | Behind | Licence, size | Verdict |
|---|---|---|---|
| QEMU `u2f-emulated` | the VM's USB bus | built into QEMU, speaks U2F only (unverified) | **absent**: this machine's `qemu-system-x86_64` 11.1.3 lists `u2f-passthru` and no `u2f-emulated` in `-device help`. |
| QEMU `u2f-passthru` | a host `/dev/hidraw` | built in | refused: it hands the guest a real key. Real keys are never touched. |
| QEMU `canokey` | the VM's USB bus | CanoKey QEMU (Apache-2.0), a library linked into QEMU | **absent**: not in this QEMU's `-device help`. It would be the best fit (it does CTAP2 with `hmac-secret`); worth re-checking where QEMU is built with it (open, section 8). |
| OpenSK | a host process, or firmware | Apache-2.0, tens of thousands of lines of Rust | refused: a dependency on a project's tree and `std` build whose uhid or hidraw bridge is not verified here (unverified), to test a client of about 850 lines. |
| python-fido2 and the like | a host script | Apache-2.0 / BSD, client side | refused: they are clients, and a Python in the guest is not there. |
| **In-tree, on `/dev/uhid`** | the guest kernel's uhid | ours, Apache-2.0 like the tree (`Cargo.toml:10`), about 400 lines | **chosen.** |

**The choice: write it in this tree**, as a module of kithd behind a cargo feature, `fido2-test`.
It is the shape `forge` already has: a test-only build of kithd, made in a target directory of its own
by `ci/musl.sh` with `KITHD_FEATURES=fido2-test` (`ci/musl.sh:28-39` handles
`forge` so), whose shipped binary is checked to hold none of it (`ci/musl.sh:50-53`: the shipped
kithd is grepped for the forge route; the same grep gets a string only the stand-in has). The
feature is declared like `forge = []` (`crates/kithd/Cargo.toml:12`). Because the feature is off in
release, **the stand-in adds nothing to kithd's size**, which section 5 needs.

How it works: it opens `/dev/uhid`, sends `UHID_CREATE2` with a report descriptor of usage page
`0xF1D0` (FIDO), usage 1, one 64-byte input report and one 64-byte output report, then answers
CTAPHID: INIT, CBOR (`getInfo`, `clientPIN` getKeyAgreement, `makeCredential`, `getAssertion`
with `hmac-secret`), PING, and `KEEPALIVE` with status `UPNEEDED` followed by a "touch" a test
releases by a file it creates. Its secrets are a fixed seed, so a test can say what the
`hmac-secret` must be. Two instances (two uhid devices with different seeds) stand for the two keys.

What it proves and does not: the client's frames go through the kernel's real HID layer
(uhid, then hidraw, then the client), so a wrong report size, a missed keep-alive or a bad
channel is found. It does not prove a real key's quirks (the stand-in is written by the same
hand that wrote the client, and reads the same specification: a misreading would agree with
itself). NIST's CBC vectors check the cipher step in the unit tests (section 1); nothing
public checks the CTAP2 exchange, so **the independent check is one real key**, tried by the
owner, once, after the build, and a failure found there becomes a captured fix (the same rule
as the TPM, `docs/adr-unlock.md`'s Unverified items).

**The stand-in is a test tool and must not reach a release, at forge's parity.** `forge` has
four guards, and `fido2-test` gets each one; T-0955 extends each of them, and the slice is not
done until all four are:

1. **The build output.** `os/build.sh:98-103` refuses an `--out` that is not `target/os-forge`
   for a forge build; the same rule is extended so a `fido2-test` build goes only to its own
   folder (`target/os-fido2`) and a shipped image is never made from it.
2. **The test runner.** `ci/vm/tests.sh:22` sets `KITHD_FEATURES=forge` and
   `osdir=$root/target/os-forge` for the access test alone; the stand-in's test sets
   `KITHD_FEATURES=fido2-test` and `osdir=$root/target/os-fido2` the same way, and no other test
   gets either.
3. **The musl build.** `ci/musl.sh`'s case table (`ci/musl.sh:28-39`) knows `forge` only, and
   its release-path grep (`ci/musl.sh:50-53`) looks for the forge route in the shipped kithd;
   both gain `fido2-test` and a string only the stand-in has.
4. **A loud startup line.** `crates/kithd/src/main.rs:365` prints a line when the forge is on;
   a `fido2-test` kithd prints one too, at the start, naming that it will answer as a key.

`ci/budgets.py:439` already strips `KITHD_FEATURES` from its build, so the size measure never
sees the stand-in.

## 3. The kernel: HIDRAW, USB_HID, UHID

Checked in `os/kernel.config` and `os/features/*.config` (`all`, `gpu-amd-phoenix`, `vfio`): **none of
the three is named.** `os/kernel.config` is merged over `x86_64_defconfig` by `os/build.sh`
(`os/build.sh:173-278`); what it does not name stays what the defconfig gives. It has
`USB_XHCI_HCD=y` (line 22), `INPUT_EVDEV=y` (line 155), `DM_CRYPT=y` (line 34).

- `CONFIG_HIDRAW` and `CONFIG_USB_HID`: **unverified** whether the defconfig has them.
  A key on USB is a USB HID device, and the client reads `/dev/hidraw*`, so both are needed. The
  fix is not to find out but to **name them** (`=y`) in `os/kernel.config`. `os/build.sh:276-278` fails the
  build when the kernel dropped a wanted line ("the kernel did not take …"), so naming
  them also proves the build has them, at the price of a `=y` for what is possibly already
  on. They pull in `HID` and `HID_GENERIC`, which `USB_HID` needs (`select`).
  What the defconfig's own HID options are (`HID_GENERIC`, `HID_*` drivers, `UHID`) is
  **unchecked**: `os/` names none of them, and the defconfig is in a kernel tree this record
  did not read. A defconfig that already has `UHID=y` is the case the check below is for.
- `CONFIG_UHID`: **not for the shipped image.** `/dev/uhid` lets a root process make an input
  device out of nothing; a node has no use for it. It goes in a test-only feature file,
  `os/features/uhid-test.config`, merged into the kernel only for the test spec the VM test
  boots.
- **The check is against the built `.config`, not the fragments.** The "did not take" loop
  (`os/build.sh:276-278`) greps `^CONFIG_` from the merge fragments, and the kernel's
  `.config` writes an option that is off as `# CONFIG_UHID is not set`, which that grep never
  sees. So the slice adds a check on the **built `.config`**, after the merge:
  `CONFIG_HIDRAW=y` and `CONFIG_USB_HID=y` must be there in every build; for a shipped build
  the line `# CONFIG_UHID is not set` must be there, asserted explicitly (a missing line, which
  is what an option the tree does not know looks like, fails too), and for the test build
  `CONFIG_UHID=y` must be. This also catches a defconfig that gives UHID on its own.
- **A second kernel costs a second build.** The test kernel differs by one option, so it is a
  second full kernel build for the spec the VM test boots, on top of the shipped one. The
  time is not measured here (unverified); T-0953 measures it and puts the figure in its
  commit, and if it is large the test kernel is built only when the stand-in's test runs,
  never in the default build.
- The kernel's size grows by the HID core, `usbhid` and `hidraw`: tens of kB of image
  (unverified; measured at slice 1 against the image budget in `ci/budgets.py`).

## 4. Enrolling two keys at a running node

Two keys are the request's guard against losing one. The flow is the one a person with two keys
and a node can do, and no part of it needs a typed line at a console that is not waiting:

1. **The verb.** `kith node key add NAME` (`POST /v1/lock/NAME/fido2 {"keys": 2}`), for who
   may apply a NodeKey, by the route and the permit that `crypt::pass` uses
   (`crates/kithd/src/crypt.rs:2386-2425`: the verb is answered by that node alone, another node
   asks it as itself having checked the caller, and the audit log records that it was done,
   never a secret). One request enrols two keys or none. One key alone is not enrolled.
2. **At the node**, which is running and so holds the state's key in memory
   (`crypt::open` returns it with `By`, `crypt.rs:991`): its console says "touch key 1 of 2".
   The person plugs in key 1. The node makes a credential for the relying party `kith.local` with
   `hmac-secret`, and one touch. It then asks for an assertion with a random 32-byte salt, and a second touch
   returns the `hmac-secret`: `makeCredential` does not return the secret, only that the key has it.
3. "Touch key 2 of 2": the same, with key 1's credential in the `excludeList` of
   `makeCredential`, so the same key answers `CREDENTIAL_EXCLUDED` and is refused ("that is the same
   key") rather than enrolled twice.
4. **Written, read back, opened once, in that order** (the rule of adr-unlock's order of writes,
   which keeps the recovery key's line): the state key is wrapped under each `hmac-secret`
   by `wrap` (`crypt.rs:228`), both `fido2:` lines go into the record in one write, the copy first
   (`crypt.rs:464-493`), the record is read back by `Record::read` (`crypt.rs:442-459`), and
   `unwrap` (`crypt.rs:237`) of the line read back with the secret still in memory must give the
   state's key. Only then does the verb answer. A cut at any point leaves the record as it
   was, or whole with the new lines; no old line goes at any point.
5. **Status** says "FIDO2: 2 keys"; a key's credential id is not secret and is shown by its first
   8 hex digits, so two keys can be told apart.
6. **Remove**: `kith node key remove NAME` removes both lines (one alone is refused: a node with one
   key is the state the request guards against), after the recovery key has been shown once
   (`seen`, `crypt.rs:130`), so the record is never left with a way in only a lost key held.
   Replacing a lost key is `remove` then `add` with two keys, which needs the node running and one
   other way in; swapping one key of two is open (section 8).

The record's lines follow `passphrase:` (`Record::text`, `crypt.rs:387-437`; `parse_said`,
`crypt.rs:326-385`): `fido2: <credential id hex> <salt hex> <wrapped key hex>`, one line a key.
A line that cannot be read is dropped and said, never "damaged"; a third line is dropped and said
at read and refused at enrolment (`Record::with_fido2`, T-0971, with the order of writes `Record::order`
and the read-back proof `fido2_proves`). An older kithd ignores
the lines it does not know, and loses them when it writes the record again, since `text()` writes
only what `Record` holds (an inference from `text()`; the downgrade is stated in section 8).

**The size of the record.** A line is about 520 characters at its worst (a credential id of up to
128 bytes in hex, the salt, a wrapped key of 92 bytes), so two take about 1.1 KB of the 4 KiB
`ROOM` (`crypt.rs:100`), and four 2.2 KB. A node that has every other way in carries the lines
of `Record::text` (`crypt.rs:387-437`): `secret`, `recovery`, `key`, `tpm`, `tpm-parent`,
`passphrase`, `tpm-pin`, `tpm-next`, `tpm-pin-next`, the two `duress` keys, `seen`. Those are
estimated at about 1.9 KB all together (an estimate from the line formats; not measured), so
**two fido2 lines bring the record to about 3 KB, and four would not fit in 4 KiB.** So the
verb enrols exactly two keys and **v1 holds two lines, not four**; the `peers:` line, which is
last and already gives way when the room is short (`crypt.rs:421-433`), gives way first, and
the write fails and says so, before anything is written, when the lines other than `peers:`
would not fit. T-0956 has a test with a record that has every other line.

**A node in no cluster.** `pass` answers "this node is in no cluster" there
(`crypt.rs:2413`), since it needs the cluster to say who the node is. The key verbs have the
same route and the same permit, so **on a node with no cluster they are refused the same way**
over the API. This record does not check whether the tree has a local, owner-only route a verb
could use instead (unverified). **T-0956 decides:** either the verb has a local route for such
a node, with the same two-touch flow, or a node in no cluster cannot enrol a key and the verb
says so in those words; either way it has a test on a node with no cluster.

## 5. kithd's size against the budget

`KITHD_SIZE = 13.20` (`ci/budgets.py:48`), in MiB: `MB = 1024 * 1024` (`ci/budgets.py:31`) and the
limit is `int(KITHD_SIZE * MB)` (`ci/budgets.py:61`), so 13,841,203 bytes. `docs/numbers.json` rounds to 12 against 13 (`kithd.size`,
`kithd.size.budget`) and cannot say more. The size on main when this was written is about
**13.17 MiB** (the figure the brief for this record gives; `ci/budgets.py` was not run here), so
the **headroom is about 0.03 MiB, 30 kB**.

The client is estimated at 60 to 120 kB for the protocol and CBOR (adr-unlock's
estimate, whose "from 11.35 MB measured" is long out of date), and 100 to 200 kB with the enrolment
and console. **It does not fit in 30 kB**, and adr-unlock's "the size would fit the budget" is no
longer true. Options:

- **Raise the budget** for the slice that adds it: the history in `ci/budgets.py:34-48` shows each
  feature that did so (13.00 to 13.10 for a phone's way in, 13.10 to 13.20 for the people's levels),
  with the reason in the comment. A raise is its own commit with its measure, and 13.40 is the
  figure to expect (unmeasured). **Chosen**, because the feature is the point and the shipped
  kithd is the only place for it.
- Make the client a cargo feature that a release leaves out: refused, since a way in that is
  absent from the shipped node is not a way in.
- Look for the room first: `ci/budgets.py` tells a crate from a crate (`docs/numbers.json`'s
  `by_crate`: kithd's own code is the largest by far), and the web UI's text served
  compressed (`ci/budgets.py:46-47`) has been the way under before. Done by the slice that
  needs it, not by this record.

**Slice T-0956 measures**, before and after, and puts both in its commit; a budget raise without
the number is refused in review. It is not slice T-0954 (T-0966, T-0968): that slice's code is called by nothing,
and a linker may drop it, so what it adds is not what the feature costs.

## 6. Build slices

Each is one task and stands alone: it merges and passes its gates without the next.

| Task | Slice |
|---|---|
| T-0953 | **Kernel.** `CONFIG_HIDRAW=y`, `CONFIG_USB_HID=y` in `os/kernel.config`; `CONFIG_UHID` in the test-only `os/features/uhid-test.config`; the check on the **built `.config`** (section 3), with `# CONFIG_UHID is not set` asserted for a shipped build; the image size and the second kernel's build time measured. |
| T-0954 (carved: T-0966 the wire half, T-0968 the rest) | **The client.** `crates/kithd/src/fido2.rs`: CTAPHID framing and the CBOR subset (T-0966), then ECDH (T-0968), `hmac-secret` with the hand-written CBC, behind a trait of the device so tests use a pipe; tested on NIST's CBC vectors, the x-coordinate derivation and bad frames (short, a wrong channel, an oversize length, a keep-alive storm). **No size measure and no budget raise here:** nothing calls the code yet, and the linker may drop it, so a number taken now is not the number the feature costs. |
| T-0955 | **The stand-in, and the client against it.** The `fido2-test` feature with the uhid authenticator and the four release guards of section 2 (`os/build.sh:98-103`, `ci/vm/tests.sh:22`, `ci/musl.sh`'s case table and grep, a loud startup line). Its VM test is **the client against the stand-in through uhid and hidraw, and nothing more**: a `fido2-test` subcommand of the test build that runs `makeCredential` and `getAssertion` with a known salt on the stand-in and prints the `hmac-secret`, which the test compares with what the seed says it must be; a second stand-in with another seed gives another secret, and a touch withheld times out. It needs no record, no console prompt and no verb. |
| T-0956 | **The record, the verbs and the state opened by touch.** The `fido2:` lines (two), the console's "touch your key" beside its typed lines (judged after the passphrase, with the same two seconds before an answer, `crypt.rs:726-757`, so a wrong key is answered as every wrong line), `kith node key add` and `remove` with the order of writes above, the audit log; the VM test of enrolling two keys and **opening the state by touching one of two stand-ins** (the other opens it too, a key it was not enrolled with is refused) and of losing one. **kithd's size is measured here, before and after, with the feature called, and the budget raised with the number if it must be** (section 5). |

The order is 1, 2, 3, 4; slices 1 and 2 are independent of each other. Only T-0956 needs the
record, so only T-0956 can open a state by touch and measure the size of what is linked.

## 7. Rivals

- **A passphrase and the TPM PIN already cover a person at the console** (adr-unlock's own last
  reason). True of the person who has a PIN; the key adds a way that needs no memory and survives a
  TPM's loss (a board changed), which the passphrase also does. It is a way,
  not a stronger one. **Not building it** is a rival, and what the other half of this
  record's decision costs is 4 tasks and a budget raise. It is recorded as the cheaper path, and
  the owner decides by closing or keeping the four tasks.
- **The key as a second factor** (the key plus the TPM PIN, both needed). A real gain,
  and a different record line (`secret` from the key wrapped under what the PIN opens); built
  after the single way works. Open.
- **U2F** (what QEMU's emulated key speaks): it signs, it does not hold a secret; there is
  nothing to wrap a key under.
- **A key on the cluster side** (a person's key unlocks a node through the API): a person
  with the owner's key already can; the point of this is the case with no other node.

## 8. What it leaves open

- **A key alone is single-factor possession.** The record (the credential id and the salt) is
  plain on the config partition, as the other lines' public parts are. Whoever has the key and
  a copy of the disk can derive the `hmac-secret` **offline** and unwrap the state's key: no
  console, no two-second wait, no rate limit and no PIN is in the way. The earlier wording, that
  the node's console is needed, was wrong. The mitigations are the key's own PIN (`clientPIN`
  getPinToken, user verification: the key then limits the tries itself), or the key as a second
  factor (section 7: the secret from the key wrapped under what the TPM PIN opens). v1 asks for
  a touch (user presence) only, so **in v1 a stolen key plus a copy of the disk opens the state**,
  a key is kept apart from the node, and the strong way stays TPM plus PIN. The `hmac-secret`
  for user verification is a different secret (CTAP2.1's `CredRandomWithUV`), so enrolling with
  a PIN is a new line, not an edit of this one.
- **A key with a PIN already set** is probably refused by v1 (`PIN_REQUIRED`, section 1).
- **PIN protocol 2** (section 1): required before any release, or accepted as a limit by the
  owner.
- **canokey** in QEMU, where a QEMU has it (section 2), as the test that is not by the same hand.
- **A downgrade loses the lines** (section 4): an older kithd that rewrites the record drops
  `fido2:` lines it does not know. adr-unlock's rule for passphrase lines is the same; a
  guard is for the slice that writes them (the node refuses an OS slot older than the one that
  wrote them, if `os.rs` has the means).
- **Swapping one of two keys**, and more than two keys enrolled at once (the record's room
  allows two lines, section 4).
- **A hardware token the kernel does not give a hidraw** (a Bluetooth or NFC key): out of scope.
- **The weakest link of this record:** the kernel options. Whether `x86_64_defconfig` has `HIDRAW`
  and `USB_HID` is unverified; slice T-0953 turns it into a check.

## Review

Self-review of this record as an adversary: the size figure (13.17) is the brief's and not
measured here, so a number that moves it moves section 5 and nothing else; the two
absent QEMU devices are facts about one machine's QEMU, not about QEMU; the `hmac-secret` flow
(two touches, no secret from `makeCredential`) is from the CTAP2 specification and is
unverified against a real key; and the stand-in agreeing with a client written beside it is
named in section 2 as the thing the specification's vectors and a real key check.
