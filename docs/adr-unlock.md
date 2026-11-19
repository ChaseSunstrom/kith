# The ways into a node's encrypted state, and what each leaves open

Status: decided (T-0189 step 1). Steps 2 (the session, T-0585) and 3 (TPM plus PIN, T-0612)
are built and have run against swtpm only; `kith node pin` is refused unless the owner passes
`--untried-tpm`, which says the owner's checklist has not run on that machine's TPM. Step 4
is built but for dropping `tpm-next:` on a fallback (T-0858 to T-0860); step 5 is not built. They follow "Steps, in order". A security review reads this record before any code is written. Nothing in this
task runs on a real TPM, a real FIDO2 key or a real disk: a software TPM (swtpm) and VM disk
files only. What the owner would run on hardware is the checklist near the end. Every claim
about the TPM that tpm.rs does not already exercise against swtpm is marked "unverified" where
it is made and listed again under "Unverified".

## The problem

A kith OS node installed with `encrypt: true` keeps its state partition under dm-crypt.
kithd, as process 1, opens it before anything is mounted (crates/kithd/src/crypt.rs), with a
key it gets one of several ways. Each way is its own copy of that key, wrapped or sealed, on
its own line of the *lock record*: 4 KiB at 512 KiB into the config partition.

The request: several ways in, any one enough, so that a copied disk opens nothing and nobody
is locked out; and for each way, what it leaves open. Three of the ways it names are missing
(the TPM and a PIN together, an encrypted session to the TPM, a seal that a signed OS update
does not break). One exists in a form that is too loose (a node that opened another way seals
again today for whatever system runs). FIDO2 is the fifth, and is deferred here.

## What exists, and what the request asks

| The request | Today | Here |
|---|---|---|
| Several ways in, any one enough | yes: each a line of the record | new ways are new lines |
| A copied disk opens nothing | no: a copy opens with the recovery key, by a passphrase guessed offline, and by asking the cluster from wherever it reaches a node's port, until `kith node lock` | said in the table below; not changed |
| Nobody is locked out | the recovery key: 128 random bits, shown once | never removed or changed by this task |
| The disk's own secret moves into the TPM | no (README, "Not yet") | not here ("Open") |
| Sealed to the Secure Boot state | PCR 7 is sealed to (T-0237); kith OS's boot file is not signed, so PCR 7 says "off" and no more | unchanged |
| ... and to releases signed with the cluster's release key | no: a seal holds for one boot file (PCR 4) | step 4 |
| An encrypted session to the TPM | no when this record was written: the key crossed the TPM's bus in the clear | step 2, built (T-0585) |
| TPM plus the cluster's key, automatic | not as asked: the cluster's key alone is automatic, and so is the TPM alone | not here ("Open") |
| TPM plus a PIN | no (README, "Not yet": two locks) | step 3 |
| A FIDO2 key touched at the console, two enrolled | no | deferred ("FIDO2") |
| Recovery key: works with the TPM or board gone | yes | unchanged |
| ... can be turned off | no | not here (a non-goal; "Open") |
| ... made anew from a running node | yes (`kith node recovery`, T-0186) | unchanged |
| A node opened another way seals again by itself | yes, for whatever system runs (`crypt::keep`) | narrowed, step 5 |
| Say what each way leaves open | in parts, in README and SECURITY.md | this record; the docs at step 5 |
| (not asked) a passphrase | yes (T-0084): Argon2id, 19 MiB, 2 passes | unchanged |
| (not asked) a duress code | yes (T-0186) | erases the new lines with the rest |

## The ways in

Today, in the order kithd tries them at a start (`crypt::open`, `crypt::fetched`):

1. **The key on the disk** (`key:`). Written by the installer, taken off once another node
   holds the key. A cluster's first node keeps it until a second joins.
2. **The TPM's seal** (`tpm:`, T-0237, `kith node seal`). The key sealed to this TPM and to
   PCRs 0, 4, 7, 9, 12 and 15 as they stood. Tried first; no node is asked.
3. **The cluster's key.** A NodeKey in the store holds the key wrapped under 32 bytes only
   the disk has (`secret:`). Any node hands it to whoever asks by the disk's id at
   `POST /v1/unlock`, unless the NodeKey is locked, wiped or forgotten.
4. **The recovery key** (`recovery:`). The key wrapped under 16 random bytes, shown once,
   typed at the console.
5. **A passphrase** (`passphrase:`, T-0084, `kith node passphrase`). The key wrapped under
   what Argon2id draws from it, typed at the console.

The duress code (T-0186) is not a way in: typed at the console it erases the record and has
the cluster forget the key.

Wanted, and what this task builds:

6. **The seal over a salted, encrypted session** (step 2): the same way as 2, but the key
   no longer crosses the bus in the clear, and the storage key's name is kept and checked.
7. **TPM plus PIN** (step 3, `tpm-pin:`): the TPM in the sealed state, and a PIN of six
   digits or more typed at the console. Both, or nothing. A node in this mode keeps no `tpm:`
   line.
8. **A seal for the next system** (step 4, `tpm-next:` and `tpm-pin-next:`): made before an
   update signed with the release key restarts the node, so the update does not cost a start
   that needs the cluster.
9. **Sealing again after opening another way** (step 5): only on a system the release key
   signed, on the TPM it sealed to before, while the cluster still hands the key out.

Not built here: FIDO2 ("FIDO2"), and TPM plus the cluster's key as the request reads it
("Open").

## What each way leaves open

The four attackers:

- **A copied disk**: a byte-for-byte copy of the disk, made at some moment, without the
  machine.
- **A stolen machine**: the whole machine, taken while off, started as it is or with any
  other system.
- **A taken cluster node**: someone runs one node of the cluster (its store, its
  certificate, what its API answers), not this machine.
- **The host of a virtual TPM**: the machine under a VM whose TPM is swtpm or a cloud's
  virtual TPM. It has the VM's disk, its memory, and the virtual TPM's state.

"Nothing" means that way gives that attacker nothing. Another way may still give them
something: every row stands beside the others, and any one way is enough.

| Way | A copied disk | A stolen machine | A taken cluster node | The host of a virtual TPM |
|---|---|---|---|---|
| The key on the disk | opens | opens | needs nothing from it | opens |
| The cluster's key | opens wherever the copy reaches a node's port, until `kith node lock` | opens where it starts within reach of the cluster, until locked | nothing alone; with a copy of the disk, opens, and no lock stops it (it holds every NodeKey) | opens: it has the disk and the network |
| The recovery key | nothing without the key; with it, opens for good (a new recovery key does not change a copy) | the same | nothing; a taken control node can have a running node make a new one and show it (SECURITY.md), which opens a copy made after | as a copied disk |
| The TPM's seal, today | nothing | opens by itself started as it is, and then only the running system stands between; a probe on a discrete TPM's bus reads the key as it is unsealed | nothing | opens: it holds the virtual TPM's seeds and can set its PCRs |
| A passphrase | guessed offline, without limit, at Argon2id's cost a try | the same | nothing; a node that relayed it when it was given saw it | as a copied disk |
| The seal over the salted session | nothing | as the seal; a probe that only listens reads nothing; one that resets the TPM and replays the measurements still gets the key (not defended); one put in before the seal was made reads everything | nothing | opens |
| TPM plus PIN | nothing | M guesses at once, then one every I seconds: at most 1% of the PINs in a year (the bounds below); a PIN seen as it is typed opens (a camera, or a boot file changed to record it: the boot file is not signed); a TPM whose secrets are read out gives up the PIN's object too | nothing; a node that relayed the PIN when it was set would see it (as built, T-0612, none relays one) | opens: it reads the PIN's object out of the TPM's state |
| A seal for the next system | nothing | as the seal it stands for; and a copy of an older record, written back with the older signed system it was sealed for, opens (no seal can be taken back) | nothing more than today: a seal is made only for a boot file in an update the release key signed, and no node holds that key | opens |
| Sealing again after opening another way | nothing | as the seal | nothing: a node seals again only at a start where a node of the cluster handed its key out | opens |
| FIDO2 (deferred) | nothing | opens with a touch if the key is with the machine | nothing | opens: it reads the VM's memory |
| TPM plus the cluster's key (not built) | nothing, even beside a taken cluster node | opens where it starts within reach of a cluster that hands its key out | nothing, even with a copy of the disk | opens |

Said once for every row:

- **A virtual TPM trusts its host.** The host reads the VM's memory, where the key is while
  the state is open, and the virtual TPM's state, where every seal's secret is. No way here
  keeps anything from it.
- **The recovery key and a copy of the disk open the state**, whatever else is set, for as
  long as that copy exists.
- **A machine taken while it runs** is not defended: its key is in memory.
- **A TPM whose secrets can be read out** (its pins probed, or a firmware TPM faulted, as
  has been published for one maker's firmware TPM; not checked here) gives up everything it
  holds: every seal, and the PIN's object with its lockout.
- **Whoever holds the release key** decides which systems a node runs, and from step 4 which
  it seals for. That is no more than today, where such a system is handed the key by the
  cluster once it starts.
- **Whoever may apply NodeKeys** (an admin, or a taken control node) turns ways on and off:
  a seal, a PIN, a passphrase, a new recovery key. This task does not change who may.
- **The record has no integrity of its own.** Whoever can write the disk can remove lines
  (a way in, the storage key's name) or put back lines from an older copy. They cannot make
  a line that opens anything without the secret it is sealed or wrapped under.

## The TPM, exactly

### What tpm.rs speaks today

tpm.rs writes each command itself to `/dev/tpmrm0`. No library is linked. It has nine:
TPM2_CreatePrimary (0x131), TPM2_Create (0x153), TPM2_Load (0x157), TPM2_Unseal (0x15E),
TPM2_FlushContext (0x165), TPM2_StartAuthSession (0x176), TPM2_PCR_Read (0x17E),
TPM2_PolicyPCR (0x17F) and TPM2_PCR_Extend (0x182). It knows one refusal by name,
TPM_RC_POLICY_FAIL from session 1 (0x99D).

- Authorization is the password session (TPM_RS_PW) with an empty password, for the owner
  hierarchy, TPM2_Load's parent and PCR 15. TPM2_Create runs under an HMAC session and
  TPM2_Unseal under a policy session, each salted to the storage key, AES-128-CFB, with
  HMACs computed and the answer's checked, as "The session" below says (T-0585). The
  storage key's name is computed from its public area and kept on `tpm-parent:`.
- The parent (the storage key): ECC P-256 under the owner hierarchy; restricted, decrypting,
  AES-128-CFB, noDA; made from its template at each use and flushed after, never kept in
  the TPM.
- The sealed object: a KEYEDHASH data object, fixedTPM, fixedParent and noDA, without
  userWithAuth, so only its policy opens it. The policy is TPM2_PolicyPCR over the six PCRs.
  Its digest is computed in kithd: SHA-256 of 32 zero bytes, TPM_CC_PolicyPCR, the
  selection, and SHA-256 of the values that TPM2_PCR_Read gave.
- Its tests (`tpm_gives_a_sealed_key_back_to_the_same_system_only`,
  `tpm_session_carries_no_key_and_checks_each_answer`,
  `tpm_parent_is_checked_before_anything_is_sent`, and crypt.rs's
  `tpm_parent_is_kept_when_an_old_seal_is_sealed_again`) run all of this against swtpm, and `sh ci/vm.sh --test tpm` runs it under OVMF with swtpm as the VM's TPM.

### The PCRs

Unchanged from T-0237: the SHA-256 bank, PCRs 0, 4, 7, 9, 12 and 15.

- 0: the firmware's code. 4: what the firmware started (systemd-boot, then kith OS's boot
  file: kernel, and a command line that names the root by its verity hash). 7: whether
  Secure Boot is on and whose keys it trusts. 9 and 12: a command line or initramfs given
  from outside the boot file. 15: what kithd measures itself before it asks the TPM for
  anything (the node's config partition: name, addresses, kithd's arguments).
- These meanings are the firmware's and the stubs' (the TCG PC Client Platform Firmware
  Profile, and systemd's and the kernel's EFI stubs), not the TPM library's. T-0237's VM
  test shows them on OVMF only: a changed boot file moves 4, a command line given from
  outside moves 9 or 12, a changed config moves 15. On other firmware they are unverified.
- Not 1, 2, 3 or 5 (firmware settings, plugged cards' option ROMs, the boot manager's
  settings and the partition table): they move with things an owner does, and the node
  widens its partitions at its first start. Not 11: systemd's stub measures the boot file's
  sections there (unverified for the stub version kith builds with), which PCR 4 already
  covers as the boot file's hash; PCR 11 becomes the one worth a signed policy only once
  Secure Boot is on ("A seal across a signed update").
- tpm.rs refuses to seal when 0, 4 or 15 holds nothing: a machine that measured nothing
  would open for any system. That stays.

### The session: salted, encrypted, its key's name kept

Decided: every command that carries a secret, or whose answer is one, runs with a session
salted to the storage key, with parameter encryption, and the storage key's name is kept
beside the seal and checked before any salt or secret is sent.

Which key: the storage key kithd already makes as the parent (TPM2_CreatePrimary under the
owner hierarchy, the template above). It is the key every seal lives under, so salting to it
adds no key. Not the endorsement key: its worth is its certificate, which nothing here checks
("Open").

Sealing:

1. TPM2_CreatePrimary as today. From `outPublic`, kithd computes the name itself:
   TPM_ALG_SHA256 (2 bytes) and SHA-256 of the public area. It does not take the name the
   TPM answers.
2. kithd makes an ephemeral P-256 key (`ring::agreement`, already linked), computes Z, the
   x-coordinate of the shared point with the storage key's public point, and the salt as
   KDFe(SHA-256, Z, "SECRET", its own x, the storage key's x, 256 bits) (swtpm accepted it as
   written; Part 1, ECDH secret sharing; Part 3, TPM2_StartAuthSession).
3. TPM2_StartAuthSession: tpmKey the storage key, bind TPM_RH_NULL, a 32-byte random
   nonceCaller, encryptedSalt the ephemeral point (TPMS_ECC_POINT), sessionType HMAC,
   symmetric AES-128-CFB, authHash SHA-256. The session key is KDFa(SHA-256, salt, "ATH",
   nonceTPM, nonceCaller, 256) (swtpm accepted it as written; Part 1, session key).
4. TPM2_PCR_Read and the policy, as today.
5. TPM2_Create, the parent authorized by that session with `decrypt` set: `inSensitive`,
   which holds the key, crosses encrypted. AES-128-CFB, key and IV from KDFa(SHA-256,
   session key, "CFB", nonceCaller, nonceTPM, 256) (swtpm accepted it as written; Part 1,
   parameter encryption). The command's HMAC is over cpHash (the command code, the parent's
   name, the parameters as they cross), the two nonces and the session's attributes. The
   answer's HMAC is checked before anything in it is used (swtpm accepted it as written:
   cpHash and rpHash are taken over the parameters encrypted; Part 1).
6. Both handles flushed. Kept: the blob on `tpm:` (its format unchanged) and the name on
   `tpm-parent:`.

Unsealing:

1. TPM2_CreatePrimary; the name computed as above. If a name is kept and this one differs,
   kithd stops there: no salt is sent and no blob is loaded. The start says "this is not the
   TPM the key was sealed with, or something sits between it and this machine", and the
   node asks the cluster as for any refusal.
2. TPM2_Load under the password session, as today. The blob is already encrypted under the
   parent and holds nothing the bus may not see.
3. TPM2_StartAuthSession as in sealing, but sessionType POLICY. Then TPM2_PolicyPCR.
4. TPM2_Unseal with that session, `encrypt` set and `continueSession` clear: `outData`
   comes back encrypted. The HMAC key is the session key alone, since the session ran no
   PolicyAuthValue (swtpm accepted it as written; Part 1, the HMAC of a policy session
   without one).

A seal made before step 2 has no `tpm-parent:`. It is unsealed through a session salted to
the storage key as the TPM gives it (no name to check), so a probe that only listens reads
nothing from then on. Then the node seals again with the name kept: written, read back and
opened before the old line goes ("Order of writes").

A node seals again by itself only to the TPM it sealed to before: when the name it would
keep differs from the one kept, it does not seal, and says why in the NodeKey's status. A
cleared TPM, or a disk moved to another machine, needs `kith node seal --off` and then
`kith node seal` from the owner.

What the session gives, and what not:

- A probe that only listens on a discrete TPM's bus reads no key, no PIN, and nothing it
  can guess a PIN against offline: the HMAC that proves a PIN is keyed by the session key,
  which it does not have.
- Another TPM in this one's place (a second swtpm in the test) is refused by the name before
  anything is sent.
- An interposer put in later that hands kithd its own key in the storage key's place is
  refused by the name.
- **Someone on the bus when the seal was made is not kept out.** They could have handed
  kithd their own key then. kithd kept that key's name, salts every session to it, and they
  read everything, every start. Only a check of the TPM's endorsement certificate tells a
  real TPM from such a one ("Open").
- An interposer that resets the TPM and replays the measurements from the event log makes
  the PCRs say whatever it likes, and unseals in a session of its own. The session does not
  stop that; nothing in this task does. It is the "TPM whose pins are read" that the
  non-goals and today's docs already name.

### TPM plus PIN

Decided: two objects and a wrap, not one object with both policies.

- **k1**, 32 bytes, sealed as the TPM's seal is: PolicyPCR, noDA. k1 is drawn from the state
  key (HKDF-SHA-256, "kith-lock tpm-pin pcr"), so any node with its state open can make it
  again; it is never stored.
- **k2**, 32 random bytes, sealed under a policy of TPM2_PolicyAuthValue alone (its digest:
  SHA-256 of 32 zero bytes and TPM_CC_PolicyAuthValue, 0x16B). Attributes fixedTPM and
  fixedParent; noDA clear, so every wrong PIN counts; userWithAuth clear, so only a policy
  session opens it. Its authValue is the PIN's digits as ASCII, at most 32 bytes (unverified:
  Part 3, TPM2_Create refuses a userAuth longer than the name algorithm's digest).
- **W**: the state key wrapped (ChaCha20-Poly1305, as `crypt::wrap`) under HKDF-SHA-256 of
  k1 and k2 together.
- The line: `tpm-pin: <k1 blob> <k2 blob> <W>`.

Why two objects: an update, a firmware update or a refused start changes what PCRs the seal
must name, and kithd does not know the PIN then. With k1 apart, kithd seals k1 again for the
new values (step 4, step 5) and leaves k2 and W as they are. One object holding PolicyPCR and
PolicyAuthValue together could be made again only with the PIN typed.

What this gives up against one object: k2 can be tried from another system on the same
machine. The guesses are counted by the same TPM against the same lockout, so the rate does
not change, and k2 alone opens nothing.

At a start:

1. k1 first, from `tpm-pin:` and then `tpm-pin-next:`. No PIN, and no guess counted.
2. If neither k1 opens, no PIN is asked for: "this system is not the one the PIN's seal
   names: the PIN cannot open it here". No PIN is spent on a seal that cannot open.
3. Otherwise the console asks for the PIN beside the recovery key. A line of 6 to 32 digits
   is tried as a PIN, after the recovery key, a duress code and a passphrase have been tried
   (`crypt::judged`). A duress code has the recovery key's shape and is never tried as a PIN.
4. k2: TPM2_StartAuthSession (POLICY, salted as above), TPM2_PolicyAuthValue, then
   TPM2_Unseal with `encrypt` set, the HMAC keyed by the session key and the PIN (unverified:
   Part 1, HMAC key with PolicyAuthValue).
5. A wrong PIN is refused with TPM_RC_AUTH_FAIL (0x98E from session 1) and counted. The
   console answers it as it answers every line that opens nothing. Once the count reaches M,
   every PIN, the right one too, is refused with TPM_RC_LOCKOUT (0x921) until the count falls
   by one every I seconds. The console says that, and when the next try comes, since
   otherwise the right PIN looks wrong (unverified: Part 1, dictionary attack protection; the
   two codes are Part 2 values not yet seen from a TPM here).

The PIN is digits only, typed on the row above the letters. A US layout, which is the
console's, reads digits from those keys whatever their caps say. It is given to the node as a
passphrase is: `kith node pin NAME` asks for it, and it goes over the cluster's TLS to that
node alone, kept by no node, nor by the store or the audit log. The NodeKey says
`seal: "pin"`, which an older kithd reads as "not sealed" ("The lock record").

As built (T-0612): asked of the named node alone, at its own address over TLS. Another node
refuses it and passes it on to none, saying to ask that node itself (whether one may is the
owner's decision, "Open"; the CLI asks the kithd it reaches). The NodeKey is not told `seal: "pin"`: its status
says `"pin": true`, and `seal` stays the owner's word for the TPM alone. A PIN given again
replaces the line (written, read back, opened, as "PIN on"), not beside the old one. The
settings are said when the PIN is set, not again at each start.

### The lockout bounds

When it seals with a PIN, kithd reads the TPM's dictionary-attack settings with
TPM2_GetCapability (0x17A): TPM_CAP_TPM_PROPERTIES (6), from TPM_PT_PERMANENT (0x200), 18
properties. From them: TPMA_PERMANENT's lockoutAuthSet (bit 2) and inLockout (bit 9);
TPM_PT_LOCKOUT_COUNTER (0x20E), the wrong tries counted now; TPM_PT_MAX_AUTH_FAIL (0x20F),
M; TPM_PT_LOCKOUT_INTERVAL (0x210), I, the seconds after which the count falls by one;
TPM_PT_LOCKOUT_RECOVERY (0x211), R, the wait after a wrong lockout authorization
(unverified: the property numbers and bit positions are Part 2 values recalled, not yet read
from a TPM here).

It refuses to seal with a PIN of d digits unless all of these hold:

- 6 ≤ d ≤ 32, digits only.
- M ≥ 1 and I ≥ 1. An I of 0 turns the lockout off (unverified: Part 3,
  TPM2_DictionaryAttackParameters); an M of 0 is refused whatever it means.
- **M + ⌈31,536,000 / I⌉ ≤ 10^d / 100.** The guesses a year allows, the first M at once and
  one every I seconds after, are at most 1% of the PINs there are. With M = 32: a PIN of 6
  digits needs I ≥ 3,164 s (53 minutes), 7 digits I ≥ 316 s, 8 digits I ≥ 32 s, 9 digits
  I ≥ 4 s, 10 or more I ≥ 1 s. A TPM set to M = 32 and I = 7,200 s allows a 6-digit PIN
  4,412 guesses a year: 0.44% of them.
- **kithd holds the lockout authorization.** Where it is empty, which is how a TPM comes,
  anyone who starts another system on the machine can reset the count with
  TPM2_DictionaryAttackLockReset (0x139) and guess M more after every restart (Part 3,
  TPM2_DictionaryAttackLockReset: authorized by lockoutAuth). So where lockoutAuthSet is
  clear, kithd sets it, with TPM2_HierarchyChangeAuth (0x129) on TPM_RH_LOCKOUT
  (0x4000000A): 32 random bytes, sent encrypted in a salted session, kept in a file of the
  state and nowhere else, then read back by lockoutAuthSet. Where it is set, a kept file is
  no proof (a disk moved, a state put back): kithd shows the kept value to the TPM with
  TPM2_DictionaryAttackLockReset in a salted session, which forgives the wrong tries counted
  (it lets nobody try the old PIN, which the new one replaces, and only whoever may apply the
  NodeKey sets one). Where kithd keeps no value, or the TPM refuses it (AUTH_FAIL or
  BAD_AUTH), someone else holds it: kithd refuses ("clear the TPM in the firmware's settings
  first"). A TPM whose lockout hierarchy is shut by an earlier wrong value (TPM_RC_LOCKOUT)
  is told as a wait of its recovery time, and any other failure as itself; each refuses the
  PIN.

The refusal says which bound failed and the shortest PIN this TPM's M and I would take.
kithd does not change M or I itself ("Open"). R is read and said, not bounded: only kithd
holds the lockout authorization, and 32 random bytes are not guessed.

The number of wrong PINs before the right one is refused is M less the count at that moment.
It is said when the PIN is set ("this TPM refuses every PIN after M wrong ones, and allows
one more every I seconds"). The bound holds for random digits only: a date or 123456 is
among the first guesses. Each setting of a PIN tries one wrong PIN, which the TPM counts, to
learn that the TPM counts at all.

Where kithd took the lockout authorization, it keeps it only in this node's encrypted state.
If that state is lost (wiped, or its key erased by a duress code), only clearing the TPM in
the firmware's settings gives it back. The owner decides this knowingly: `--untried-tpm`'s
help and the refusal without it say so. The flag is the owner's word, not a lock: whoever
may apply a NodeKey at the node can send it.

Unverified, and in the owner's checklist: whether a TPM restarted after a shutdown that was
not orderly counts that as a wrong try (Part 1, dictionary attack protection), so that a
machine that loses power often spends its tries; and whether the count falls only while the
TPM has power. The bound above assumes an attacker keeps the machine on all year.

What it costs whoever is not the owner: anyone at the console can type M wrong PINs and lock
the PIN for a while. The TPM's seal, the cluster and the recovery key are other ways, and
the TPM's seal (noDA) is not under the lockout. Whoever runs their own system on the machine
can also set the owner hierarchy's authorization, and from then on the TPM gives kithd
nothing: a refusal, not a key.

A duress code erases the record and so the PIN's objects. The lockout authorization was kept
in the state, which nothing opens any more: the TPM's lockout hierarchy then answers nobody
until the TPM is cleared from the firmware's settings. The count of wrong tries still falls
by itself.

### A seal across a signed update

Three ways were weighed.

**A. TPM2_PolicyAuthorize, with a PCR policy signed at release time.** The seal's policy
names a signing key; the release tooling signs the PCR values each release will produce, and
a node shows the TPM that signature (TPM2_LoadExternal, TPM2_VerifySignature, then
TPM2_PolicyAuthorize). Why not now:

- PCR 4 cannot be signed at release time. It holds the firmware's own events before
  systemd-boot's and the boot file's, and those differ from machine to machine (unverified in
  general; on OVMF the VM test's event log shows them).
- What can be signed at release time is PCR 11, the boot file's sections as systemd's stub
  measures them. But with Secure Boot off, as on kith OS today, anything the firmware starts
  can extend PCR 11 with the signed values and then start another kernel. PCR 11 means
  something only when Secure Boot keeps the stub from being replaced (PCR 7), or when PCR 4
  is sealed too, which brings back the per-machine values.
- The cluster's release key is Ed25519 (`os/update.sh --sign`, `kith_packages::artifact`).
  TPMs verify RSA and ECDSA. Whether any TPM in the field verifies Ed25519 is unverified,
  and it is not counted on. So A would need a second release key, P-256, endorsed by the
  first, with its own handover.
- An approved policy cannot be taken back: an older signed release's values keep opening.

**B. Seal again for the new system before the restart (chosen).** The update path verifies
the header's signature and writes the other slot (`os::install`). Then kithd computes the
PCRs the new boot file will give on this machine, seals the key to them as `tpm-next:` (k1 as
`tpm-pin-next:` in PIN mode), and keeps `tpm:` as it is.

**Both.** B now. A once Secure Boot signing of the boot file exists (its own task), so a node
can take an update it could not predict. That is not built here.

Why B: A cannot bind anything on kith OS while its boot file is not signed for Secure Boot,
and it needs a second release key the TPM can verify. B needs no new TPM command: the policy
digest is computed in kithd from values, as tpm.rs does today. B keeps the running system's
seal untouched until the new system has opened the state once, so a wrong prediction costs a
start that goes back by itself, not a lockout.

How the new values are predicted (no TPM command; about 190 lines):

1. The event log, as the kernel gives it (`/sys/kernel/security/tpm0/binary_bios_measurements`
   with securityfs mounted; unverified that kith OS's kernel configuration exposes it), is
   read in the TCG's crypto-agile format, SHA-256 digests.
2. The log is replayed for the sealed PCRs, PCR 15 being kithd's one extend. If that replay
   is not what TPM2_PCR_Read gives, nothing is predicted ("the event log does not explain
   this start").
3. Each event of a sealed PCR whose digest kithd can make from the boot file that runs is
   made again from the new one: PCR 4's event for the boot file (its PE Authenticode hash,
   as the firmware measures an application it starts; unverified beyond OVMF) and, where
   there is one, the event for the boot file's own command line (the kernel's EFI stub
   measures what it was started with into PCR 9 on recent kernels: unverified). For the
   command line, kithd tries SHA-256 of the running boot file's `.cmdline` as UTF-16 and as
   UTF-8, with and without an ending zero, and uses for the new one the form that matched.
   Every other event is kept as it is.
4. The new boot file is read back from the ESP after it was written. Its SHA-256 must be the
   one the signed header names for that slot, or nothing is predicted.

What a system the release key did not sign gets:

- Never a `tpm-next:`. Only the signed update path makes one, after `os::signed` has checked
  the header and the piece's hash has been checked against it. An update from a stick
  (`kith.update=`) is not signed and is never sealed for.
- At its start PCR 4 differs from both seals: the TPM refuses, and the node asks the cluster
  or the console as today.
- Once open by another way, it does not seal itself (step 5's checks).
- `tpm:` stays, for the system that ran before.

How the old seal is kept until the new system has opened the state once:

- `tpm:` is not touched by the update. At each start both `tpm:` and `tpm-next:` are tried.
- **Today a slot is marked good 10 seconds after kithd starts** (`init::Boot::network`), and
  on an encrypted node that is before the state is open (main.rs starts the network before
  `crypt::open`). A new system that cannot open the state is then marked good while it
  waits, and the boot loader never goes back. Decided: on every node whose state is
  encrypted, sealed or not, the slot is marked good once the state is open and those 10
  seconds have passed. That is a fault of today's code whatever this task builds, and is
  fixed as its own task before step 4 ("Review").
- Once the new slot is good, kithd writes `tpm:` with what `tpm-next:` held, drops
  `tpm-next:`, and reads the record back: one write. A start in between still has both lines,
  and either opens.

How a seal that does not open is undone with nobody at the node:

- On a slot still on trial (its boot file still counts tries on the ESP, os.rs), when the
  record holds a seal and none of its seals opened, kithd waits five minutes for the cluster
  or the console. A line typed at the console starts the five minutes again. Then it ends the
  start as failed (`init::end(true)`).
- The boot loader counted that start down. After three, it starts the slot that is marked
  good, the system that ran, whose PCRs are the ones `tpm:` was sealed to: the state opens
  there with nobody at the node. About seventeen minutes in all (estimate).
- That system's kithd drops `tpm-next:` and says, as `os::settle` does today, that the other
  slot did not come up. The update plan pauses as it does for any node that did not come up
  (update.rs).
- Without a seal the five-minute wait does not apply: going back would open nothing more.
  The node waits on its peers for as long as it takes, and a slot on trial stays on trial
  while it does. So **whoever can keep such a node from its peers and restart it three
  times puts it back on the system it ran before**: a signed system, the one it ran until
  the update, with whatever that update mended not mended. The release floor does not stop
  it (the floor is read by a running kithd, and the boot loader reads nothing). It is kept,
  because the other choice leaves a node whose new system cannot reach its peers down until
  someone comes; the update plan sees the node on the old version and pauses. Whether such a
  node should hold on the trial slot instead is the owner's ("Open").

As built (T-0860): after `os::signed` and the slot's hash check, `update::fetch` hands the two
boot files (read back from the ESP; the new one proven to be the piece the header named) to
`crypt::ahead`, only for a release signed by a key `Keys::mine` held before it, never under
`allowDowngrade`, never from a stick. The prediction needs the running log's PCR 9 event to
match one of the four command-line forms, or it seals nothing; a failure is logged and the
update stands. One seal ahead at a time: while a `tpm-next:` that opens on this system waits
for promotion, none is made; one the TPM refuses on its PCR policy (a fallback left it) is
replaced, and `tpm:` is untouched. Any other failure to try it (a device error, a busy TPM, a
cut seal) keeps it and refuses the seal ahead for now: the next update or wake retries. `crypt::keep` promotes (`tpm:` takes `tpm-next:`, which goes, in one read-back
write) once `os::GOOD`, and only if the new seal opens to the key held; a failed try is made
again at a later wake, three times. The wait is `open`'s, five minutes, restarted by a
typed line. Not built: dropping `tpm-next:` when the old slot runs again after a fallback.
- A PIN node needs a person either way. With a person there, the PIN opens the new system
  when the prediction held; when it did not, k1 is refused, no PIN is asked for, and the five
  minutes lead back to the old system, where the PIN opens.

### Sealing again after opening another way

A node that opened with the recovery key, a passphrase or the cluster's key seals again by
itself only when all of these hold. Otherwise it stays unsealed and the NodeKey's status says
which one failed:

1. The NodeKey says `seal` (or `seal: "pin"`), and is not locked or forgotten. This is today's
   check.
2. A node of the cluster handed this disk's key out at this start: the node opened by the
   cluster, or kithd asks one node at `POST /v1/unlock` and is answered. The local store alone
   may be old: a node that was away does not know it was locked.
3. The system that runs is one the release key signed. The state holds, for each slot the
   update path wrote, the signed header, its signature and the key that signed it. The
   signature verifies under a key this node takes releases from (its kept keys, or those
   they replaced). The header's piece for this slot is the SHA-256 of the boot file this slot
   started. And the prediction for that boot file from this start's event log is the PCRs the
   TPM reads now.
4. The storage key's name is the one kept, if one was kept ("The session").

In PIN mode only k1 is sealed again: it is drawn from the state key, and k2 and W stay.

A node with no release key never seals again by itself. `kith node seal --off` and then
`kith node seal` seal it for what runs, on the owner's word, as today. A node with release
keys never seals a system they did not sign, on anyone's word: a freshly installed node,
whose system came from the installer with no signed header, seals after its first signed
update ("Open").

### What each piece needs

Lines are rough: code and tests, from tpm.rs's own size (about 300 lines for nine commands).

| Piece | TPM commands | Other code | Lines |
|---|---|---|---|
| Session (step 2) | none new; TPM2_StartAuthSession salted, TPM2_Create and TPM2_Unseal with a session | ECDH P-256 (ring), KDFa, KDFe, names, cpHash and rpHash, HMAC (ring), AES-128-CFB (the `aes` crate's block cipher, CFB by hand), `tpm-parent:` | 220 and 120 |
| PIN (step 3) | TPM2_GetCapability, TPM2_PolicyAuthValue, TPM2_HierarchyChangeAuth; tests add TPM2_DictionaryAttackParameters (0x13A) and TPM2_DictionaryAttackLockReset | bounds, k1, k2 and W, the console, `kith node pin` and its route, `seal: "pin"` | 250 and 180 |
| Seal across an update (step 4) | none new | event log and replay, Authenticode, prediction, `tpm-next:` and promotion, a slot good only once the state is open, the five-minute wait, the update's hook into `crypt::keep`, signed headers kept | 350 and 250 |
| Sealing again (step 5) | none new | the four checks, the NodeKey's status | 70 and 100 |

About 900 lines of code and 650 of tests. One new dependency, `aes` (RustCrypto, the block
cipher alone), for the session's CFB: ring has no raw AES. kithd's size grows by an estimated
60 to 120 kB against its budget of 13.00 MB, from 11.35 MB measured (docs/numbers.json). That
is an estimate: no build was made for this record. `python3 ci/budgets.py` measures it at
each step.

## FIDO2: deferred

What it would take, with no libfido2: CTAPHID over `/dev/hidraw*` (initialization, channels,
64-byte reports, keep-alives), a CBOR subset written here, CTAP2's getInfo, clientPIN
getKeyAgreement (ECDH P-256, which ring has), makeCredential with hmac-secret to enroll each
of two keys, and getAssertion with hmac-secret at the console, its salts encrypted with
AES-256-CBC (PIN protocol 1 or 2). Then the record's lines, the console's "touch your key",
and verbs to enroll and remove. About 850 lines and the `cbc` crate on top of `aes`; an
estimated 100 to 200 kB of kithd. The size would fit the budget.

Deferred, for reasons other than size:

- Nothing here can test it. QEMU's emulated security key speaks U2F, not CTAP2 (unverified),
  so the tests would first need a software authenticator behind uhid, about as large as the
  client.
- The kernel's configuration names neither CONFIG_HIDRAW nor CONFIG_USB_HID (whether
  x86_64_defconfig gives them is unverified).
- Two keys enrolled is the request's guard against losing one. That needs an enrollment flow
  at a running node's console that nothing else here has.
- For a person at the console, TPM plus PIN covers most of what a touch would.

Captured as its own task at step 5. Until it is built, README and SECURITY.md say that it is
not (criterion 5).

## Rivals

1. **Delegate to systemd and LUKS2** (systemd-cryptenroll with `--tpm2-with-pin`,
   `--tpm2-public-key`, `--fido2-device`). kith OS ships no systemd, cryptsetup or LUKS
   header, and a new disk format is a non-goal.
2. **PolicyAuthorize with a release-signed policy** (A above). It binds nothing while the boot
   file is not signed for Secure Boot, and needs a release key the TPM can verify.
3. **PolicyAuthorize with a key the node holds in its state**, signing its own predicted
   policies. It needs the same prediction as B, plus three commands (TPM2_LoadExternal,
   TPM2_VerifySignature, TPM2_PolicyAuthorize) and ECDSA signing. Its approvals can no more be
   taken back than a blob can. It buys not rewriting a blob, and the PIN's two objects already
   avoid needing the PIN to seal again.
4. **The PIN in an NV index, with TPM2_PolicySecret.** One PIN object and many seals. It costs
   NV space, TPM2_NV_DefineSpace and TPM2_NV_UndefineSpace, and an index that outlives a wiped
   disk. The two objects need none of that.
5. **One object with PolicyPCR and PolicyAuthValue.** Smallest at the TPM. It cannot be sealed
   again without the PIN, so every update or firmware change costs a PIN node a start that
   needs the cluster or the recovery key.
6. **XOR parameter obfuscation instead of AES-128-CFB** (Part 1). No new dependency; the mask
   is KDFa's output, fresh for each command. Not taken because whether TPMs in the field
   accept TPM_ALG_XOR as a session's cipher is unverified, while AES-128-CFB is what the
   common TPM stacks use. A TPM that refused it would refuse every seal.
7. **Check the endorsement key's certificate** and salt to the endorsement key. It keeps out
   an interposer present at the first seal. It needs TPM vendors' CA certificates in the image
   and reading the certificate from NV. Not now ("Open").
8. **Do less: the session and this record only** (the brief's option 3). PIN and the update
   seal captured. Not taken: every update costs a sealed node a start that needs the cluster,
   which today's docs tell owners to expect, and two locks are the first "Not yet" of the
   README's encrypted state.

## The lock record

New lines, each read the way `passphrase:` is: a line that cannot be read opens nothing and
never makes the record "damaged".

| Line | What |
|---|---|
| `tpm-parent: <hex>` | the storage key's name when the seals were made (34 bytes) |
| `tpm-next: <hex>` | the key sealed for the next system, until that system's slot is good |
| `tpm-pin: <hex> <hex> <hex>` | k1's blob, k2's blob, W |
| `tpm-pin-next: <hex>` | k1 sealed for the next system |

Older kithd (a node gone back to its other slot, or taken down by an `allowDowngrade` plan):

- It reads `secret:`, `recovery:`, `key:` and `tpm:` with `?` (`Record::parse`): one of those
  that does not parse makes the whole record "damaged", and the node does not start. So
  **no existing line changes its format.** `tpm:` keeps its blob as it is; a seal made through
  a session is the same blob.
- It ignores lines it does not know when it reads, and drops them at its next write: a node
  taken back to it loses `tpm-pin:` and `tpm-next:`. The recovery key and the cluster still
  open it, and this is said in the docs.
- It reads NodeKey `seal: "pin"` as not sealed (it asks `== true`), so it never makes a
  TPM-alone seal where the owner chose a PIN.

Room: 4 KiB, `peers:` last. `Record::write` cut whatever did not fit from the end,
silently. With the new lines the record could exceed that, and a seal line cut in half is a
record that does not parse. Decided, and built (T-0585): a write that would cut anything but
whole entries of `peers:` is refused, naming the line it would cut. Estimated: the lines other than `peers:` stay under 3.1 kB in either mode.
A sealed blob made through the session is 272 bytes on swtpm (T-0585), not the 200 first
estimated: 144 more hex characters a blob, at most three blobs in a mode, so 2.6 kB became
3.1 kB.

## Order of writes

Every change here can lock a node out of its own disk. The rules:

1. Every write is the whole record, synced, read back past the page cache, and compared.
   That is `Record::write` today.
2. **A new way is written, read back, and opened once from what was read back before any old
   line is removed.** For the TPM that means an unseal through the session; for a PIN, an
   unseal of k1 and of k2 with the PIN the request carried, and W unwrapped to the key.
3. **The recovery key's line is never removed or changed by this task.** Only
   `kith node recovery`, as today, changes it.
4. Nothing is removed while it is the only way that opened this start, except by lock, wipe or
   duress, as today.

The changes, in that order:

- **Session (first start of step 2's kithd on a sealed node):** unseal `tpm:` through a
  session with no name to check; seal through a session; write `tpm:` (new blob) and
  `tpm-parent:` in one write; read back; unseal the new blob through a session with the name
  checked. If that fails, write the old blob back and say why.
- **PIN on:** check the bounds and take the lockout authorization (its file in the state is
  written before TPM2_HierarchyChangeAuth, so a value the TPM took is never one kithd lost);
  write `tpm-pin:` in place of `tpm:` in one write; read back; open it. One write, so no
  record ever opens by the TPM alone while the status says a PIN guards it; a record read
  with both lines (an older kithd's) drops `tpm:`. If the read-back does not open, the old
  record is written back.
- **PIN changed:** a new k2 and W beside the old line; read back; open with the new PIN; then
  the old line goes. **PIN off:** `tpm-pin:` goes, and `tpm:` comes only if the NodeKey says
  `seal: true`, written and opened before.
- **Update:** `tpm-next:` is added, and nothing is removed. After the new slot is good,
  `tpm-next:` becomes `tpm:` in one write.
- **Going back:** the old system's kithd drops `tpm-next:`, and `tpm:` is what opened it.
- **Sealing again:** the new `tpm:` (or k1 on `tpm-pin:`) replaces one that did not open this
  start. Written, read back, opened.
- **Lock, wipe, forgotten:** every seal line goes, as `tpm:` and `passphrase:` do today.

What no order fixes: **the record is one 4 KiB write**, so a power cut in the middle of one
may leave it unreadable, and the recovery key's wrapped copy is in it. That is so today; this
task adds a few writes (a seal, an update, a promotion). Whether a 4 KiB aligned write is whole
after a power cut depends on the disk (unverified). A second copy of the record would close it,
but a duress code and an older kithd would then have two copies to keep in step ("Open").

## Steps, in order

1. This record, and its security review. No code.
2. The session: it changes no policy and closes a stated gap.
3. TPM plus PIN, on top of the session (a PIN without a salted session can be guessed offline
   by whoever listens on the bus).
4. The seal across a signed update, with a slot marked good only once the state is open and
   the five-minute wait.
5. Sealing again after opening another way; README and SECURITY.md (criterion 5); FIDO2 and
   the "Open" items that are tasks captured.

## Tests

All against swtpm, in VMs on disk files. None on a real TPM, a real FIDO2 key or a real disk.

`cargo test -q -p kithd --bin kithd`, against swtpm as tpm.rs's test starts it:

- `tpm_session...` (criterion 3): the stream to swtpm is wrapped in one that records every byte
  both ways. Seal and unseal; no 8-byte window of the key appears anywhere in what was
  recorded. `tpm-parent:` is the name computed from `outPublic`. A second swtpm, with its own
  state, in the first one's place is refused by the name, and the recording shows no TPM2_Load
  sent to it. A proxy that swaps the storage key's public point in TPM2_CreatePrimary's answer
  is refused the same way. A seal made the old way (no name) still opens, and is sealed again
  with a name.
- `tpm_pin...` (criterion 2): the test sets M and I with TPM2_DictionaryAttackParameters
  before kithd takes the lockout authorization. Loose settings are refused for 6 digits and
  taken for a longer PIN, as the bounds say. kithd sets lockoutAuth where it was empty, and
  lockoutAuthSet reads back. The right PIN opens. M wrong PINs, and the right one is refused
  with TPM_RC_LOCKOUT. TPM2_DictionaryAttackLockReset with the lockout authorization kithd
  kept, and the right one opens. k1 refused (a PCR moved) means no PIN tried and no count
  spent.
- `tpm_predict...`: Authenticode of a small PE made in the test, and of a boot file built the
  way `os/build.sh` builds one. A log of events made in the test, replayed, equals what swtpm
  reads after the same extends. The prediction for a changed boot file equals the PCRs after
  extending with the new digest.
- `seals_again...` (criterion 6): opened by the recovery key on a system with no signed header,
  no seal, and the status says why. With a signed header whose hash matches and a node that
  answers, a seal. With a node that refuses (locked), none. With another storage key's name,
  none.

`sh ci/vm.sh --test tpm` (OVMF and swtpm, real firmware events, VM disk files):

- Today's flow, through the session.
- PIN (as built, T-0612): an 8-digit PIN refused through the other node, then set at
  the node's own address; refused without `untried` and refused at 4 digits; swtpm's own settings (M = 3, I = R = 1,000 s) taken. The
  record reads `tpm-pin:` and no `tpm:`; the PIN is in no disk file and no log. Started with no
  network, the PIN typed on the serial console opens it. Started again, wrong PINs until the
  TPM refuses every one, then the right one refused, the console saying when the next is taken;
  the recovery key opens it. (Waiting out I is left to the unit test, at I = 40 s, and to the
  owner's checklist.)
- Update (criterion 4): two releases built with different versions, signed by a test release
  key. The node takes the second with its peers off. It restarts and opens by `tpm-next:` with
  no node asked, and `tpm:` holds the new seal once the slot is good. Then a third release,
  with QEMU's `-no-reboot` so the restart after writing it powers the VM off. The test flips one
  byte of `tpm-next:` in the disk file, then starts the VM with the peers still off. The new
  slot fails three times, the old one starts, and the state opens with nothing typed.
- An unsigned update from a stick: no `tpm-next:`, and the trial wait leads back.
- Every VM test ends by opening the disk with its recovery key.

## On hardware: the owner's checklist

Nothing below has been run. For each machine, note whether its TPM is discrete or firmware.

1. `kith node seal`; restart; it opens with no node asked. The record has `tpm-parent:`.
2. Move the disk to another machine with a TPM: refused by the name, said at the console. Then
   the recovery key opens it.
3. Optional, with a logic analyzer on a discrete TPM's bus: record a start, and search it for
   the key.
4. `kith node pin` with 6 digits: note the M, I and R it reports, and whether it refused; note
   whether the lockout authorization was empty. Restart, type the PIN, open.
5. Wrong PINs until the right one is refused; wait I seconds; the right one opens.
6. Cut the power at the PIN prompt three times; read the count of wrong tries
   (TPM_PT_LOCKOUT_COUNTER, as kithd says it) before and after.
7. Take a signed update with the network cable out; it opens by the TPM after the restart. The
   record's `tpm-next:` becomes `tpm:` once the slot is good.
8. From another system, flip one byte of the `tpm-next:` line before the restart (the record
   is at 512 KiB into the config partition). With the cable out, the machine is back on the old
   slot and open within about twenty minutes.
9. Update the firmware: both seals are refused; the cluster or the recovery key opens; the node
   seals again by itself on a signed system.
10. Clear the TPM in the firmware's settings: refused by the name; `kith node seal --off` then
    `kith node seal` seals it again.
11. End each by opening with the recovery key.

## Unverified

Claims this record makes that tpm.rs does not exercise against swtpm today, by command and
part of the TPM 2.0 library specification. The tests of steps 2 to 4 settle the first eleven
on swtpm. None is settled on hardware by this task.

Items 1 to 5 and 19 are settled on swtpm by step 2 (T-0585); they stay listed, as no hardware
TPM has run them.

Items 6, 7, 9, 10 and 11 are settled on swtpm by step 3 (T-0612), as
`tpm_pin_opens_with_its_pin_and_counts_each_wrong_one` runs them: a wrong PIN is refused with 0x98E and counted, the M-th locks every PIN out with
0x921, the properties read back as set (swtpm's own, unset: M = 3, I = R = 1,000 s), the
lockout authorization is taken encrypted where empty, and that authorization, not an empty one,
resets the count. Item 8 is not: kithd refuses an M or an I of 0 before the TPM is asked.

1. TPM2_StartAuthSession (Part 3) with an ECC tpmKey: the salt is KDFe(SHA-256, Z, "SECRET",
   the caller's x, the key's x) (Part 1, ECDH secret sharing). swtpm accepted it as written.
2. The session key is KDFa(SHA-256, salt, "ATH", nonceTPM, nonceCaller) (Part 1). swtpm
   accepted it as written.
3. AES-128-CFB parameter encryption takes its key and IV from KDFa(…, "CFB", nonceNewer,
   nonceOlder) (Part 1). swtpm accepted it as written, both ways (TPM2_Create's
   `inSensitive` in, TPM2_Unseal's `outData` out).
4. cpHash and rpHash are taken over the parameters as they cross, encrypted (Part 1). swtpm
   accepted it as written; a changed byte of an answer fails its HMAC.
5. TPM2_Unseal with a salted policy session that ran no TPM2_PolicyAuthValue: the HMAC is keyed
   by the session key alone (Part 1). swtpm accepted it as written.
6. TPM2_PolicyAuthValue (Part 3): the HMAC is keyed by the session key and the object's
   authValue; a wrong one on an object without noDA counts against the lockout (Part 1,
   dictionary attack protection).
7. TPM2_GetCapability (Part 3): the property numbers 0x200 and 0x20E to 0x211, and
   TPMA_PERMANENT's bits 2 (lockoutAuthSet) and 9 (inLockout) (Part 2).
8. TPM2_DictionaryAttackParameters (Part 3): an I of 0 turns the lockout off; what an M of 0
   does.
9. TPM2_HierarchyChangeAuth on TPM_RH_LOCKOUT with an empty lockout authorization, its newAuth
   encrypted (Part 3).
10. TPM2_DictionaryAttackLockReset authorized by an empty lockoutAuth resets the count (Part 3).
11. The codes not yet sent or received by kith: 0x17A, 0x16B, 0x129, 0x13A, 0x139,
    TPM_RC_LOCKOUT 0x921, TPM_RC_AUTH_FAIL 0x98E (Part 2). A wrong command code is refused by
    swtpm at once, so a test catches it.
12. A TPM restarted after a shutdown that was not orderly counts a wrong try; the count falls
    only while the TPM has power (Part 1, dictionary attack protection).
13. TPMs in the field accept AES-128-CFB as a session's cipher; and whether they accept XOR.
14. No TPM in the field verifies Ed25519 (TPM_ALG_EDDSA) for TPM2_VerifySignature or
    TPM2_PolicyAuthorize.
15. TPM2_Create refuses a userAuth longer than the name algorithm's digest (Part 3).
16. Firmware measures an application it starts into PCR 4 as its Authenticode hash, and PCR 4
    holds machine-specific events before the boot loader's (TCG PC Client Platform Firmware
    Profile; beyond OVMF).
17. systemd's stub, as kith builds with it, measures the boot file's sections into PCR 11 and
    an outside command line into PCR 12; the kernel's EFI stub measures its command line into
    PCR 9.
18. kith OS's kernel exposes the event log (securityfs, `binary_bios_measurements`), the events
    before ExitBootServices included.
19. A sealed blob is about 200 bytes. swtpm made it 272 ("The lock record" uses that).
20. QEMU's emulated security key speaks U2F only; the kernel's merged configuration lacks
    CONFIG_HIDRAW and CONFIG_USB_HID.
21. A 4 KiB aligned write is whole after a power cut (depends on the disk).
22. One maker's firmware TPM has had its secrets read out by faulting it (published; not
    checked here).

## Open

Decisions that are the owner's:

- **TPM plus the cluster's key, as the request reads it**: the cluster's way needing the TPM
  too, so that a copy of the disk with a taken cluster node, or with reach to the cluster,
  opens nothing. The cost: a board swap or a cleared TPM needs the recovery key. Not in this
  task's criteria, which take the cluster's key as it is.
- **The lockout bounds**: at most 1% of the PINs in a year, M ≥ 1, I ≥ 1. Stricter or looser
  is the owner's call.
- **Whether kithd may take the TPM's lockout authorization** (and keep it in the state), as
  decided above. Without it the PIN is refused on nearly every TPM, as they come with it empty.
- **Whether kithd should set M and I itself**, since it holds the lockout authorization, where
  a TPM's are too loose for the PIN given. Today it refuses and names a longer PIN.
- **The trial wait**: five minutes before a new system that could not open the state gives way.
- **Whether the installer should take the signature of the image's update**, so that a freshly
  installed node counts as signed and seals before its first update.
- **The `aes` crate**, a new dependency, for the session's AES-128-CFB, and later FIDO2's CBC.
  Taken at step 2 (T-0585): `aes` 0.9, the block cipher alone, CFB written in tpm.rs; kithd
  grew by 16 KiB (12,026,656 to 12,043,040 bytes, musl release).
- **FIDO2**: built as its own task, with a software authenticator for its tests.
- **A second copy of the lock record** against a torn write, and what a duress code and an
  older kithd then do with it.
- **Taking back old seals**: a copy of an older record opens under the older signed system it
  was sealed for, on that machine, until the TPM is cleared. TPM2_PolicyNV with a counter
  would end that, at the cost of NV space and more commands.
- **The endorsement key's certificate**, to keep out an interposer present at the first seal.
- **The recovery key turned off**, and **the disk's secret kept in the TPM**: both in the
  request, neither here. This task never removes the recovery key.
- **The measured size**: step 1 asked for FIDO2's measured size. No build was made for this
  record (the machine was loaded), so every size here is an estimate until a step measures it.
- **The lockout authorization after a duress wipe**: it was in the state, so nobody holds it.
  The owner clears the TPM in the firmware's settings before a PIN can be set there again.
  Whether kithd should keep a copy with the cluster instead is not decided.
- **Whether the cluster's key may open a PIN node's copy of the disk.** As built it may: the
  cluster's way is as it is, and a PIN adds a way, it closes none.
- **Whether `kith node pin` may be asked through a relay node**, or only of the node itself.
  As built (T-0612): only of the node itself; a relayed PIN is refused until the owner says
  otherwise (a relay would see the PIN in plain, though it could already hand out the node's
  key). Passing it on as `kith node passphrase` is passed would be a few lines.
- **A node with no seal put back by three restarts** ("A seal across a signed update"): the
  old system, or held on the trial slot until someone comes.
- **What a plan with `allowDowngrade` does to `tpm-next:`.** Until decided: nothing is
  sealed ahead for a system older than the floor, and the node asks the cluster after such
  a downgrade.

## Review

One security review of this record, checked against the code and tpm.rs (research
T-0189-adr-review). Verdict: sound with conditions; two gaps unsound as first written. Each
finding and what was decided. The seven conditions bind whoever builds steps 2 to 5; where
the text above says otherwise, this section holds.

| Finding | Decided |
|---|---|
| High: a node that keeps no release key yet takes the first release's key from whoever applies it (`Keys::refused` answers yes where none is kept), and step 4 would seal `tpm-next:` for that system, the PIN's object included | Step 4 seals ahead only for a release signed by a key the node held before that release: given where kithd is started, the image's, or kept from an earlier update. A node on first-release trust seals nothing ahead and says so; it asks the cluster after that update (condition 1) |
| High: a slot is marked good 10 seconds after kithd starts, before an encrypted state is open (confirmed: `main.rs` starts the network before `crypt::open`). The fix as first written left a node with no seal out | Good waits for the open state on every encrypted node. A node with no seal can then be put back by three restarts while it is kept from its peers: said in "A seal across a signed update" and to be said in SECURITY.md; which of the two the owner wants is in "Open" (condition 4). The fault in today's code is its own task, fixed first |
| Medium: whoever can write the lock record can drop `tpm-parent:`, and the record without it is opened with no check of which key the TPM answered with | Once a record holds any of `tpm-parent:`, `tpm-pin:` or `tpm-next:`, a `tpm:` seal without `tpm-parent:` is refused, not opened the old way; a record of the old form is opened as today with a line saying its session is not checked (condition 3). What the kept name is worth, plainly: the record is on the disk outside the encryption, so it stops an interposer who cannot write the disk. One who can write both the bus and the record puts in its own key's name and reads the key. Listening alone gets nothing either way |
| Medium: the release floor gates what an update installs, not what the loader starts, and step 5's third check tested no version | Steps 4 and 5 both need the signed header's version at or above the node's floor: nothing is sealed ahead for an older system, and an older system that opened another way does not seal itself (condition 2) |
| Medium: the "1% a year" bound rests on claims 6, 8, 10 and 12 and on the machine having power all year; the lockout authorization is lost with a duress wipe | The bound is worded as what the TPM's own settings allow if the TPM counts as its specification says. Setting a PIN tries it on that TPM: after sealing, kithd makes one wrong try and reads the count go up by one; a TPM whose count does not move gets no PIN. That shows claim 6 on the machine itself, at the cost of one try. Claim 10 is not tried there (a wrong lockout authorization shuts that hierarchy for R): lockoutAuthSet is read back after it is set, as above. Claim 8 needs no showing: an I or an M below 1 is refused. Claim 12 cannot be tried by kithd and stays in the owner's checklist; README and SECURITY.md say the PIN has run against a software TPM only until an owner has run the checklist (condition 5) |
| Low: the PIN's lifetime was not said | Read from the console with echo off, never an argument, never in a log, a status or a line handed to `judged`; held in one buffer that is zeroed once the TPM has answered (condition 6) |
| Low: one malformed line of a known kind makes the whole record damaged, so a flipped byte in `tpm-next:` would cost the seal that still holds | `tpm-next:`, `tpm-pin:` and `tpm-parent:` are read as `passphrase:` is: a line that does not parse is left out and said, the rest of the record stands. A `tpm-parent:` that does not parse counts as present for condition 3 (condition 7) |

Decided without being asked, and said here so that they are not found later:

- The storage key is made with TPM2_CreatePrimary under an empty owner authorization, as
  tpm.rs does today. Whoever runs another system on the machine can make the same key; the
  seal's policy, not the key, is what keeps them out.
- Seals without a PIN are noDA: wrong tries against them do not count, because their policy
  holds no secret to guess.
- The recovery key is a way back in every case this record covers.

Also found: tpm.rs's own comment, the README and SECURITY.md said the key crosses the bus in
plain. They changed with step 2 (T-0585).

## What the plan review and the rival plan raised

- *The choice of update seal made before the record* (HIGH): made here, after weighing A, B and
  both ("A seal across a signed update").
- *Sealing again before the restart has no rollback in the field* (HIGH): the running system's
  seal is kept; a slot is good only once the state is open; the five-minute wait sends a new
  system that cannot open back to the old one with nobody there.
- *What the session test asserts, and the salt key unauthenticated* (MEDIUM): the key's bytes
  are absent from the recorded traffic, and the name is kept and checked. The endorsement key
  is not checked: "Open".
- *swtpm's lockout is not hardware's; short PINs are weak* (MEDIUM): kithd reads the TPM's own
  settings and holds the PIN to them, takes the lockout authorization so the count cannot be
  reset from another system, and the hardware checklist counts tries. Hardware counting
  remains untried.
- *Sealing again blesses an unknown system* (MEDIUM): a node seals again only on a system the
  release key signed, whose prediction the TPM's PCRs bear out, on the same TPM, while the
  cluster hands out its key.
- *FIDO2's size unchecked* (LOW): estimated, not measured ("Open").
- *Update lockout from raw PCR values* (rival): the next system is sealed for before the
  restart, and the old seal kept.
- *Lockout by removing the last way* (rival): the recovery key is never removed by this task,
  and every new way is opened once before an old one goes. Turning the recovery key off is
  not built.
- *Sealing again without checking the boot state; the cluster's key cached on the disk*
  (rival): the first is the four checks of step 5. The second does not happen: the key is on
  the disk only until another node holds it, as today, and the node says so at each start.
- *Overclaiming against a software TPM* (rival): said at the top, under each way, and in the
  docs at step 5.
