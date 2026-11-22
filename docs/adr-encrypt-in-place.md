# Encrypting a node's state in place: the journal and the order of writes

Status: the engine is built (T-1136, `crates/kithd/src/in_place.rs`, tested on files with every
cut), and init runs it at boot (T-1137: a marker 64 KiB into the config partition, a lock record
with the key, the pass before the state is mounted; `ci/vm/encrypt.sh` cuts it mid-pass), and
`kith node encrypt` writes the marker. The user's side (time, a power cut, the SSD caveat) is in
[the cluster guide](guide/cluster.md#encrypting-a-node-that-was-installed-plain). This record is the part of T-1106 that the cuts depend on. Where the code differs
from a line here, the code is the word. It builds on [adr-unlock.md](adr-unlock.md) (the lock
record, at 512 KiB into the config partition) and on the order of writes of
[adr-second-disk.md](adr-second-disk.md).

## The problem

A node installed without `encrypt: true` has its state plain on the state partition. To encrypt
it with no reinstall, every byte of the partition is read and written back through a dm-crypt
mapping of the same partition. That takes minutes to hours, and the power can go at any byte of
it. Whatever the moment, the partition must still be readable on the next start: every chunk
either plain, or encrypted with the journal saying where the line is. A chunk half plain and half
encrypted with no way to say which is the failure this record exists to make impossible.

## What the engine is

A pure pass: no init, no CLI, no dm-crypt call. It is given three things that are all "read, write
and sync at an offset" (the `Disk` trait; a file in the tests):

- the **partition**, raw, where the plain data is read from;
- the **mapping**, the same partition under the key: a write to it lands encrypted on the
  partition (a fake that XORs in the tests, `kith_dm_sys::crypt` in the slice that wires it);
- the **journal**, in the config partition, which is not under the key.

It goes through the partition in chunks of 256 KiB (the last one is what is left), in order. The
size of the partition and of the chunk are in the journal and checked at every resume: a partition
that grew or shrank is refused, not guessed at.

## 1. The layout of the journal

The config partition is 1 MiB. Its first 64 KiB is the node's config; the lock record is 4 KiB at
512 KiB with a copy after it (`crypt::AT`). The journal sits between them:

```text
  0 KiB      64 KiB            128 KiB  132 KiB  136 KiB      192 KiB            452 KiB      512 KiB   520 KiB      1 MiB
  | config   | (free)          | head 1 | head 2 | (free)      | backup slot      | (free)     | lock    | lock copy  | (free)
```

- two **header copies**, 4 KiB each, at 128 KiB and 132 KiB: a magic line, the pass's random id,
  the partition's size, the chunk size, `done` (chunks whole at rest), a 16-byte fingerprint of the
  key, the **check of the plain chunk `done`** (32 bytes, zero once all are done) and the SHA-256
  of all of that; the rest of the 4 KiB is zero. A header that fails its sum, or has a byte after
  it, is not taken. The fingerprint and the check are HMAC-SHA-256 under a key drawn from the
  state's key with HKDF (another label than the backup's), so nobody without the key can test a
  guess of a chunk against the header, and a journal of another key is refused;
- one **backup slot** at 192 KiB, 256 KiB plus 4 KiB: a random 12-byte nonce, then the plain chunk
  sealed (ChaCha20-Poly1305) under a key drawn from the state's key with HKDF, with the pass id
  and the chunk's number as the associated data. The slot is never plain, so nothing plain is left
  outside the partition. A slot from another pass, or of another chunk, does not open.

The test `in_place::layout` holds these ranges apart from each other, from the node's config and
from the lock record, and inside 1 MiB.

## 2. The order of writes

At the start (no whole header, the second copy empty): read chunk 0 and take its check, write
header 1 with `done = 0` and that check, sync, write header 2, sync. Nothing of the partition is
touched before both are down.

For each chunk `i`, with `done = i` and the header holding the check of plain chunk `i`:

1. have the plain chunk (read from the partition; it must match the header's check, else stop);
2. seal it into the backup slot, **sync**;
3. write it through the mapping, the first half and then the second, **sync**;
4. read chunk `i + 1`, still plain, for its check; write `done = i + 1` and that check to
   header 1, **sync**, then to header 2, **sync**.

At the end: zero the backup slot (if it is not already), sync. The journal is left saying
"finished" (`done` is every chunk), and **stays so**: a `pass` over it writes nothing, and
`finished` answers true. Only `forget` empties the journal.

**The contract for the caller (T-1137).** A journal with no pass in it reads as "never begun", and
a pass over a partition that is already encrypted would read the ciphertext as plain and encrypt
it again, which is the loss this engine exists to prevent. So the caller decides what to do from
the lock record **and** the journal's terminal state, never from "no journal": call `forget` only
after the lock record, which says the partition is encrypted, is durable on the disk. A cut
between the two leaves a finished journal and a lock record, and the caller sees both. The
opposite order (forget, then write the lock record) has a window with neither, in which a boot
would start a pass over ciphertext.

Two rules carry everything: the backup of chunk `i + 1` is not written until both headers say
`i + 1`, and the partition's chunk `i` is not written until its backup is on the disk. The syncs
between the two header copies are there on purpose: with one sync after both, a disk may keep
half of each, and both copies are then torn (the sum catches one torn copy, so one must stay
whole).

## 3. The cut, at every point

A resume reads both headers, takes the whole one with the greater `done` (both whole: the
greater; one: that one; neither: see below), writes both again, then looks in the slot for the
backup of chunk `done`. If it opens, the chunk is written again through the mapping from it,
whatever state the chunk is in (plain, half, whole: the mapping gives one ciphertext for one
plain chunk and one place), and the pass goes on. If it does not open, the pass reads chunk
`done` from the partition and compares its check with the header's: equal, the chunk was never
touched and is backed up as at any chunk; **not equal, the chunk is part written or whole with no
backup to put it right from** (the slot's own sector failing, say), and the pass stops with an
error naming the chunk, writing nothing. The check is why: without it the pass would seal what
is on the partition, half plain and half ciphertext, as the chunk's plain bytes, and carry on.

| cut at | what is on the disk | resume |
| --- | --- | --- |
| backup being written | slot torn or old; header says `i`; chunk `i` plain | slot does not open for `i`: chunk read as plain, as at any chunk |
| backup written, not synced | the same, or the slot whole | either as above or from the backup; the same end state |
| backup synced | slot whole; chunk `i` plain | written from the backup |
| chunk part-written | first half encrypted, the rest plain | written whole from the backup |
| chunk done, header not | chunk `i` encrypted; header says `i` | written again from the backup, same bytes |
| header 1 written | header 1 says `i + 1`, header 2 says `i` | takes `i + 1`; or, if copy 1 is the torn one, `i`, and writes chunk `i` again from the slot, which is still the backup of `i` |
| header 2 written, not synced | as the row above, with copy 2 whole or torn | as the row above |
| both headers | `i + 1` | the next chunk |

**Neither header whole.** If header 2 is all zero the pass never got past its first write (header 1
may be torn): it starts. If header 2 holds anything else, the journal is damaged, and the engine
stops rather than start again over a partition half encrypted. A header that is whole but says
another size or chunk is refused the same way.

**A cut in a resume** is a cut like any other: the resume uses the same writes in the same order.
The test cuts a second time at every point of the resume and runs a third.

**What a disk may do that a file does not.** The tests keep a fake whose writes wait until a sync,
and at a cut keep none of them, all of them, the first half of each, or the first 64 bytes of
each (a header with its new count and its old sum): so a missing sync shows as a failure and not
as a pass on a file that wrote everything at once. The cut test runs
4 crash modes x (4 points of a chunk x 8 chunks + 3 points of a header x 9 headers) = 236 cuts,
each resumed to the end state; a second test cuts again inside the resume. Two syncs were
checked by taking them out, each turning the test red: the one that puts the backup on the disk
before the chunk is written, and the one between the two header copies (the last of the crash
modes ends in "both copies damaged"). The check of the next chunk was checked the same way: with
the comparison off, the test of a part written chunk with a corrupted slot ends in a pass that
goes on.

## What it does not do

- It does not read a chunk twice from the raw partition after the mapping wrote it: a raw read of
  a partition the mapping wrote may come from a page cache that never saw the write. The caller
  that verifies does so through the mapping, after dropping the cache (`posix_fadvise` on the
  device, as `crypt.rs` does when it reads the lock record), or it reads the cache's old bytes.
- A chunk half written whose backup is gone is not repaired: the pass stops, names the chunk and
  writes nothing (section 3). That chunk is part ciphertext and part plain on the partition, so
  the caller must not mount it, plain or through the mapping, nor call it done.
- **A bad sector mid-pass** (a read or write that fails on the partition) leaves the partition
  half encrypted, with the journal saying where. The pass returns the error and keeps the
  journal. T-1137 must then refuse to boot on the partition as plain, with a clear message, and
  keep the journal, so that a later start (or a replaced disk) can go on.
- Four syncs per chunk, and the 260 KiB slot rewritten at each chunk: on a raw NAND that wears
  the slot's blocks over a pass; behind an eMMC or SD card's controller, which levels the wear,
  it is a few hundred MiB of writes over a pass of a gigabyte-class partition and nothing more.
- **Flash keeps the plain blocks.** The pass overwrites by address, and an SSD, NVMe drive, eMMC
  or SD card maps an address to a new block at each write: the old plain block stays in flash
  until the controller erases it, out of the engine's reach. After a pass the interface reads
  ciphertext; the chips may still hold plain. No pass in software can change that. The remedy is
  outside the engine: a secure erase of the whole drive (`nvme sanitize`, `blkdiscard --secure`,
  ATA secure erase, or an SED's key change) and a reinstall with `encrypt: true`. The guide says
  so beside the verb.
- No online pass: the partition is not mounted while it runs. No decrypt.
- The sealed backup is under the state's key, so it is as strong as the state, and no stronger.
  A lock record that is erased does not erase a backup left in the journal; the engine zeroes the
  slot at the end and `forget` zeroes everything.
