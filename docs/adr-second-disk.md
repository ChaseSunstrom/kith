# A second disk for a node's data, under the state's key

Status: design, nothing built (T-0863). It decides how a disk other than the one kith OS runs
from holds data, encrypted, and how it is opened, with what kithd does to a disk it does not
know. Where the code differs from a line here, the code is the word. It builds on
[adr-unlock.md](adr-unlock.md), which settled how a node's state is opened, and on the ways of
that page it shares: all of them.

**A name first.** [the OS guide](guide/os.md) calls the installer's target "a second disk for the
node" (the "As a guest on Proxmox VE" section). That is a disk kith OS is written *to*. This
record is about a **data disk**: one kith OS is already running without, and keeps data on. The
word "data disk" is used throughout, so the two are not mixed.

## The problem

A node's state is one partition of the disk it boots from, under dm-crypt
(`kith_dm_sys::crypt`, `crates/kith-dm-sys/src/lib.rs:296-318`). A machine with a second disk,
larger or faster, has nowhere kith puts anything on it. The mechanism that is there for volumes
that must be encrypted, `Volume encrypted: true` (`crates/kithd/src/encrypted.rs:1-15`), is a
file under the state, so its room is the state partition's, and its key is kept by the cluster's other
nodes: it cannot be opened by a node alone. A data disk should be:

- encrypted as a whole, so a disk taken from the machine reads as noise: only if **the whole of it
  was written through the mapping once** at add (section 1), since a header of 4 KiB alone
  encrypts nothing that was on the disk before;
- opened by whatever opens the state, with no new thing to type or touch at the console;
- erased by what erases the state (a duress code, `crypt::erase`, `crates/kithd/src/crypt.rs:629`);
- never written, mounted or even read past its first 4 KiB, until the owner has said it is this
  node's: kithd is process 1 and root, and a USB stick, a backup disk or another machine's disk is
  not its to take.

## What is checked

Every claim about code cites a line. Not checked here: the sysfs file that gives a disk's serial on
every bus (the code reads several, `install.rs:95-117`; an NVMe and a virtio disk are covered by
it, the rest are unverified), and whether the kernel's `EXT4_IOC_RESIZE_FS` works on a mapping of
a disk of any size (it does on a file under loop, `kith-dm-sys` `grow`, `lib.rs:155`: that is the same
call).

## 1. How the data is encrypted

**aes-xts-plain64 over the whole of the disk after a 4 KiB header, by `kith_dm_sys::crypt`.**
`crypt(name, device, from, sectors, key)` maps `sectors` of `device` from sector `from` under a
64-byte key (`lib.rs:296-318`), so a header of 8 sectors at the start and the mapping from sector 8
is what that function already does (its doc: "from its sector `from`"). The same
cipher, the same call and the same `remove` (`lib.rs:321`) as the state's
(`crypt.rs:1052`). **No new crypto**, no LUKS: kithd has no LUKS reader, and a LUKS header holds
keyslots, which are ways in of their own with their own passphrases and their own PBKDF, outside
the lock record's rules ([adr-unlock.md](adr-unlock.md) on the order of writes and the duress
erase).

**The header is plain text, 4 KiB, and says only what the disk is**:

    kith-disk v1
    id: <32 hex digits, random>
    sum: <SHA-256 of the lines above, in hex>

in the style of the lock record (`kith-lock v1`, `sum:`, `crypt.rs:99-135`). It holds no key and no
size. It exists so kithd can tell **a kith data disk from a disk of someone else's** without
trusting a name: `sdb` is the order the kernel found the disks in (`install.rs:35-37`), and a
disk's serial can be absent.

**What "encrypted" means here, and what it does not.**

- **Old data is overwritten at add, through the mapping.** Writing a 4 KiB header and a small file
  system leaves everything else on the disk as it was: a disk that held a person's files still
  reads them past the header, and a region nothing has written yet shows **the usage map**
  (which regions hold data and which hold what was there before). So `add` writes zeros
  **through the mapping** over the whole of it, which the cipher turns into noise: the order
  of section 2 has this step, between the mapping and the file system. It takes the disk's size
  over its write speed (a 1 TB disk is minutes to hours), runs as the `pending` entry says it
  is, and a cut leaves `pending`, which `add` again starts over. `add --quick` instead discards
  the disk (`BLKDISCARD`, instant); it is allowed, **and says in its answer that the usage map
  is then visible** (a discarded region reads as zero, or as it was, depending on the device,
  where the written ones are noise), and that the old plaintext is gone only if the device
  really erases on discard (unverified for any device). The default is the overwrite.
- **XTS has no integrity.** aes-xts-plain64 hides the content; it does not stop a person with the
  disk from changing a sector (the sector then reads as noise, with no error), or putting back an
  older copy of one. The state's own dm-crypt has the same property
  (`crypt.rs:1052`). A disk's content that must not be altered needs a check of its own; none is
  claimed here.
- **Two copies of a sector show where it changed.** A person who sees the disk twice learns
  which sectors were rewritten between, not what they hold.

**The key is the disk's own, random, and kept in the state.** `crypt::random::<64>()`
(`crypt.rs:213`, `pub(crate)`) when the disk is added; kept in a directory of the state,
`disks/<id>/` (the state is already under dm-crypt, root-only): the key in `disks/<id>/key`, and
beside it `disks/<id>/entry` with what kithd knows of the disk (its serial, and whether the add
was finished), and `disks/<id>/data` where it mounts. (The key and the directory are different
paths: `disks/<id>` is the directory and holds both.) It is in no record and no disk but the
state. Rivals for the key:

- *drawn from the state's key by HKDF* (nothing stored but a salt): refused. The key then
  cannot be forgotten alone: removing a disk would not erase it, since the state's key and
  the id (which the header shows) draw it again. A key of its own that remove deletes (its bytes
  overwritten first, then the file removed, then the directory synced) is a **cryptographic erase of
  that one disk, as strong as the state's erasure and no stronger**: see "Removing" in section 2.
- *a `disk:` line in the lock record*: refused. The record is read before the state is
  opened, which a data disk does not need, it has 4 KiB (`ROOM`, `crypt.rs:100`) that the ways
  in fill, and it would run into the order-of-writes rule for a thing that is no way in.
- *its own passphrase or key at the console*: refused. A second prompt, a second set of
  ways in and a second duress to erase; and the node would wait at boot for a disk, which a
  disk is not worth.
- *Volume `encrypted: true`* (`encrypted.rs`): kept, not replaced. It is the way for a volume,
  in the state partition, held by the cluster. This record is for the node that has the disk.

**Which ways in it shares: every one**, because it has none. The disk opens after the state is
open (`STATE_OPEN`, `crates/kithd/src/init.rs:605`: "told once this node has its state to use,
however long the key takes to come"), from a key that is in the state. So the key on disk, the TPM
seal, the PIN, the passphrase, the cluster's key (`POST /v1/unlock`), the recovery key
(`crypt.rs:726-757`, `judged`) and a FIDO2 key (once [adr-fido2.md](adr-fido2.md) is built) open the
disk by opening the state. The duress code, which erases the lock record
(`erase`, `crypt.rs:629`), makes the state's key unrecoverable, and with it the disks' keys, which
are inside the state. **The state is the one lock.** Said plainly, since it is the cost: a lost
state is a lost disk. A disk is not recoverable by anyone without the state it was added under.

**A node whose state is not encrypted is refused** (`disk add` says why): the keys would lie
on a disk readable as it is, next to what they lock.

## 2. What kithd does with a disk it does not know

A disk is **known** when it has a header whose sum is right and whose id is in a `disks/<id>/`
directory of the state, and that entry is finished (`ready`). Everything else is **unknown**, whether no header, a
wrong sum, an id the state does not list (another node's disk, or one removed), or a half-made one.

For an unknown disk kithd does **nothing to it**. It does not map it, mount it, write it,
`mkfs` it, or read more than its first 4 KiB (the header's room). It says so: the node's status
lists every disk it sees as `known`/`unknown` with the name, size, model and serial that
`install::disks` already has (`crates/kithd/src/install.rs:65-91`, `Disk`, `install.rs:32-46`), and
the console line "kithd: disk sdb (serial …, 1.0 TB) is not known: not touched" is
printed once at boot. A removable disk (`Disk.removable`, `install.rs:45-46`: a stick or a reader) and
the disk the system runs from (`booted`, `install.rs:65`) are not offered at all, the second by the
same kind of fence `labelled` uses for the state (`init.rs:334-356`), turned the other way round
for a data disk. **`on_ours` cannot be reused as it is**, and the no-verity case is why:
`on_ours(false, _)` is true (`init.rs:352`: "any, where there is no verity root"), so inverted
it would refuse every disk on a node started without a verity root (the installer's stick, a
development start), and used as it is it would offer the booted disk. A new function, `off_ours`,
decides it in three cases, each with a unit test:

- **a verity root, its disk known:** a disk is offered if it is not the root's own disk
  (`disk != ours`);
- **a verity root, its disk not readable:** none is offered (it fails closed, as `on_ours`
  does, `init.rs:353`);
- **no verity root:** the node's own disk is the one that holds the partition `labelled("state")`
  finds (`init.rs:334`); every other disk is offered; if no state partition is found, **none is
  offered** (fails closed).

`O_EXCL` at add (below) is the second guard behind this one, not a replacement.

**Adding is an act of the owner**, never of kithd. `kith node disk add NAME --serial SERIAL`
(`POST /v1/disks/NAME`, for who may apply a NodeKey, as `crypt::pass`, `crypt.rs:2386-2425`).
**On a node in no cluster**, `pass` refuses (`crypt.rs:2413`: "this node is in no cluster"), and
a lone box with a data disk is likely the first user of this feature, so the disk verbs are
**not** copied from `pass` in that line: they act on the node itself with no cluster needed, and
another node is asked as `pass` does only where there is one. Whether `permit`
(`crate::api::permit`) works with no cluster is unverified; T-0958 settles it and has a test on
a node with no cluster, and if it does not, says in the verb's answer that it cannot.

1. The serial is **typed**, and kithd matches it with the disk's (the serial the installer shows and matches against what was typed,
   `install.rs:95-97`), so `sdb` moved by a reboot is not the disk meant. A disk that says no
   serial is refused.
2. The disk is opened for writing with `O_EXCL` (a block device that is mounted, mapped or held
   fails it), and **its first 4 KiB must be zero**, with no GPT or MBR signature, ext4 or LUKS
   magic, nor a kith header. A disk that is not empty is refused unless the same request says
   `--wipe`, which is then logged as such in the audit log (as the passphrase's audit entry is,
   without the secret) with the serial.
3. A state that is not encrypted refuses.
4. **Written in this order, each step surviving a cut**: the entry `disks/<id>/entry` is written
   `pending` and `disks/<id>/key` made and synced (the key is made and kept before anything uses
   it); the mapping is made; **the whole of the mapping is overwritten with zeros** (section 1,
   or `--quick`'s discard); the small ext4 file system that kith OS carries
   (the seed, below) is written to it and grown to the disk's size
   (`grow`, `lib.rs:155`), as `encrypted.rs` does for a volume; the **header is written last** and
   synced; the entry is marked `ready`. A cut before the header leaves a disk whose first 4 KiB are
   still zero: `add` again starts over, and nothing else ever finds a half-made disk
   usable (`pending` with no header is "half-made: `disk add` again", and is reported).
   **A cut between the header and `ready`** leaves a header whose id is in a `pending` entry:
   the disk is unknown (known needs `ready`), and its first 4 KiB are no longer zero, so the
   step-2 rule would refuse it. `add` therefore **resumes** when the header's sum is right and
   its id is the `pending` entry's of this node: it opens the mapping with the kept key, checks
   that the seed's file system answers, and marks `ready`; if it does not, `--wipe` starts over.
5. Mounted at `disks/<id>/data` under the state, `nosuid,nodev,noatime`, as `mount_state` does
   (`init.rs:559-584`).

**The seed must reach the disk's size.** The file system the node writes is
`/usr/share/kith/volume.ext4`, **8 MiB** (`os/build.sh:418`), made with `mkfs.ext4 -b 4096
-N 4096` and no `resize=` (`os/build.sh:419-420`). An ext4 grown online is capped by the group
descriptor blocks reserved when it was made, by default about 1024 times the original size,
**about 8 GiB for 8 MiB** (the figure is from ext4's reserved-GDT rule; not measured here), and the
example disk of this record is 1 TB. So a data disk does not use that seed as it is. **T-0958
makes the seed for a data disk with `-E resize=` for the largest disk it will take** (its own
file, `usr/share/kith/data.ext4`, so the Volume's seed and its image bytes stay as they are),
the cost being the reserved descriptor blocks inside the seed (a seed bigger than 8 MiB;
measured in the image budget by that task), or makes the file system at add by another means.
The VM test (section 3) grows a **sparse file of 16 GiB or larger**, over the 8 GiB the 8 MiB
seed would allow, and says what it measured.

**Removing**, `kith node disk remove ID`: unmount (refused while in use), `crypt::remove`
(`lib.rs:321`), then **the header's 4 KiB is zeroed** (the disk is then plainly unknown again, and
`--quick` is not needed to start it over), the key's bytes overwritten and `disks/<id>/key`
removed. A `disk add --wipe` makes it a new one.

**What remove is, and is not.** It is not a full cryptographic erase. The state is ext4 on a
mapped partition: **the old `key` file can survive** in the file system's journal, in blocks the
file system freed and did not overwrite, or in remapped or wear-levelled blocks of an SSD, and
all of those are readable by whoever has **the state's key**, since the key file lay inside the
state. So remove is **as strong as the state's erasure and no stronger**: against a person with
the disk but not the state's key, the disk's data is noise with no reachable key, and against a
person who has the state's key (the owner under a duress, a node whose state is opened), a
removed disk's old key may be recoverable from the state's free space. The strong erase of a
disk is the duress erase of the state, which destroys the state's key; for a disk removed on
its own, the person who needs more **discards the disk** (`disk remove --discard`, `BLKDISCARD`
after the header is zeroed), and says so in the answer. Neither is claimed to reach into a
device that remaps blocks (unverified).

**At boot** a task starts when the state is open (`state_then(&STATE_OPEN, …)`, `init.rs:610-637`)
and is not on the path of the node's start: it reads the headers, maps and mounts the known
disks, and fails each on its own (a disk that does not answer within a bounded time is marked
`unreadable` and the rest go on). A known disk that is not found is "known, not seen": the
entry stays. No hot-plug: only boot and `disk add` look (open, section 6).

## 3. The VM test, on a disk file

**Never a real disk.** The test makes its disks as **files** under its work directory
(`truncate -s 64M $work/data.raw`), attached as virtio disks **with no `-snapshot`**, the way
`ci/vm/tests.sh:39` attaches `disk.raw`, and with an added `serial=` so a serial can be typed.
**Not the way `ci/vm.sh:496` attaches `--disk IMAGE`: that line adds `-snapshot`**, which
sends the guest's writes to a temporary file and leaves the disk file as it was, so "checksum
unchanged" and "marker absent from the disk file" would pass for any build, even one that wrote
the plaintext. The test asserts the other way too, so it cannot pass vacuously: after the add
the disk file's checksum **differs** from before. The script refuses, as a first line, a path that is not a regular file (`[ -f ]`),
so a device node can never be given to it. It is a part of `ci/vm.sh` next to `crypt` and
`duress` (the same node with its state encrypted: `ci/vm.sh:16-19`), as `--test disk`. What it
shows, on a disk file:

1. **An unknown disk is left alone.** Two files are attached with the encrypted node: one zero,
   one with a GPT signature written by the test, one with random bytes. The node reports all three as unknown
   and says so on the console; the VM is stopped and a checksum of each disk file equals the one
   from before it was started.
2. **Adding is refused as it should be:** a wrong serial; the file with a signature (without
   `--wipe`); an unencrypted state (a second node, state in the clear); the serial of the disk
   the node runs from.
3. **Adding works and the data is not on the disk.** The test first fills a file with a
   repeated plaintext line (the old data, which must not survive) and adds it with `--wipe`. The
   correct serial adds it; the test writes a marker string under the mount; the file's first
   bytes are `kith-disk v1`; after the VM stops, the marker **and the old plaintext line** are
   **absent from the whole disk file**, and the file system's magic
   (`0xEF53` at offset 1080 of the mapping) is absent from the disk file where it would be
   (sector 8 plus 1080 bytes). **An entropy check** covers the rest: every 1 MiB region of the
   file after the header, written by the file system or not, compresses to no less than 99% of
   its size (`gzip -c | wc -c`), so a usage map, or a zero or repeated region, would fail.
   With `--quick` the same test asserts the opposite, that the usage map shows, as the answer says.
4. **It opens by each way in the state does.** The node restarts with its state keyed by the
   key on disk (the disk mounts, the marker is read), by the recovery key typed at the console, and by
   the passphrase typed: `ci/vm/blackout.sh` and the crypt test show how each is typed; the disk
   follows without a line of its own.
5. **Duress erases it.** A duress code is typed (`ci/vm.sh --test duress`): the lock record is
   erased, the node powers off, and on the disk file's next start the node cannot open its
   state; the header is there and the marker is not, and no key to read it with exists anywhere.
6. **Remove, and a cut add.** `disk remove` leaves an unknown disk with its header zeroed that
   the node does not touch (checksum as before the next start); a node killed between `pending`
   and the header, and started again, reports "half-made" and `add` again completes; **a node
   killed between the header and `ready`** (the leftover `pending` entry with a header) reports
   it, and `add` again resumes and completes without `--wipe`.
7. **A disk bigger than the seed's default cap.** A sparse file of 16 GiB or larger is added
   and grown; the file system's size under the mount is within a block group of the disk's, which
   an 8 MiB seed without `resize=` could not reach (section 2).
8. **A node with no cluster** adds, lists and removes a disk (section 2).

None of it reaches a real disk, a real TPM or a real key.

## 4. Build slices

| Task | Slice |
|---|---|
| T-0957 | **The core, on files.** The header (written and read back by unit tests on a disk file in a temporary directory), the entry and key under `disks/<id>/`, the signature check, the order of writes of an add with the mapping step behind a trait (a fake in the tests, so a cut at each point is tested, including between the header and `ready`, and the resume), `off_ours` with its three cases (section 2), the refusal of a root disk or a removable one, and the zeroing of the header and the key on remove. No mapping, no boot, no verb. |
| T-0958 | **The mapping, boot, verbs and the VM test.** What a file cannot show: the real mapping (`kith_dm_sys::crypt` needs root and device-mapper), the overwrite through it, the seed written and grown (made with `-E resize=`, section 2), the mount; the task after `STATE_OPEN` that mounts the known disks and leaves the unknown alone, the node's status line of disks, `kith node disk add`, `remove` and `list` with the audit entries and the no-cluster route, and `ci/vm.sh --test disk` (section 3) on a disk file. |

T-0957's unit tests run on files in a directory, so **they cannot cover the mapping, the mount or
the grow**; those need root and device-mapper, are **VM-only**, and are covered by T-0958 and
by nothing before it. T-0957 stands alone (it merges and passes its gates without T-0958, with the
mapping behind a trait); T-0958 needs it. T-0957 and T-0958 were captured with the earlier wording
that put the seed in T-0957: this section is the word.

## 5. Rivals, in short

- **Do nothing, and use Volume `encrypted: true` for what must be encrypted** (already built).
  Right for a node in a cluster with room on its state partition. Wrong for a disk of its own
  that is bigger than the state, which is the request.
- **Mount the disk unencrypted** (what `fstab` would). A disk taken from the machine
  is then read as it is; the node's other data is encrypted and this is not.
- **LUKS, from `cryptsetup`'s format.** Interoperable with a laptop, and a second set of ways in
  that this node's lock record does not hold (section 1).
- **A disk found and taken on its own** (any disk with no header is formatted). Refused first:
  a node that formats what it finds is a data-loss bug waiting for a USB stick.

## 6. What it leaves open

- **A Volume that is placed on a data disk** (`disk: NAME` on a Volume or a PVC's class): this
  record makes the mount; who uses it is a later task.
- **Hot-plug and a disk that comes later.** Boot and `add` look; a udev-less node watches
  nothing.
- **More than one disk as one** (striping or mirroring): none; each disk is its own.
- **Re-keying a disk in place** (a new key, the data re-encrypted): none; a disk is new or
  kept.
- **Another node's disk moved here**: it is unknown, its key is in the other node's state, and
  the state's loss is a disk's loss (said in section 1, the cost of one lock).
- **The first build's weakest link**: the serial. A disk that gives none cannot be added without
  an explicit flag, and the sysfs files the code reads are those the installer reads
  (`install.rs:95-117`); a bus that gives its serial elsewhere is a disk that waits for a
  later fix.
- **A removed disk's old key** may survive in the state's free space, journal or an SSD's
  remapped blocks (section 2): remove is as strong as the state's erasure, and the strong way is
  a duress or a discard.
- **Unverified here**: `O_EXCL` refusing a block device that a device-mapper mapping holds,
  on the kernel kith OS ships (it does on mainline for a mounted or held device; the test of
  step 2 is the check).

## Review

Self-review of this record as an adversary. A disk that lies about its serial gets the owner's
own typed word as its only guard, which is the installer's trust too. A header that is forged
carries no key, so a forged header opens nothing and is "unknown" unless the id is in the state.
An id that collides with an existing entry is refused at add (random 16 bytes). The state's file
of keys is as secret as the state; a copy of the state's files out of a running node (a backup
of the state directory) carries the disks' keys, which is a thing to check where backups of the
state are made (unverified: no backup path was read for this record).
