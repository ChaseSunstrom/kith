//! The one change kith OS makes to the partition table of its own disk: where the disk
//! goes on past its last partition, and that partition is the one named, the partition is
//! made to end where the disk does. (The image's state partition is 32 MB; the disk the
//! image was written to is not.) `init` asks at each start, before the state is mounted.
//!
//! Only a GPT counted in 512-byte sectors whose checksums are right is touched, and of it
//! only that partition's end, the table's own ends and its checksums. The spare table is
//! written whole at the disk's new end, and is on the disk, before the first copy is
//! touched: whenever the power goes, one of the two is whole.

use std::fs::File;
use std::os::unix::fs::FileExt;

const SECTOR: u64 = 512;
/// Partitions end on a MiB, and less than one more is not worth a write.
const MIB: u64 = 2048;

/// A partition that was made longer: its number (from 1), where it starts, and how long it
/// is now, in sectors.
#[derive(Debug, PartialEq)]
pub struct Widened {
    pub number: u32,
    pub start: u64,
    pub sectors: u64,
}

/// CRC-32 as a GPT has it (the one of zip and Ethernet).
fn crc(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

/// A header's checksum: of its `size` bytes, with the checksum's own four as zeros.
fn header_sum(header: &[u8], size: usize) -> u32 {
    let mut summed = header[..size].to_vec();
    summed[16..20].fill(0);
    crc(&summed)
}

fn read(disk: &File, at: u64, length: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0; length];
    // (`at` may be what a disk says: no sector is past what can be counted.)
    let done = disk.read_exact_at(&mut bytes, at.saturating_mul(SECTOR));
    done.map(|()| bytes)
        .map_err(|e| format!("reading its partition table: {e}"))
}

/// The header in sector `at`, if it is one and adds up, the entries it points to, and
/// whether those are the entries it sums.
fn copy(disk: &File, at: u64) -> Result<(Vec<u8>, Vec<u8>, bool), String> {
    let header = read(disk, at, SECTOR as usize)?;
    let size = u32_at(&header, 12) as usize;
    if &header[..8] != b"EFI PART" || !(92..=SECTOR as usize).contains(&size) {
        return Err("its disk has no partition table of the kind kith OS makes (GPT)".into());
    }
    let (entries, count, each) = (
        u64_at(&header, 72),
        u32_at(&header, 80) as usize,
        u32_at(&header, 84) as usize,
    );
    let sound = header_sum(&header, size) == u32_at(&header, 16) && u64_at(&header, 24) == at;
    if !sound || !(128..=4096).contains(&each) || !(1..=1024).contains(&count) || entries < 2 {
        return Err("its disk's partition table is damaged".into());
    }
    let entries = read(disk, entries, count * each)?;
    let sums = crc(&entries) == u32_at(&header, 88);
    Ok((header, entries, sums))
}

/// The table whose header is in sector `at`, if all of it adds up.
fn table(disk: &File, at: u64) -> Result<(Vec<u8>, Vec<u8>), String> {
    match copy(disk, at)? {
        (header, entries, true) => Ok((header, entries)),
        _ => Err("its disk's partition table is damaged".into()),
    }
}

/// `header` as the copy in sector `me` has it, for `entries` at `entries_at`.
fn headed(header: &[u8], entries: &[u8], me: u64, other: u64, entries_at: u64, usable: u64) -> Vec<u8> {
    let (mut header, size) = (header.to_vec(), u32_at(header, 12) as usize);
    for (place, value) in [(24, me), (32, other), (48, usable), (72, entries_at)] {
        header[place..place + 8].copy_from_slice(&value.to_le_bytes());
    }
    header[88..92].copy_from_slice(&crc(entries).to_le_bytes());
    let sum = header_sum(&header, size);
    header[16..20].copy_from_slice(&sum.to_le_bytes());
    header
}

/// Make the partition named `name` end where `disk` (`sectors` long) does, if it is the last
/// one of the disk's GPT and there is a MiB or more to gain. `None`: there was nothing to
/// gain. An error: the table is not one this will touch (nothing was written), or the disk
/// could not be written.
///
/// A power cut in the middle of this leaves a first copy whose header does not sum the
/// entries under it, and a spare in the disk's last sector that does: the next call
/// finishes it. Any other table that does not add up is left as it is.
pub fn widen(disk: &File, sectors: u64, name: &str) -> Result<Option<Widened>, String> {
    let write = |at: u64, bytes: &[u8]| disk.write_all_at(bytes, at * SECTOR);
    let wrote = |done: std::io::Result<()>| done.map_err(|e| format!("writing its partition table: {e}"));
    let spare = sectors.saturating_sub(1);
    let (header, mut entries) = match table(disk, 1) {
        Ok(first) => first,
        Err(why) => {
            // Only what a power cut in the writes below leaves is finished here: a first
            // header that is whole, over entries that are already, byte for byte, the ones
            // the spare in the disk's last sector sums. A spare that says anything else (a
            // table left there from before the image was written) is not copied over this one.
            let (Ok((old, there, false)), Ok((last, entries))) = (copy(disk, 1), table(disk, spare)) else {
                return Err(why);
            };
            if there != entries || u64_at(&last, 32) != 1 {
                return Err(why);
            }
            let first = headed(&last, &entries, 1, spare, u64_at(&old, 72), u64_at(&last, 48));
            wrote(write(1, &first).and_then(|()| disk.sync_data()))?;
            (first, entries)
        }
    };
    let (at, each) = (u64_at(&header, 72), u32_at(&header, 84) as usize);
    // The last partition there is, and whether it is the one.
    let used = entries
        .chunks(each)
        .enumerate()
        .filter(|(_, entry)| entry[..16] != [0; 16]);
    let last = used.max_by_key(|(_, entry)| u64_at(entry, 40)).map(|(index, entry)| {
        let named: Vec<u16> = entry[56..128]
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        (
            index,
            String::from_utf16_lossy(&named),
            u64_at(entry, 32),
            u64_at(entry, 40),
        )
    });
    // The spare table: its entries, then its header in the disk's last sector.
    let room = (entries.len() as u64).div_ceil(SECTOR);
    let spare_entries = sectors.saturating_sub(1 + room);
    let end = (spare_entries / MIB * MIB).saturating_sub(1);
    let gain = last.filter(|(_, named, start, old)| {
        named.trim_end_matches('\0') == name && start <= old && end >= old.saturating_add(MIB)
    });
    let Some((index, _, start, _)) = gain else {
        // (A table that spans the disk, as after the writes below, and a record in front
        // of it that does not say so yet: a power cut came between the two.)
        if u64_at(&header, 32) == spare {
            protective(disk, spare);
        }
        return Ok(None);
    };
    entries[index * each + 40..index * each + 48].copy_from_slice(&end.to_le_bytes());
    let copy = |me, other, entries_at| headed(&header, &entries, me, other, entries_at, spare_entries - 1);
    // The spare whole and on the disk, then the first copy.
    wrote(
        write(spare_entries, &entries)
            .and_then(|()| write(spare, &copy(spare, 1, spare_entries)))
            .and_then(|()| disk.sync_data())
            .and_then(|()| write(at, &entries))
            .and_then(|()| write(1, &copy(1, spare, at)))
            .and_then(|()| disk.sync_data()),
    )?;
    protective(disk, spare);
    Ok(Some(Widened {
        number: index as u32 + 1,
        start,
        sectors: end + 1 - start,
    }))
}

/// The record in front of a GPT says how long the disk is to what knows no GPT. Nothing
/// kith OS starts by reads it: it is written last, and whether it is decides nothing.
fn protective(disk: &File, spare: u64) {
    let size = u32::try_from(spare).unwrap_or(u32::MAX).to_le_bytes();
    if let Ok(mut first) = read(disk, 0, SECTOR as usize)
        && first[450] == 0xEE
        && first[510..] == [0x55, 0xAA]
        && first[458..462] != size
    {
        first[458..462].copy_from_slice(&size);
        let _ = disk.write_all_at(&first, 0).and_then(|()| disk.sync_data());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A disk of `sectors` with a GPT as a partitioning tool writes one (128 entries from
    /// sector 2, the spare at the end): `parts` are (name, first sector, last sector).
    fn image(sectors: u64, parts: &[(&str, u64, u64)]) -> Vec<u8> {
        let mut disk: Vec<u8> = (0..sectors * SECTOR).map(|at| (at % 251) as u8).collect();
        let mut entries = vec![0u8; 128 * 128];
        for (entry, (name, first, last)) in entries.chunks_mut(128).zip(parts) {
            entry[..16].fill(7);
            entry[32..40].copy_from_slice(&first.to_le_bytes());
            entry[40..48].copy_from_slice(&last.to_le_bytes());
            for (at, unit) in name.encode_utf16().enumerate() {
                entry[56 + at * 2..58 + at * 2].copy_from_slice(&unit.to_le_bytes());
            }
        }
        for (me, other, at) in [(1, sectors - 1, 2), (sectors - 1, 1, sectors - 33)] {
            let mut header = [0u8; 512];
            header[..8].copy_from_slice(b"EFI PART");
            header[12..16].copy_from_slice(&92u32.to_le_bytes());
            for (place, value) in [(24, me), (32, other), (40, 34), (48, sectors - 34), (72, at)] {
                header[place..place + 8].copy_from_slice(&value.to_le_bytes());
            }
            header[80..84].copy_from_slice(&128u32.to_le_bytes());
            header[84..88].copy_from_slice(&128u32.to_le_bytes());
            header[88..92].copy_from_slice(&crc(&entries).to_le_bytes());
            let sum = header_sum(&header, 92);
            header[16..20].copy_from_slice(&sum.to_le_bytes());
            disk[(me * SECTOR) as usize..((me + 1) * SECTOR) as usize].copy_from_slice(&header);
            disk[(at * SECTOR) as usize..((at + 32) * SECTOR) as usize].copy_from_slice(&entries);
        }
        disk[..512].fill(0);
        disk[450] = 0xEE;
        disk[454..458].copy_from_slice(&1u32.to_le_bytes());
        disk[458..462].copy_from_slice(&((sectors - 1) as u32).to_le_bytes());
        disk[510..512].copy_from_slice(&[0x55, 0xAA]);
        disk
    }

    /// `disk` made `sectors` long (a longer disk the image was written to), widened: what
    /// was said, and what the disk holds then.
    fn widened(mut disk: Vec<u8>, sectors: u64, test: &str) -> (Result<Option<Widened>, String>, Vec<u8>) {
        disk.resize((sectors * SECTOR) as usize, 0);
        let path = std::env::temp_dir().join(format!("kith-gpt-{}-{test}", std::process::id()));
        std::fs::write(&path, &disk).unwrap();
        let file = File::options().read(true).write(true).open(&path).unwrap();
        let said = widen(&file, sectors, "state");
        let now = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        (said, now)
    }

    /// The table whose header is in sector `at`, checked as a reader checks it: where its
    /// other copy is, the last sector a partition may use, and its entries.
    fn checked(disk: &[u8], at: u64) -> (u64, u64, Vec<u8>) {
        let header = &disk[(at * SECTOR) as usize..((at + 1) * SECTOR) as usize];
        assert_eq!((&header[..8], u64_at(header, 24)), (&b"EFI PART"[..], at));
        assert_eq!(header_sum(header, 92), u32_at(header, 16), "the header at {at}");
        let entries = (u64_at(header, 72) * SECTOR) as usize;
        let entries = &disk[entries..entries + 128 * 128];
        assert_eq!(crc(entries), u32_at(header, 88), "the entries of the header at {at}");
        (u64_at(header, 32), u64_at(header, 48), entries.to_vec())
    }

    const PARTS: [(&str, u64, u64); 2] = [("config", 2048, 4095), ("state", 4096, 6143)];

    #[test]
    fn widen_counts_as_a_partition_table_does() {
        assert_eq!(crc(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn widen_makes_the_last_partition_end_where_a_longer_disk_does() {
        // 4 MiB of image on a disk of 10: the spare table's 33 sectors end the disk, and the
        // partition ends on the MiB before them.
        let image = image(8192, &PARTS);
        let (said, disk) = widened(image.clone(), 20480, "longer");
        assert_eq!(
            said,
            Ok(Some(Widened {
                number: 2,
                start: 4096,
                sectors: 18432 - 4096
            }))
        );
        let (spare, usable, entries) = checked(&disk, 1);
        assert_eq!((spare, usable), (20479, 20446));
        assert_eq!(checked(&disk, 20479), (1, 20446, entries.clone()));
        assert_eq!(u64_at(&disk[20479 * 512..], 72), 20447);
        // Of the entries only the partition's end is another, and of the disk only the tables.
        let mut before = checked(&image, 1).2;
        before[128 + 40..128 + 48].copy_from_slice(&18431u64.to_le_bytes());
        assert_eq!(entries, before);
        assert_eq!(disk[34 * 512..8192 * 512], image[34 * 512..]);
        assert!(disk[8192 * 512..20447 * 512].iter().all(|byte| *byte == 0));
        assert_eq!(
            (u32_at(&disk, 458), &disk[..458], &disk[462..512]),
            (20479, &image[..458], &image[462..512])
        );
        // Asked again (the next start), there is nothing to do.
        let (said, again) = widened(disk.clone(), 20480, "again");
        assert_eq!((said, again == disk), (Ok(None), true));
    }

    #[test]
    fn widen_is_whole_whenever_the_power_goes() {
        let before = {
            let mut disk = image(8192, &PARTS);
            disk.resize(20480 * 512, 0);
            disk
        };
        let done = widened(before.clone(), 20480, "done").1;
        // The writes in their order: the spare's entries, its header, the first copy's
        // entries, its header, the record in front. After each: the disk as it would be found.
        let writes = [
            20447 * 512..20479 * 512,
            20479 * 512..20480 * 512,
            2 * 512..34 * 512,
            512..1024,
            0..512,
        ];
        let mut disk = before;
        for (step, write) in writes.into_iter().enumerate() {
            disk[write.clone()].copy_from_slice(&done[write]);
            let path = std::env::temp_dir().join(format!("kith-gpt-{}-cut{step}", std::process::id()));
            std::fs::write(&path, &disk).unwrap();
            let file = File::options().read(true).write(true).open(&path).unwrap();
            // One of the two copies adds up, and says the old layout or the new, never a third.
            let found = table(&file, 1)
                .or_else(|_| table(&file, 20479))
                .expect("a table that adds up");
            let end = u64_at(&found.1, 128 + 40);
            assert!(
                end == 6143 || end == 18431,
                "after write {step}: the state ends at {end}"
            );
            // The next start finishes what was begun.
            assert!(widen(&file, 20480, "state").is_ok(), "after write {step}");
            assert!(
                std::fs::read(&path).unwrap() == done,
                "after write {step}: not the disk a whole run leaves"
            );
            assert_eq!(widen(&file, 20480, "state"), Ok(None), "after write {step}");
            std::fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn widen_leaves_alone_what_is_not_its_to_change() {
        let unchanged = |image: Vec<u8>, sectors: u64, test: &str| {
            let mut longer = image.clone();
            longer.resize((sectors * SECTOR) as usize, 0);
            let (said, disk) = widened(image, sectors, test);
            assert!(disk == longer, "{test}: the disk was written");
            said
        };
        // A disk as long as its image, and one with less than a MiB more for the partition.
        assert_eq!(unchanged(image(8192, &PARTS), 8192, "same"), Ok(None));
        let parts = [("config", 2048, 4095), ("state", 4096, 7167)];
        assert_eq!(unchanged(image(8192, &parts), 8192 + 2048, "little"), Ok(None));
        // The state is not the last partition, or the last is not the state.
        let parts = [("state", 2048, 4095), ("data", 4096, 6143)];
        assert_eq!(unchanged(image(8192, &parts), 20480, "not-last"), Ok(None));
        assert_eq!(unchanged(image(8192, &[]), 20480, "none"), Ok(None));
        // A table that does not add up is nobody's to write over.
        let mut torn = image(8192, &PARTS);
        torn[512 + 40] ^= 1;
        assert!(unchanged(torn, 20480, "header").unwrap_err().contains("damaged"));
        let mut torn = image(8192, &PARTS);
        torn[1024 + 128 + 41] ^= 1;
        assert!(unchanged(torn, 20480, "entries").unwrap_err().contains("damaged"));
        // (Nor is it mended from a spare in the disk's last sector that says something else:
        // one left there by whatever had the disk before.)
        let (mut torn, before) = (image(8192, &PARTS), image(20480, &[("data", 2048, 16383)]));
        torn.resize(20480 * 512, 0);
        torn[20447 * 512..].copy_from_slice(&before[20447 * 512..]);
        torn[1024 + 128 + 41] ^= 1;
        assert!(unchanged(torn, 20480, "stale").unwrap_err().contains("damaged"));
        let mut torn = image(8192, &PARTS);
        torn[512] = b'X';
        assert!(
            unchanged(torn, 20480, "other")
                .unwrap_err()
                .contains("no partition table")
        );
        assert!(unchanged(vec![0; 512], 1, "short").unwrap_err().contains("reading"));
    }
}
