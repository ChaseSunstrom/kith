//! The static release binary, as shipped (ci/musl.sh): kithd aborts on a panic and never
//! unwinds, so its unwind tables (a seventh of it) are not linked in, by the script kith's
//! are left out with (../kith-cli/no-unwind.ld); and the addresses to set right when it
//! starts are written packed (some 600 kB less: the start files of Rust's own musl read
//! them so).
//!
//! Where the toolchain has its own lld, that links it, and puts the functions kithd runs
//! from its start until it idles next to each other, in the order `kithd.order` lists them
//! (ci/order.py writes it): the kernel keeps in memory the pages around each one a process
//! touches, so the same code scattered over the binary held 7 MB of it resident, and
//! together under 2.
//! Without that lld, GNU ld links it as before, in the order the compiler gave.
use std::path::{Path, PathBuf};

fn main() {
    features_table();
    println!("cargo::rerun-if-changed=../kith-cli/no-unwind.ld");
    println!("cargo::rerun-if-changed=kithd.order");
    println!("cargo::rerun-if-changed=no-unwind-lld.ld");
    let musl = std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|env| env == "musl");
    // (The profile's name: the build script is not told that the profile aborts.)
    if !musl || !std::env::var("PROFILE").is_ok_and(|profile| profile == "release") {
        return;
    }
    // Written where cargo builds (see kith-cli's build.rs).
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let script = out.join("no-unwind.ld");
    let unwind = include_str!("../kith-cli/no-unwind.ld");
    let arg = |arg: String| println!("cargo::rustc-link-arg-bins={arg}");
    match lld() {
        Some(lld) => {
            // (lld takes no `INSERT` with a discard: it has the script's own form, and the
            // order is in it, a line for each function's section.)
            // (A function the compiler thinks seldom runs is in `.text.unlikely.NAME`. Each
            // line of the file is a name as a pattern: ci/order.py says of what.)
            let hot: String = include_str!("kithd.order")
                .lines()
                .map(|name| format!("    *(.text.{name} .text.unlikely.{name})\n"))
                .collect();
            let (template, place) = (include_str!("no-unwind-lld.ld"), "    /* kithd.order */\n");
            assert!(
                template.contains(place),
                "no-unwind-lld.ld no longer says where the order goes"
            );
            let lld_script = template.replace(place, &hot);
            std::fs::write(&script, lld_script).unwrap();
            arg("-fuse-ld=lld".into());
            arg(format!("-B{}", lld.display()));
            // Where every function ended up, for ci/order.py (the binary itself is stripped),
            // under the names the linker knows them by: the ones the order file must have.
            arg(format!("-Wl,-Map={}", out.join("kithd.map").display()));
            arg("-Wl,--no-demangle".into());
        }
        None => {
            println!("cargo::warning=no lld in this toolchain: kithd is linked in the compiler's order");
            std::fs::write(&script, unwind).unwrap();
        }
    }
    arg(format!("-Wl,-T,{}", script.display()));
    arg("-Wl,--no-eh-frame-hdr".into());
    arg("-Wl,-z,pack-relative-relocs".into());
}

/// os/features' `# pci:` lines as `OS_FEATURES` (devices.rs matches the PCI bus against it): each
/// feature that has some, by name, with its vendor and device ids as sysfs writes them. A line
/// that is not `vendor:device` in hex stops the build, so a typo is not a card never matched.
fn features_table() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("os_features.rs");
    let dir = Path::new("../../os/features");
    // (A directory: cargo looks at every file in it.)
    println!("cargo::rerun-if-changed=../../os/features");
    let Ok(listed) = std::fs::read_dir(dir) else {
        println!("cargo::warning=os/features is not there: no feature is matched to the PCI bus");
        std::fs::write(&out, "pub const OS_FEATURES: &[(&str, &[(&str, &str)])] = &[];\n").unwrap();
        return;
    };
    let mut files: Vec<PathBuf> = listed
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "config"))
        .collect();
    files.sort();
    let mut table = String::from("pub const OS_FEATURES: &[(&str, &[(&str, &str)])] = &[\n");
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let name = file.file_stem().unwrap().to_str().unwrap();
        let ids: Vec<(String, String)> = text
            .lines()
            .filter_map(|line| line.strip_prefix("# pci:"))
            .flat_map(str::split_whitespace)
            .map(|pair| {
                let hex = |id: &str| id.len() == 4 && id.bytes().all(|b| b.is_ascii_hexdigit());
                match pair.split_once(':') {
                    Some((vendor, device)) if hex(vendor) && hex(device) => {
                        (vendor.to_ascii_lowercase(), device.to_ascii_lowercase())
                    }
                    _ => panic!(
                        "{}: '{pair}' in a `# pci:` line is not vendor:device in hex",
                        file.display()
                    ),
                }
            })
            .collect();
        if ids.is_empty() {
            continue;
        }
        let pairs: Vec<String> = ids
            .iter()
            .map(|(vendor, device)| format!("(\"{vendor}\", \"{device}\")"))
            .collect();
        table.push_str(&format!("    ({name:?}, &[{}]),\n", pairs.join(", ")));
    }
    table.push_str("];\n");
    std::fs::write(&out, table).unwrap();
}

/// The directory of the toolchain's `ld.lld` (the one rustc itself links with where lld is
/// its default), if it has one.
fn lld() -> Option<PathBuf> {
    let rustc = std::env::var("RUSTC").ok()?;
    let sysroot = std::process::Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    let sysroot = String::from_utf8(sysroot.stdout).ok()?;
    let host = std::env::var("HOST").ok()?;
    let dir = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin/gcc-ld");
    dir.join("ld.lld").exists().then_some(dir)
}
