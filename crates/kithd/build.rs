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
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    write_site(&dir, &PathBuf::from(std::env::var("OUT_DIR").unwrap()));
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

/// What the installer's picture (src/install/fb.rs) is drawn with, written to OUT_DIR/site.rs:
/// the colours of docs/site.css's first `:root` block (read here, not copied: a colour the
/// site changes is the one the installer draws), and the glyphs of kithd's font, one per
/// printable ASCII character from the space on, seven rows of five bits each.
fn write_site(dir: &Path, out: &Path) {
    println!("cargo::rerun-if-changed=../../docs/site.css");
    println!("cargo::rerun-if-changed=font/glyphs.txt");
    let css = std::fs::read_to_string(dir.join("../../docs/site.css")).expect("docs/site.css");
    let root = css.find(":root {").expect("docs/site.css has a :root block");
    let block = &css[root..];
    let block = &block[..block.find('}').expect("the :root block closes")];
    let mut code = String::new();
    for line in block.lines() {
        let Some((name, value)) = line.trim().strip_prefix("--").and_then(|rest| rest.split_once(':')) else {
            continue;
        };
        let Some(hex) = value.trim().trim_end_matches(';').strip_prefix('#') else {
            continue;
        };
        if hex.len() != 6 {
            continue;
        }
        let [r, g, b] = [0, 2, 4].map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("a hex colour"));
        let name = name.trim().replace('-', "_").to_uppercase();
        code += &format!("#[allow(dead_code)]\npub const SITE_{name}: [u8; 3] = [{r:#04x}, {g:#04x}, {b:#04x}];\n");
    }
    let font = std::fs::read_to_string(dir.join("font/glyphs.txt")).expect("kithd's font");
    let glyphs: Vec<[u8; 7]> = font
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            let rows: Vec<&str> = line.split_whitespace().collect();
            assert!(rows.len() == 7 && rows.iter().all(|row| row.len() == 5), "a glyph is seven rows of five: {line}");
            let mut glyph = [0u8; 7];
            for (bits, row) in glyph.iter_mut().zip(rows) {
                *bits = u8::from_str_radix(row, 2).expect("a row of 0s and 1s");
            }
            glyph
        })
        .collect();
    assert_eq!(glyphs.len(), 95, "the font has a glyph for each printable ASCII character");
    code += "#[allow(dead_code)]\npub const GLYPHS: [[u8; 7]; 95] = [\n";
    for glyph in &glyphs {
        code += &format!("    {glyph:?},\n");
    }
    code += "];\n";
    std::fs::write(out.join("site.rs"), code).expect("OUT_DIR/site.rs");
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
