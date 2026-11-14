//! The static release binary, as shipped (ci/musl.sh), linked by GNU ld: kithd aborts on a
//! panic and never unwinds, so its unwind tables (a seventh of it) are not linked in, by
//! the script kith's are left out with (../kith-cli/no-unwind.ld); and the addresses to
//! set right when it starts are written packed (some 600 kB less: the start files of
//! Rust's own musl read them so).
fn main() {
    println!("cargo::rerun-if-changed=../kith-cli/no-unwind.ld");
    let musl = std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|env| env == "musl");
    // (The profile's name: the build script is not told that the profile aborts.)
    if musl && std::env::var("PROFILE").is_ok_and(|profile| profile == "release") {
        // Written where cargo builds (see kith-cli's build.rs).
        let script = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("no-unwind.ld");
        std::fs::write(&script, include_str!("../kith-cli/no-unwind.ld")).unwrap();
        println!("cargo::rustc-link-arg-bins=-Wl,-T,{}", script.display());
        println!("cargo::rustc-link-arg-bins=-Wl,--no-eh-frame-hdr");
        println!("cargo::rustc-link-arg-bins=-Wl,-z,pack-relative-relocs");
    }
}
