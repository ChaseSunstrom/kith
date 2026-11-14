//! Where kith is built to abort on a panic (the release profile), its unwind tables are
//! not linked in: see no-unwind.ld. Tests and debug builds unwind, and keep them.
fn main() {
    println!("cargo::rerun-if-changed=no-unwind.ld");
    // The static binary, as shipped (ci/musl.sh), linked by GNU ld. (lld refuses the script:
    // a release build for another target keeps its tables and is some 400 kB larger.)
    let musl = std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|env| env == "musl");
    // (The profile's name: the build script is not told that the profile aborts.)
    if musl && std::env::var("PROFILE").is_ok_and(|profile| profile == "release") {
        // Written where cargo builds, not named where the source is: a target directory
        // shared by several checkouts keeps this script's output, and a checkout's path
        // goes away with it.
        let script = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("no-unwind.ld");
        std::fs::write(&script, include_str!("no-unwind.ld")).unwrap();
        println!("cargo::rustc-link-arg-bins=-Wl,-T,{}", script.display());
        println!("cargo::rustc-link-arg-bins=-Wl,--no-eh-frame-hdr");
        // The addresses to set right when it starts, written packed (the start files of
        // Rust's own musl read them so).
        println!("cargo::rustc-link-arg-bins=-Wl,-z,pack-relative-relocs");
    }
}
