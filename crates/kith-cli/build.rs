//! Where kith is built to abort on a panic (the release profile), its unwind tables are
//! not linked in: see no-unwind.ld. Tests and debug builds unwind, and keep them.
fn main() {
    println!("cargo::rerun-if-changed=no-unwind.ld");
    // The static binary, as shipped (ci/musl.sh), linked by GNU ld. (lld refuses the script:
    // a release build for another target keeps its tables and is some 400 kB larger.)
    let musl = std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|env| env == "musl");
    // (The profile's name: the build script is not told that the profile aborts.)
    if musl && std::env::var("PROFILE").is_ok_and(|profile| profile == "release") {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("no-unwind.ld");
        println!("cargo::rustc-link-arg-bins=-Wl,-T,{}", script.display());
        println!("cargo::rustc-link-arg-bins=-Wl,--no-eh-frame-hdr");
    }
}
