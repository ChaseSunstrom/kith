//! Puts `v1.schema.json` into the build without its indentation: the binaries read the kinds'
//! schemas out of it (see `SCHEMAS` in src/lib.rs), and the file stays one a person can read.

fn main() {
    println!("cargo::rerun-if-changed=v1.schema.json");
    let text = std::fs::read_to_string("v1.schema.json").expect("v1.schema.json is beside Cargo.toml");
    // A JSON string holds no line break, so the spaces a line begins with are never inside one.
    let small: String = text.lines().map(str::trim_start).collect();
    let out = std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR");
    std::fs::write(std::path::Path::new(&out).join("schemas.json"), small).expect("OUT_DIR is written to");
}
