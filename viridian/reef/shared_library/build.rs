use std::env::var;
use std::path::PathBuf;

use cbindgen::generate;

fn main() {
    let include = PathBuf::from(var("CARGO_MANIFEST_DIR").unwrap()).join("include").join(format!("{}.h", var("CARGO_PKG_NAME").unwrap()));
    generate(".").expect("Unable to generate bindings!").write_to_file(include);
}
