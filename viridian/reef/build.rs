use std::env::var;
use std::path::PathBuf;

use prost_build::compile_protos;

const CERTIFICATES_PROTO: &str = "common.proto";

fn main() {
    let proto_dir = PathBuf::from(var("CARGO_MANIFEST_DIR").unwrap()).parent().unwrap().parent().unwrap().join("vessels").canonicalize().unwrap();
    compile_protos(&[proto_dir.join(CERTIFICATES_PROTO)], &[proto_dir]).expect("Failed to compile protobuf files!");
}
