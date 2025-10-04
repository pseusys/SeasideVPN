use std::env::var;
use std::path::PathBuf;

use prost_build::Config;
use protoc_bin_vendored::{include_path, protoc_bin_path};

const CERTIFICATES_PROTO: &str = "certificates.proto";

fn main() {
    let mut prost_build = Config::new();
    prost_build.protoc_executable(protoc_bin_path().unwrap());
    let proto_dir = PathBuf::from(var("CARGO_MANIFEST_DIR").unwrap()).parent().unwrap().parent().unwrap().join("vessels").canonicalize().unwrap();
    prost_build.compile_protos(&[CERTIFICATES_PROTO], &[proto_dir, include_path().unwrap()]).expect("Failed to compile protobuf files!");
}
