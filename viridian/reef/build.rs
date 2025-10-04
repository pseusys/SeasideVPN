use std::env::var;
use std::path::PathBuf;

use prost_build::Config;
use protoc_bin_vendored::{include_path, protoc_bin_path};

const CERTIFICATES_PROTO: &str = "certificates.proto";

fn main() {
    let proto_dir = PathBuf::from(var("CARGO_MANIFEST_DIR").unwrap()).parent().unwrap().parent().unwrap().join("vessels");
    let proto_certificates_file = proto_dir.join(CERTIFICATES_PROTO);
    assert!(proto_certificates_file.exists(), "Certificates protobuf definition doesn't exist!");

    let mut prost_build = Config::new();
    prost_build.protoc_executable(protoc_bin_path().unwrap());
    prost_build.compile_protos(&[proto_certificates_file], &[proto_dir, include_path().unwrap()]).expect("Failed to compile protobuf files!");
}
