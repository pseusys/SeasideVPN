use std::error::Error;
use std::env::set_var;

use protoc_prebuilt::init;


const PROTOC_VERSION: &str = "24.4";


fn main() -> Result<(), Box<dyn Error>> {
    let (protoc_bin, _) = init(PROTOC_VERSION).unwrap();
    set_var("PROTOC", protoc_bin);

    tonic_build::configure()
        .build_server(false)
        .compile_protos(&["common.proto", "whirlpool_viridian.proto"], &["../../vessels"])
        .unwrap();
    Ok(())
}
