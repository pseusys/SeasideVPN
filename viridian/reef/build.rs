use std::error::Error;


fn main() -> Result<(), Box<dyn Error>> {
    tonic_build::configure()
        .build_server(false)
        .compile_protos(&["common.proto", "whirlpool_viridian.proto"], &["../../vessels"])
        .unwrap();
    Ok(())
}
