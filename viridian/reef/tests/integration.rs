use std::error::Error;

use bollard::Docker;
use bollard::exec::{CreateExecOptions, CreateExecResults, StartExecOptions, StartExecResults};
use compose_rs::{Compose, ComposeCommand};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use test_context::{test_context, TestContext};

struct CertificatesContext {
    value: String
}

impl TestContext for CertificatesContext {
    fn setup() -> CertificatesContext {
        CertificatesContext { value: "Hello, world!".to_string() }
    }

    fn teardown(self) {
        // Perform any teardown you wish.
    }
}

#[tokio::test]
#[test_context(CertificatesContext)]
async fn run_integration(_: &mut CertificatesContext) {
    let compose = Compose::builder().path("docker/compose.yml").build().expect("Error building compose file!");
    if let Err(e) = compose.up().exec() {
        panic!("Error starting services: {}", e);
    }

    let docker = Docker::connect_with_local_defaults().expect("Error connecting to Docker daemon!");

    let exec_cmd = vec!["exit", "1"];
    let exec_options = CreateExecOptions {attach_stdout: Some(true), cmd: Some(exec_cmd), ..Default::default()};
    let exec_create_response = docker.create_exec("seaside-reef", exec_options).await;
    if let Err(e) = exec_create_response {
        panic!("Error running test command: {}", e);
    }

    if let Err(e) = compose.down().exec() {
        panic!("Error stopping services: {}", e);
    }
}
