from contextlib import contextmanager
from os import environ
from pathlib import Path
from typing import Iterator, Tuple

from python_on_whales import DockerClient

# Root of algae viridian source files.
ALGAE_ROOT = Path(__file__).parent.parent


@contextmanager
def docker_test() -> Iterator[Tuple[Path, bool]]:
    """
    Build all base Docker images and prepare Docker client.
    Context manager, yields path to "algae/docker" directory and current docker client.
    :return: iterator of tuples: path to docker directory and flag if currently in CI environment.
    """
    hosted = "CI" in environ
    docker_path = ALGAE_ROOT / "docker"
    docker = DockerClient(compose_files=[docker_path / "compose.default.yml"])
    try:
        docker.compose.build(quiet=hosted)
        yield docker_path, hosted
    finally:
        docker.compose.rm(stop=True)
