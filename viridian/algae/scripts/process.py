from glob import glob
from pathlib import Path
from shutil import rmtree
from subprocess import run as subprocess_run
from sys import argv
from typing import List, Union

from PyInstaller.__main__ import run as install
from python_on_whales import Container, DockerClient
from python_on_whales.components.image.cli_wrapper import ValidImage
from python_on_whales.utils import run as docker_run

from scripts._utils import ALGAE_ROOT

_EXECUTABLE_NAME = "algae.run"


def generate() -> None:
    command = "protoc -I=vessels --python_betterproto_out=viridian/algae/sources/generated vessels/*.proto"
    generated_dir = ALGAE_ROOT / "sources" / "generated"
    rmtree(generated_dir, ignore_errors=True)
    generated_dir.mkdir(exist_ok=True)
    subprocess_run(command, cwd=ALGAE_ROOT.parent.parent, shell=True, check=True)


def compile() -> None:
    executable_name = argv[1] if len(argv) > 1 else _EXECUTABLE_NAME
    paths = ["--specpath", str(ALGAE_ROOT), "--distpath", str(ALGAE_ROOT / "dist"), "--workpath", str(ALGAE_ROOT / "build")]
    install(paths + ["-F", "-c", "-y", "-n", executable_name, str(ALGAE_ROOT / "sources" / "main.py")])


def execute() -> None:
    from sources.main import main

    main(argv[1:])


def clean() -> None:
    for path in glob("**/__pycache__", recursive=True):
        rmtree(path, ignore_errors=True)

    rmtree(".pytest_cache", ignore_errors=True)
    rmtree("build", ignore_errors=True)
    rmtree("dist", ignore_errors=True)
    rmtree("sources/generated", ignore_errors=True)

    Path(f"{_EXECUTABLE_NAME}.spec").unlink(missing_ok=True)
    Path("poetry.lock").unlink(missing_ok=True)

    docker = DockerClient()
    unique_containers: List[Union[str, Container]] = ["seaside-algae", "seaside-whirlpool", "seaside-echo", "seaside-internal-router", "seaside-external-router", "network-disruptor"]
    copy_containers: List[Union[str, Container]] = [f"docker-algae-copy-{n + 1}" for n in range(3)]
    docker.container.remove(unique_containers + copy_containers, True, True)
    algae_images: List[ValidImage] = [f"seaside-algae-{mode}" for mode in ("default", "smoke", "smoke-sleeping", "default-sleeping", "smoke-local", "smoke-remote")]
    whirlpool_images: List[ValidImage] = [f"seaside-whirlpool-{mode}" for mode in ("default", "smoke", "integration", "smoke-local", "smoke-remote")]
    docker.image.remove(["seaside-echo-smoke", "seaside-router-smoke", "seaside-router-smoke-sleeping", "seaside-echo-default", "seaside-echo"] + algae_images + whirlpool_images, True, True)
    docker_network = [f"docker_{net}" for net in ("sea-client", "sea-router", "sea-server", "sea-cli-int", "sea-rout-int", "sea-rout-ext", "sea-serv-ext")]
    docker_run(docker.docker_cmd + ["network", "remove", "--force"] + docker_network)
