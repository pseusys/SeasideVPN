from glob import glob
from pathlib import Path
from shutil import rmtree
from subprocess import run
from sys import argv

from PyInstaller.__main__ import run as install
from python_on_whales import DockerClient
from python_on_whales.utils import run as docker_run

from scripts._utils import ALGAE_ROOT

_EXECUTABLE_NAME = "algae.run"


def generate() -> None:
    command = "protoc -I=vessels --python_betterproto_out=viridian/algae/sources/generated vessels/*.proto"
    generated_dir = ALGAE_ROOT / "sources" / "generated"
    rmtree(generated_dir, ignore_errors=True)
    generated_dir.mkdir(exist_ok=True)
    run(command, cwd=ALGAE_ROOT.parent.parent, shell=True, check=True)


def compile() -> None:
    executable_name = argv[1] if len(argv) > 1 else _EXECUTABLE_NAME
    install(["-F", "-c", "-y", "-n", executable_name, str(ALGAE_ROOT / "sources" / "main.py")])


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
    docker.container.remove(["seaside-algae", "seaside-whirlpool", "seaside-echo", "seaside-internal-router", "seaside-external-router"], True, True)
    docker.image.remove(["seaside-algae-smoke", "seaside-whirlpool-smoke", "seaside-echo-smoke", "seaside-router-smoke", "seaside-algae-default", "seaside-whirlpool-default", "seaside-echo-default", "seaside-algae-sleeping"], True, True)
    docker_run(docker.docker_cmd + ["network", "remove", "--force"] + [f"docker_{net}" for net in ("sea-client", "sea-router", "sea-server", "sea-cli-int", "sea-rout-int", "sea-rout-ext", "sea-serv-ext")])
