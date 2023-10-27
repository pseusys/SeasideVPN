from glob import glob
from pathlib import Path
from shutil import rmtree
from subprocess import run
from sys import argv

from PyInstaller.__main__ import run as install

from scripts._utils import ALGAE_ROOT

_EXECUTABLE_NAME = "algae.run"


def generate() -> None:
    command = "protoc -I=vessels --python_out=viridian/algae/generated --experimental_allow_proto3_optional vessels/*.proto"
    generated_dir = ALGAE_ROOT / "generated"
    rmtree(generated_dir, ignore_errors=True)
    generated_dir.mkdir(exist_ok=True)
    run(command, cwd=ALGAE_ROOT.parent.parent, shell=True, check=True)


def compile() -> None:
    executable_name = argv[1] if len(argv) > 1 else _EXECUTABLE_NAME
    install(["-F", "-c", "-y", "-n", executable_name, str(ALGAE_ROOT / "sources" / "main.py")])


def clean() -> None:
    rmtree("build", ignore_errors=True)
    rmtree("dist", ignore_errors=True)
    rmtree(".pytest_cache", ignore_errors=True)
    for path in glob("**/__pycache__", recursive=True):
        rmtree(path, ignore_errors=True)
    for path in glob("*.spec"):
        rmtree(path, ignore_errors=True)
    Path(f"{_EXECUTABLE_NAME}.spec").unlink(missing_ok=True)
    Path("poetry.lock").unlink(missing_ok=True)
