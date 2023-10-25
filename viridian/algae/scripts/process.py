from glob import glob
from os import getcwd
from pathlib import Path
from shutil import rmtree
from sys import argv

from PyInstaller.__main__ import run

_ALGAE_ROOT = Path(getcwd()) / "viridian" / "algae"
_EXECUTABLE_NAME = "algae.run"


def compile() -> None:
    executable_name = argv[1] if len(argv) > 1 else _EXECUTABLE_NAME
    run(["-F", "-c", "-y", "-n", executable_name, str(_ALGAE_ROOT / "sources" / "main.py")])


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
