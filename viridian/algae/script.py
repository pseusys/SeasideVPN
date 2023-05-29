from glob import glob
from pathlib import Path
from shutil import rmtree
from typing import List

from black import Mode, Report, WriteBack, reformat_one
from flake8.api.legacy import get_style_guide
from isort import check_file, file
from PyInstaller.__main__ import run
from pytest import main

_ALGAE_ROOT = Path(__file__).parent
_EXECUTABLE_NAME = "algae.run"
_MAX_LINE_LEN = 180


def _get_paths() -> List[Path]:
    return [path for path in _ALGAE_ROOT.glob("**/*.py")]


def lint() -> int:
    lint_result = 0
    selector = ["E", "W", "F"]
    ignore = ["E24", "W503"]
    report = get_style_guide(select=selector, ignore=ignore, max_line_length=_MAX_LINE_LEN).check_files()
    lint_result += sum(len(report.get_statistics(sel)) for sel in selector)
    lint_result += format(False)
    # TODO: Add mypy testing
    # @mypy . --exclude venv*,build
    return lint_result


def format(modify: bool = True) -> int:
    result = True
    report = Report(check=not modify, quiet=False)
    write = WriteBack.YES if modify else WriteBack.CHECK
    for path in _get_paths():
        mode = Mode(line_length=_MAX_LINE_LEN)
        reformat_one(path, False, write, mode, report)
        edited = file(path, line_length=_MAX_LINE_LEN) if modify else check_file(path, True, line_length=_MAX_LINE_LEN)
        result = result and (edited or modify)
    return report.return_code + (0 if result else 1)


def test():
    test_dir = _ALGAE_ROOT / Path("test/")
    return main(["-s", str(test_dir.resolve())])


def build():
    run(["-F", "-c", "-y", "-n", _EXECUTABLE_NAME, "sources/main.py"])


def clean():
    rmtree("build", ignore_errors=True)
    rmtree("dist", ignore_errors=True)
    for path in glob("**/__pycache__", recursive=True):
        rmtree(path, ignore_errors=True)
    for path in glob("*.spec"):
        rmtree(path, ignore_errors=True)
    Path(f"{_EXECUTABLE_NAME}.spec").unlink(missing_ok=True)
    Path("poetry.lock").unlink(missing_ok=True)
