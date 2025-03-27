from logging import getLogger
from pathlib import Path
from typing import List, Optional

from black import Mode, Report, WriteBack, reformat_one  # type: ignore
from flake8.api.legacy import get_style_guide
from isort import check_file, file
from mypy.api import run

# Root of algae viridian source files.
ALGAE_ROOT = Path(__file__).parent.parent

# Maximum python sources line length.
_MAX_LINE_LEN = 500

# All the project files will be checked, except for "__init__.py"s (the default option)
_FILES = [str(file) for file in ALGAE_ROOT.glob("*/[!_]*.py")]

# Default logger instance.
logger = getLogger(__name__)


def lint(files: Optional[List[str]] = None) -> int:
    """
    Run python code linting.
    "Error", "warning" and "fatal" levels of `flake8` library are chacked.
    Library `black` is also used without source files modification.
    :param files: list of files to check, `None` for all project files.
    :return: exit code integer.
    """

    files = _FILES if files is None else files
    lint_result = 0

    selector = ["E", "W", "F"]
    ignore = ["E24", "W503", "E203"]  # E24 and W503 are recommended, E203 conflicts with `black`.
    report = get_style_guide(select=selector, ignore=ignore, max_line_length=_MAX_LINE_LEN).check_files(files)
    lint_result += sum(len(report.get_statistics(sel)) for sel in selector)

    lint_result += format(files, False)

    cache_dir = str(ALGAE_ROOT / ".mypy_cache")
    mypy_opts = ["--strict", "--ignore-missing-imports", "--cache-dir", cache_dir, "--explicit-package-bases"]
    out, err, code = run(mypy_opts + files)
    if code != 0:
        logger.error(f"{out}\n{err}")
    lint_result += code

    return lint_result


def format(files: Optional[List[str]] = None, modify: bool = True) -> int:
    """
    Format python code using `black` library.
    :param files: list of files to check, `None` for all prject files.
    :param modify: whether source files should be modified.
    :return: exit code integer.
    """

    files = _FILES if files is None else files
    result = True

    report = Report(check=not modify, quiet=False)
    write = WriteBack.YES if modify else WriteBack.CHECK
    args = dict(line_length=_MAX_LINE_LEN, profile="black")

    for path in ALGAE_ROOT.glob("**/[!_]*.py"):
        mode = Mode(line_length=_MAX_LINE_LEN)
        reformat_one(path, False, write, mode, report)
        edited = file(path, **args) if modify else check_file(path, True, **args)
        result = result and (edited or modify)

    return report.return_code + (0 if result else 1)
