from logging import getLogger
from os import getcwd
from pathlib import Path

from black import Mode, Report, WriteBack, reformat_one
from flake8.api.legacy import get_style_guide
from isort import check_file, file
from mypy import api

_ALGAE_ROOT = Path(getcwd()) / "viridian" / "algae"
_MAX_LINE_LEN = 180

logger = getLogger(__name__)


def lint() -> int:
    lint_result = 0
    selector = ["E", "W", "F"]
    ignore = ["E24", "W503"]
    report = get_style_guide(select=selector, ignore=ignore, max_line_length=_MAX_LINE_LEN).check_files()
    lint_result += sum(len(report.get_statistics(sel)) for sel in selector)
    lint_result += format(False)
    mypy_opts = ["--strict", "--ignore-missing-imports", "--no-namespace-packages"]
    out, err, code = api.run(mypy_opts + [str(file) for file in _ALGAE_ROOT.glob("**/*.py")])
    if code != 0:
        logger.error(out)
        logger.error(err)
    lint_result += code
    return lint_result


def format(modify: bool = True) -> int:
    result = True
    report = Report(check=not modify, quiet=False)
    write = WriteBack.YES if modify else WriteBack.CHECK
    for path in _ALGAE_ROOT.glob("**/*.py"):
        mode = Mode(line_length=_MAX_LINE_LEN)
        reformat_one(path, False, write, mode, report)
        edited = file(path, line_length=_MAX_LINE_LEN) if modify else check_file(path, True, line_length=_MAX_LINE_LEN)
        result = result and (edited or modify)
    return report.return_code + (0 if result else 1)
