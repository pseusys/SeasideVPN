from glob import glob
from logging import getLogger
from os import environ, getcwd
from pathlib import Path
from shutil import rmtree
from sys import argv
from time import sleep

from black import Mode, Report, WriteBack, reformat_one
from colorama import Fore, just_fix_windows_console
from docker import from_env
from docker.types import IPAMConfig, IPAMPool
from flake8.api.legacy import get_style_guide
from isort import check_file, file
from mypy import api
from PyInstaller.__main__ import run

from sources.main import main

_ROOT_PATH = Path(getcwd())
_ALGAE_ROOT = _ROOT_PATH / Path("viridian/algae")
_EXECUTABLE_NAME = "algae.run"
_MAX_LINE_LEN = 180

logger = getLogger(__name__)


def execute() -> None:
    main()


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


def test() -> int:
    just_fix_windows_console()
    client = from_env()

    internal_pool = IPAMPool(subnet="10.0.0.0/24", gateway="10.0.0.1")
    internal_ipam = IPAMConfig(pool_configs=[internal_pool])
    internal_net = client.networks.create("sea-int", driver="bridge", ipam=internal_ipam)

    caerulean_address = "10.0.0.87"
    caerulean_env = dict(ADDRESS="10.0.0.87", LOG_LEVEL="DEBUG")
    viridian_env = dict(ADDRESS="10.0.0.87", LOG_LEVEL="DEBUG")

    caerulean_path = _ROOT_PATH / Path("caerulean/whirlpool")
    caerulean_tag = "whirlpool-latest"
    client.images.build(path=str(caerulean_path), tag=caerulean_tag, rm=True)
    caerulean_cnt = client.containers.create(caerulean_tag, name="whirlpool", detach=True, privileged=True, network="none", environment=caerulean_env)

    client.networks.get("none").disconnect(caerulean_cnt)
    internal_net.connect(caerulean_cnt, ipv4_address=caerulean_address)
    caerulean_cnt.start()

    # Wait for a second to make sure caerulean started
    sleep(1)

    viridian_tag = "algae-latest"
    client.images.build(path=str(_ALGAE_ROOT), tag=viridian_tag, rm=True)

    if "CI" in environ:
        viridian_env["CI"] = caerulean_env["CI"] = "CI"

    viridian_cnt = client.containers.run(viridian_tag, name="algae", detach=True, privileged=True, network=internal_net.name, environment=viridian_env)
    # Wait for a second to make sure viridian started
    sleep(1)

    exit, output = viridian_cnt.exec_run(["poetry", "run", "pytest", "--log-cli-level=DEBUG", "test/"])
    viridian_cnt.kill("SIGINT")
    viridian_cnt.wait()

    if exit != 0:
        logger.error(f"Testing: {Fore.RED}failed{Fore.RESET}!")
        logger.error(output.decode())
        logger.error(viridian_cnt.logs().decode())
        logger.error(caerulean_cnt.logs().decode())
    else:
        logger.info(f"Testing: {Fore.GREEN}success{Fore.RESET}!")

    viridian_cnt.remove()
    caerulean_cnt.stop()
    caerulean_cnt.remove()
    internal_net.remove()
    client.close()
    return exit


def build() -> None:
    executable_name = argv[1] if len(argv) > 1 else _EXECUTABLE_NAME
    run(["-F", "-c", "-y", "-n", executable_name, str(_ALGAE_ROOT / Path("sources/main.py"))])


def clean() -> None:
    rmtree("build", ignore_errors=True)
    rmtree("dist", ignore_errors=True)
    for path in glob("**/__pycache__", recursive=True):
        rmtree(path, ignore_errors=True)
    for path in glob("*.spec"):
        rmtree(path, ignore_errors=True)
    Path(f"{_EXECUTABLE_NAME}.spec").unlink(missing_ok=True)
    Path("poetry.lock").unlink(missing_ok=True)
