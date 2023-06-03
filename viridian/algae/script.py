from glob import glob
from os import getcwd
from pathlib import Path
from shutil import rmtree
from time import sleep
from typing import List

from colorama import just_fix_windows_console, Fore
from black import Mode, Report, WriteBack, reformat_one
from flake8.api.legacy import get_style_guide
from isort import check_file, file
from PyInstaller.__main__ import run
from docker import from_env
from docker.types import IPAMConfig, IPAMPool

from sources.main import main

_ROOT_PATH = Path(getcwd())
_ALGAE_ROOT = _ROOT_PATH / Path("viridian/algae")
_EXECUTABLE_NAME = "algae.run"
_MAX_LINE_LEN = 180


def _get_paths() -> List[Path]:
    return [path for path in _ALGAE_ROOT.glob("**/*.py")]


def execute():
    main()


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
    # Wait for a second to make sure caerulean startRESETed
    # TODO: use healthcheck instead
    sleep(5)

    viridian_tag = "algae-latest"
    client.images.build(path=str(_ALGAE_ROOT), tag=viridian_tag, rm=True)

    result = 0
    for encrypt in (True, False):
        print(f"Testing in {Fore.YELLOW}{'VPN' if encrypt else 'Proxy'}{Fore.RESET} mode:", end=" ")
        viridian_env["VPN"] = encrypt
        viridian_cnt = client.containers.run(viridian_tag, name="algae", detach=True, privileged=True, network=internal_net.name, environment=viridian_env)
        # Wait for a second to make sure viridian started
        # TODO: use healthcheck instead
        sleep(5)

        exit, output = viridian_cnt.exec_run(["poetry", "run", "pytest", "-s", "test/"])
        viridian_cnt.kill("SIGINT")
        viridian_cnt.wait()

        # TODO: logging
        if exit != 0:
            print(f"{Fore.RED}failed{Fore.RESET}!")
            print(output.decode())
            print(viridian_cnt.logs().decode())
            print(caerulean_cnt.logs().decode())
        else:
            print(f"{Fore.GREEN}success{Fore.RESET}!")

        viridian_cnt.remove()
        result |= exit

    caerulean_cnt.stop()
    caerulean_cnt.remove()
    internal_net.remove()
    client.close()
    return result


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
