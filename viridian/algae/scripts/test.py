from logging import getLogger
from os import environ, getcwd
from pathlib import Path
from re import compile, search
from time import sleep
from typing import Literal, Union

from colorama import Fore, Style, just_fix_windows_console
from pytest import main as pytest
from python_on_whales import DockerClient, DockerException

_ALGAE_ROOT = Path(getcwd()) / "viridian" / "algae"
_OWNER_KEY_REGEX = compile(r"\"Node API setup, node owner key: (\S{32})\"")

logger = getLogger(__name__)


def _test_set(docker_path: Path, profile: Union[Literal["local"], Literal["remote"]]) -> int:
    logger.info(f"Testing {profile}...")
    docker = DockerClient(compose_files=[docker_path / f"compose.{profile}.yml"])
    docker.compose.up(detach=True)

    # Wait for a second to make sure caerulean started TODO: use healthcheck instead
    sleep(15)

    owner_key = search(_OWNER_KEY_REGEX, str(docker.container.logs("whirlpool")))
    if owner_key is not None:
        logger.info(f"Node owner key extracted: {Fore.BLUE}{Style.BRIGHT}{owner_key.group(1)}{Style.RESET_ALL}")
    else:
        logger.critical("Node owner key not found!")
        docker.compose.down()
        return 1

    try:
        test_command = ["poetry", "run", "pytest", "--log-cli-level=DEBUG", f"tests/test_{profile}.py"]
        docker.compose.execute("algae", test_command, envs=dict() if "CI" not in environ else {"CI": environ["CI"]})
        docker.compose.kill(signal="SIGINT")
        logger.info(f"Testing {profile}: {Fore.GREEN}success{Fore.RESET}!")
    except DockerException:
        logger.error(f"Testing {profile}: {Fore.RED}failed{Fore.RESET}!")

        # Wait for a second to synchronize whirlpool logs
        sleep(1)

        logger.error(docker.container.logs("whirlpool"))
        logger.error(docker.container.logs("algae"))
        logger.error(docker.container.logs("seaside-echo"))
        return 1

    return 0


def test() -> int:
    just_fix_windows_console()
    docker_path = _ALGAE_ROOT / "docker"

    docker = DockerClient(compose_files=[docker_path / "compose.base.yml"])
    docker.compose.build()

    result = _test_set(docker_path, "local") + _test_set(docker_path, "remote")
    result += pytest(["--log-cli-level=DEBUG", _ALGAE_ROOT / "tests" / "test_unit.py"])

    docker.compose.rm(stop=True)
    return result
