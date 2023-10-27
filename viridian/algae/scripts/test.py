from logging import getLogger
from os import environ, getcwd
from pathlib import Path
from time import sleep
from typing import Literal, Union

from colorama import Fore, just_fix_windows_console
from pytest import main as pytest
from python_on_whales import DockerClient, DockerException

from scripts._utils import ALGAE_ROOT

logger = getLogger(__name__)


def _test_set(docker_path: Path, profile: Union[Literal["local"], Literal["remote"]]) -> int:
    logger.info(f"Testing {profile}...")
    docker = DockerClient(compose_files=[docker_path / f"compose.{profile}.yml"])
    docker.compose.up(wait=True, detach=True)

    # Wait for 15 seconds to make sure caerulean started TODO: use healthcheck instead
    sleep(15)

    try:
        test_command = ["poetry", "run", "pytest", "--log-cli-level=DEBUG", f"tests/test_{profile}.py"]
        docker.compose.execute("algae", test_command, envs=dict() if "CI" not in environ else {"CI": environ["CI"]})
        docker.compose.kill(signal="SIGINT")
        logger.info(f"Testing {profile}: {Fore.GREEN}success{Fore.RESET}!")
    except DockerException:
        logger.error(f"Testing {profile}: {Fore.RED}failed{Fore.RESET}!")

        # Wait for a second to synchronize whirlpool logs
        sleep(1)

        logger.error(docker.container.logs("algae"))
        logger.error(docker.container.logs("whirlpool"))
        logger.error(docker.container.logs("seaside-echo"))

        docker.compose.kill()
        return 1

    return 0


def test() -> int:
    just_fix_windows_console()
    docker_path = ALGAE_ROOT / "docker"

    docker = DockerClient(compose_files=[docker_path / "compose.base.yml"])
    docker.compose.build()

    result = _test_set(docker_path, "local") # + _test_set(docker_path, "remote")
    # result += pytest(["--log-cli-level=DEBUG", _ALGAE_ROOT / "tests" / "test_unit.py"])

    docker.compose.rm(stop=True)
    return result
