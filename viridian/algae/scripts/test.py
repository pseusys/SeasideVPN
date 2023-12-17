from logging import getLogger
from os import environ
from pathlib import Path
from time import sleep
from typing import Literal, Union

from colorama import Fore, Style, just_fix_windows_console
from python_on_whales import DockerClient, DockerException
from python_on_whales.exceptions import NoSuchContainer

from scripts._utils import ALGAE_ROOT

logger = getLogger(__name__)


def _print_container_logs(docker: DockerClient, container: str, last: int = 100) -> None:
    try:
        logger.error(f"{Style.BRIGHT}{Fore.YELLOW}Container {container} logs:{Style.RESET_ALL}")
        logger.error(docker.container.logs(container, tail=last))
    except NoSuchContainer: 
        logger.error(f"{Style.BRIGHT}{Fore.RED}No container {container} found!{Style.RESET_ALL}")


def _test_set(docker_path: Path, profile: Union[Literal["local"], Literal["remote"]], local: bool) -> int:
    logger.info(f"{Style.BRIGHT}{Fore.BLUE}Testing {profile}...{Style.RESET_ALL}")
    docker = DockerClient(compose_files=[docker_path / f"compose.{profile}.yml"])
    before_networks = set([net.name for net in docker.network.list()])

    try:
        docker.compose.up(wait=True, build=True, detach=True, quiet=local)

        test_command = ["pytest", "--log-cli-level=DEBUG", f"tests/test_{profile}.py"]
        docker.compose.execute("algae", test_command, envs=dict() if local else {"CI": environ["CI"]})

        docker.compose.kill(signal="SIGINT")
        logger.info(f"{Style.BRIGHT}Testing {profile}: {Fore.GREEN}success{Fore.RESET}!{Style.RESET_ALL}")
        exit_code = 0

    except DockerException as exc:
        logger.error(f"Testing {profile}: {Style.BRIGHT}{Fore.RED}failed{Fore.RESET}!{Style.RESET_ALL}")
        logger.error(f"Error message: {exc}")

        # Wait for a second to synchronize whirlpool logs
        sleep(1)

        _print_container_logs(docker, "algae")
        _print_container_logs(docker, "whirlpool")
        _print_container_logs(docker, "seaside-echo")

        docker.compose.kill()
        exit_code = 1

    except KeyboardInterrupt:
        logger.error(f"Testing {profile}: {Style.BRIGHT}{Fore.YELLOW}interrupted{Fore.RESET}!{Style.RESET_ALL}")
        docker.compose.kill()
        exit_code = 1

    after_networks = set([net.name for net in docker.network.list()]) - before_networks
    docker.compose.rm(stop=True)
    docker.network.remove(list(after_networks))
    return exit_code


def test() -> int:
    just_fix_windows_console()
    local = "CI" not in environ
    docker_path = ALGAE_ROOT / "docker"

    docker = DockerClient(compose_files=[docker_path / "compose.default.yml"])
    docker.compose.build(quiet=local)

    result = _test_set(docker_path, "local", local) + _test_set(docker_path, "remote", local)
    # result += pytest(["--log-cli-level=DEBUG", _ALGAE_ROOT / "tests" / "test_unit.py"])

    docker.compose.rm(stop=True)
    return result
