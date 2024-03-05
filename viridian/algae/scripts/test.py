from logging import getLogger
from os import environ
from pathlib import Path
from typing import Literal, Union

from colorama import Fore, Style, just_fix_windows_console
from python_on_whales import DockerClient, DockerException

from scripts.misc import docker_test, generate_certificates

# Default logger instance.
logger = getLogger(__name__)


def _print_container_logs(docker: DockerClient, container: str, last: int = 100) -> None:
    """
    Print container logs if container exists. Otherwise display warning.
    :param docker: current Docker client.
    :param container: container name string.
    :param last: number of last lines to print (default: 100).
    """
    try:
        logger.error(f"{Style.BRIGHT}{Fore.YELLOW}Container {container} logs:{Style.RESET_ALL}")
        logger.error(docker.compose.logs(container, tail=str(last)))
    except DockerException:
        logger.error(f"{Style.BRIGHT}{Fore.RED}No container {container} found!{Style.RESET_ALL}")


def _test_set(docker_path: Path, profile: Union[Literal["local"], Literal["remote"], Literal["integration"], Literal["unit"]], hosted: bool) -> int:
    """
    Launch specified compose file and launch speceified test set inside of it.
    Print test output and any errors that happened.
    :param docker_path: path to "algae/docker" directory, containing all dockerfiles and compose files.
    :param profile: name of the testing profile, one of "local", "remote", "integration", "unit".
    :param hosted: flag, whether the current test set is being run in CI (disables verbose output).
    :return: integer return code, 0 if tests succeeded.
    """
    logger.warning(f"{Style.BRIGHT}{Fore.BLUE}Testing {profile}...{Style.RESET_ALL}")
    docker = DockerClient(compose_files=[docker_path / f"compose.{profile}.yml"])
    before_networks = set([net.name for net in docker.network.list()])

    try:
        docker.compose.up(wait=True, build=True, detach=True, quiet=hosted)

        test_command = ["pytest", f"--log-cli-level={'ERROR' if hosted else 'DEBUG'}", "-k", f"test_{profile}"]
        docker.compose.execute("algae", test_command, envs=dict() if not hosted else {"CI": environ["CI"]})

        docker.compose.kill(signal="SIGINT")
        logger.warning(f"{Style.BRIGHT}Testing {profile}: {Fore.GREEN}success{Fore.RESET}!{Style.RESET_ALL}")
        exit_code = 0

    except DockerException as exc:
        logger.error(f"Testing {profile}: {Style.BRIGHT}{Fore.RED}failed{Fore.RESET}!{Style.RESET_ALL}")
        logger.error(f"Error message: {exc}")

        _print_container_logs(docker, "algae")
        _print_container_logs(docker, "whirlpool")
        if profile == "local":
            _print_container_logs(docker, "seaside-echo")
            _print_container_logs(docker, "network-disruptor")
            for i in range(3):
                _print_container_logs(docker, f"docker-algae-copy-{i}")

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


def test_unit() -> int:
    """
    Run unit tests: all the algae client functions in particular.
    :return: integer return code.
    """
    just_fix_windows_console()
    with docker_test() as (docker_path, hosted):
        return _test_set(docker_path, "unit", hosted)


def test_integration() -> int:
    """
    Run integration tests: sequence of VPN connection, disconnection and other control requests.
    :return: integer return code.
    """
    just_fix_windows_console()
    with docker_test() as (docker_path, hosted), generate_certificates():
        return _test_set(docker_path, "integration", hosted)


def test_local() -> int:
    """
    Run local smoke tests: connection is made to local TCP server in a Doocker container.
    Also network packet random drop (50%) is enabled ("gaiaadm/pumba" library is used).
    :return: integer return code.
    """
    just_fix_windows_console()
    with docker_test() as (docker_path, hosted), generate_certificates():
        return _test_set(docker_path, "local", hosted)


def test_remote() -> int:
    """
    Run remote smoke tests: connection is made to several remote servers.
    Several different transport and application layer protocols are used.
    :return: integer return code.
    """
    just_fix_windows_console()
    with docker_test() as (docker_path, hosted), generate_certificates():
        return _test_set(docker_path, "remote", hosted)


def test_smoke() -> int:
    """
    Run smoke tests: run both "local" and "remote" smoke tests (specified above).
    :return: integer return code.
    """
    just_fix_windows_console()
    with docker_test() as (docker_path, hosted), generate_certificates():
        result = 0
        for test_set in ("local", "remote"):
            result = result or _test_set(docker_path, test_set, hosted)  # type: ignore[arg-type]
        return result


def test_all() -> int:
    """
    Run tests: run all tests (specified above).
    :return: integer return code.
    """
    just_fix_windows_console()
    with docker_test() as (docker_path, hosted), generate_certificates():
        result = 0
        for test_set in ("unit", "integration", "local", "remote"):
            result = result or _test_set(docker_path, test_set, hosted)  # type: ignore[arg-type]
        return result
