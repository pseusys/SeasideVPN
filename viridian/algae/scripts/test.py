from ipaddress import IPv4Address
from logging import getLogger
from os import environ
from pathlib import Path
from shutil import rmtree
from typing import Literal, Union

from colorama import Fore, Style
from python_on_whales import DockerClient, DockerException
from yaml import safe_load

from setup.certificates import generate_certificates

Profile = Union[Literal["local"], Literal["remote"], Literal["integration"], Literal["unit"]]

# Root of algae viridian source files.
ALGAE_ROOT = Path(__file__).parent.parent

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
        logger.error(docker.logs(container, tail=last))
    except DockerException:
        logger.error(f"{Style.BRIGHT}{Fore.RED}No container {container} found!{Style.RESET_ALL}")


def test_set(profile: Profile) -> None:
    """
    Launch specified compose file and launch specified test set inside of it.
    Print test output and any errors that happened.
    :param docker_path: path to "algae/docker" directory, containing all dockerfiles and compose files.
    :param profile: name of the testing profile, one of "local", "remote", "domain", "integration", "unit".
    :param hosted: flag, whether the current test set is being run in CI (disables verbose output).
    :return: integer return code, 0 if tests succeeded.
    """
    hosted = "CI" in environ.keys()
    docker_path = ALGAE_ROOT / "docker"

    logger.warning(f"{Style.BRIGHT}{Fore.BLUE}Testing {profile}...{Style.RESET_ALL}")
    compose_file = docker_path / f"compose.{profile}.yml"
    docker = DockerClient(compose_files=[compose_file])
    before_networks = set([net.name for net in docker.network.list()])

    certificates_path = docker_path.parent / "certificates"
    whirlpool_conf = safe_load(compose_file.read_text())["services"].get("whirlpool", None)
    if whirlpool_conf is not None:
        logger.debug("Generating self-signed testing certificates...")
        generate_certificates(IPv4Address(whirlpool_conf["environment"]["SEASIDE_ADDRESS"]), certificates_path, True)
        logger.debug("Self-signed certificates generated!")
    else:
        logger.debug("Just creating certificates folders with user permissions...")
        certificates_path.mkdir(parents=True, exist_ok=True)

    try:
        logger.debug("Building containers...")
        docker.compose.build(build_args={"RUNNING_IN_CI": "1" if hosted else "0"}, quiet=hosted)
        logger.debug("Running tests...")
        docker.compose.up(wait=False, detach=False, abort_on_container_exit=True, quiet=hosted)

        logger.warning(f"{Style.BRIGHT}Testing {profile}: {Fore.GREEN}success{Fore.RESET}!{Style.RESET_ALL}")
        exit_code = 0

    except DockerException as exc:
        logger.error(f"Testing {profile}: {Style.BRIGHT}{Fore.RED}failed{Fore.RESET}!{Style.RESET_ALL}")
        logger.error(f"Error message: {exc}")

        _print_container_logs(docker, "seaside-algae")
        _print_container_logs(docker, "seaside-whirlpool")
        if profile == "local":
            _print_container_logs(docker, "seaside-echo")
            _print_container_logs(docker, "network-disruptor")
            for i in range(1, 4):
                _print_container_logs(docker, f"seaside-algae-local-algae-copy-{i}")

        docker.compose.kill()
        exit_code = 1

    except KeyboardInterrupt:
        logger.error(f"Testing {profile}: {Style.BRIGHT}{Fore.YELLOW}interrupted{Fore.RESET}!{Style.RESET_ALL}")
        docker.compose.kill()
        exit_code = 1

    after_networks = set([net.name for net in docker.network.list()]) - before_networks
    docker.compose.rm(stop=True, volumes=True)
    docker.network.remove(list(after_networks))

    logger.debug("Clearing self-signed testing certificates (if any)...")
    rmtree(certificates_path, ignore_errors=True)
    logger.debug("Self-signed certificates removed (if any)!")
    exit(exit_code)
