from asyncio import run as async_run
from glob import glob
from pathlib import Path
from shutil import rmtree
from subprocess import DEVNULL, check_call
from sys import argv, executable
from typing import List, Union
from zipapp import create_archive

from colorama import Fore, Style, just_fix_windows_console
from PyInstaller.__main__ import run as install
from python_on_whales import Container, DockerClient
from python_on_whales.components.image.cli_wrapper import ValidImage
from python_on_whales.utils import run as docker_run

from scripts.misc import ALGAE_ROOT

# Default algae executable file name.
_EXECUTABLE_NAME = "algae.run"

# Default caerulean installer file name.
_INSTALLER_NAME = "install.pyz"


def generate() -> None:
    """
    Generate protobuf source files.
    Previous generation results will be removed.
    Library `betterproto` is used for generation.
    """
    command = f"{executable} -m grpc_tools.protoc -I=vessels --python_betterproto_out=viridian/algae/sources vessels/*.proto"
    generated_dir = ALGAE_ROOT / "sources" / "generated"
    rmtree(generated_dir, ignore_errors=True)
    check_call(command, cwd=ALGAE_ROOT.parent.parent, stdout=DEVNULL, stderr=DEVNULL, shell=True)


def compile() -> None:
    """
    Generate single algae executable.
    Library `pyinstaller` is used for generation.
    """
    executable_name = argv[1] if len(argv) > 1 else _EXECUTABLE_NAME
    paths = ["--specpath", str(ALGAE_ROOT), "--distpath", str(ALGAE_ROOT / "dist"), "--workpath", str(ALGAE_ROOT / "build")]
    install(paths + ["-F", "-c", "-y", "-n", executable_name, str(ALGAE_ROOT / "sources" / "main.py")])


def execute() -> None:
    """
    Import and execute main function of algae module.
    Pass console arguments to it.
    """
    from sources.main import main

    async_run(main(argv[1:]))


def bundle() -> None:
    """
    Bundle caerulean installation script.
    """
    installer_name = argv[1] if len(argv) > 1 else _INSTALLER_NAME
    create_archive(ALGAE_ROOT / "setup", ALGAE_ROOT / installer_name, main="main:main", compressed=True)


def clean() -> None:
    """
    Delete all algae generated source files, build files and executables.
    Also remove all related Docker conatiners, images and networks.
    """
    for path in glob("**/__pycache__", recursive=True):
        rmtree(path, ignore_errors=True)

    rmtree(".pytest_cache", ignore_errors=True)
    rmtree("build", ignore_errors=True)
    rmtree("dist", ignore_errors=True)
    rmtree("certificates", ignore_errors=True)
    rmtree("sources/generated", ignore_errors=True)

    Path(f"{_EXECUTABLE_NAME}.spec").unlink(missing_ok=True)
    Path("poetry.lock").unlink(missing_ok=True)

    docker = DockerClient()
    unique_containers: List[Union[str, Container]] = ["seaside-algae", "seaside-whirlpool", "seaside-echo", "seaside-internal-router", "seaside-external-router", "network-disruptor"]
    copy_containers: List[Union[str, Container]] = [f"docker-algae-copy-{n + 1}" for n in range(3)]
    docker.container.remove(unique_containers + copy_containers, force=True, volumes=True)
    algae_images: List[ValidImage] = [f"seaside-algae-{mode}" for mode in ("default", "smoke", "smoke-sleeping", "default-sleeping", "smoke-local", "smoke-remote", "smoke-domain")]
    whirlpool_images: List[ValidImage] = [f"seaside-whirlpool-{mode}" for mode in ("default", "smoke", "integration", "smoke-local", "smoke-remote")]
    docker.image.remove(["seaside-echo-smoke", "seaside-router-smoke", "seaside-router-smoke-sleeping", "seaside-echo-default", "seaside-echo"] + algae_images + whirlpool_images, True, True)
    docker_network = [f"docker_{net}" for net in ("sea-client", "sea-router", "sea-server", "sea-cli-int", "sea-rout-int", "sea-rout-ext", "sea-serv-ext")]
    docker_run(docker.docker_cmd + ["network", "remove", "--force"] + docker_network)


def help() -> None:
    """
    Print poetry commands summary.
    """
    just_fix_windows_console()
    print(f"{Style.BRIGHT}Available poetry scripts{Style.RESET_ALL}:")
    print(f"\t{Fore.BLUE}poetry poe generate{Fore.RESET}: generate protobuf sources (using betterproto library).")
    print(f"\t{Fore.BLUE}poetry poe lint{Fore.RESET}: run Python code linting locally.")
    print(f"\t{Fore.BLUE}poetry poe format{Fore.RESET}: run Python code formatting locally.")
    print(f"\t{Fore.BLUE}poetry poe test-unit{Fore.RESET}: run algae unit tests in a Docker container.")
    print(f"\t{Fore.BLUE}poetry poe test-integration{Fore.RESET}: run seaside integration tests in a Docker container.")
    print(f"\t{Fore.BLUE}poetry poe test-smoke{Fore.RESET}: run seaside smoke tests in a Docker container.")
    print(f"\t{Fore.BLUE}poetry poe test-local{Fore.RESET}: run seaside local smoke tests in a Docker container (without access to internet).")
    print(f"\t{Fore.BLUE}poetry poe test-remote{Fore.RESET}: run seaside remote smoke tests in a Docker container.")
    print(f"\t{Fore.BLUE}poetry poe test-domain{Fore.RESET}: run seaside domain smoke tests in a Docker container.")
    print(f"\t{Fore.BLUE}poetry poe test-all{Fore.RESET}: run all possible tests in a Docker container.")
    print(f"\t{Fore.BLUE}poetry poe compile{Fore.RESET}: compile algae Python source code to an executable (using pyinstaller library).")
    print(f"\t{Fore.BLUE}poetry poe execute [ARGS...]{Fore.RESET}: execute algae Python sources locally (ARGS will be passed to the executable).")
    print(f"\t{Fore.BLUE}poetry poe bundle{Fore.RESET}: bundle caerulean installation script 'install.pyz', required for caerulean installation and certificates generation.")
    print(f"\t{Fore.BLUE}poetry poe clean{Fore.RESET}: clean all the build files, executables, Docker images, containers and networks.")
    print(f"\t{Fore.BLUE}poetry poe help{Fore.RESET}: print this message again.")
    print(f"{Style.BRIGHT}Arguments for algae executable (ARGS){Style.RESET_ALL}:")
    print(f"\t{Fore.YELLOW}[PAYLOAD]{Fore.RESET}: caerulean payload string (required!).")
    print(f"\t{Fore.GREEN}-a --address [ADDRESS]{Fore.RESET}: caerulean remote IP address (default: 127.0.0.1).")
    print(f"\t{Fore.GREEN}-n --ctrlport [CTRLPORT]{Fore.RESET}: caerulean network port number (default: 8587).")
    print(f"\t{Fore.GREEN}-t --tunnel [TUNNEL]{Fore.RESET}: tunnel interface name (default: seatun).")
    print(f"\t{Fore.GREEN}-l --link [LINK]{Fore.RESET}: connection link, will be used instead of other arguments if specified.")
    print(f"{Style.BRIGHT}Connection link format{Style.RESET_ALL}:")
    print(f"\t{Fore.CYAN}seaside+[NODE_TYPE]://[ADDRESS]:[CTRLPORT]/[PAYLOAD]{Fore.RESET}")
