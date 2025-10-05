from glob import glob
from logging import getLogger
from os import makedirs
from pathlib import Path
from shutil import copyfile, rmtree
from sys import argv
from typing import List, Union

# Root of algae viridian source files.
ALGAE_ROOT = Path(__file__).parent.parent

# Default algae executable file name.
_EXECUTABLE_NAME = "algae.run"

# Default caerulean installer file name.
_INSTALLER_NAME = "install.pyz"

# Default logger instance.
logger = getLogger(__name__)


def generate() -> None:
    """
    Generate protobuf source files.
    Previous generation results will be removed.
    Library `betterproto` is used for generation.
    """
    from grpc_tools.protoc import _get_resource_file_name, main

    sources_root = ALGAE_ROOT / "sources" / "generated"
    rmtree(sources_root, ignore_errors=True)
    makedirs(sources_root, exist_ok=True)

    generation_settings = "client_generation=async"
    vessels_root = ALGAE_ROOT.parent.parent / "vessels"
    proto_include = _get_resource_file_name("grpc_tools", "_proto")
    vessels = [str(file) for file in glob(f"{str(vessels_root)}/*.proto", recursive=True)]
    params = [main.__module__, f"-I={proto_include}", f"-I={str(vessels_root)}", f"--python_betterproto2_out={str(sources_root)}", f"--python_betterproto2_opt={generation_settings}"]
    exit(main(params + vessels))


def bundle() -> None:
    """
    Bundle caerulean installation script.
    """
    from tomli import loads
    from zipapps import create_app

    pyproject = Path.cwd() / "pyproject.toml"
    dependencies = loads(pyproject.read_text()).get("project", dict()).get("optional-dependencies", dict()).get("setup", list())

    setup = ALGAE_ROOT / "setup"
    entrypoint = "setup.main:main"
    install_cache = "$TEMP/seaside_install_cache"
    pycache = str((setup / "__pycache__").relative_to(ALGAE_ROOT))
    installer_name = str(ALGAE_ROOT / (argv[1] if len(argv) > 1 else _INSTALLER_NAME))
    create_app(str(setup), output=installer_name, main=entrypoint, compressed=True, lazy_install=True, ensure_pip=True, unzip="*", unzip_path=install_cache, pip_args=dependencies, rm_patterns=pycache)


def clean() -> None:
    """
    Delete all algae generated source files, build files and executables.
    Also remove all related Docker containers, images and networks.
    """

    for path in glob("**/__pycache__", recursive=True):
        rmtree(path, ignore_errors=True)

    rmtree(".pytest_cache", ignore_errors=True)
    rmtree("build", ignore_errors=True)
    rmtree("dist", ignore_errors=True)
    rmtree("certificates", ignore_errors=True)
    rmtree("sources/generated", ignore_errors=True)

    Path(f"{_EXECUTABLE_NAME}.spec").unlink(missing_ok=True)
    Path(_INSTALLER_NAME).unlink(missing_ok=True)
    Path("poetry.lock").unlink(missing_ok=True)

    try:
        from python_on_whales import Container, DockerClient
        from python_on_whales.components.image.cli_wrapper import ValidImage
        from python_on_whales.utils import run

        docker = DockerClient()
        unique_containers: List[Union[str, Container]] = ["seaside-algae", "seaside-whirlpool", "seaside-echo", "seaside-internal-router", "seaside-external-router", "network-disruptor"]
        copy_containers: List[Union[str, Container]] = [f"docker-algae-copy-{n + 1}" for n in range(3)]
        docker.container.remove(unique_containers + copy_containers, force=True, volumes=True)
        algae_images: List[ValidImage] = [f"seaside-algae-{mode}" for mode in ("default", "smoke", "smoke-sleeping", "default-sleeping", "smoke-local", "smoke-remote", "smoke-domain")]
        whirlpool_images: List[ValidImage] = [f"seaside-whirlpool-{mode}" for mode in ("default", "smoke", "integration", "smoke-local", "smoke-remote")]
        docker.image.remove(["seaside-echo-smoke", "seaside-router-smoke", "seaside-router-smoke-sleeping", "seaside-echo-default", "seaside-echo"] + algae_images + whirlpool_images, True, True)
        docker_network = [f"docker_{net}" for net in ("sea-client", "sea-router", "sea-server", "sea-cli-int", "sea-rout-int", "sea-rout-ext", "sea-serv-ext")]
        run(docker.docker_cmd + ["network", "remove", "--force"] + docker_network)

    except ImportError:
        logger.info("Skipping clearing Docker artifacts as 'test' extra is not installed!")
