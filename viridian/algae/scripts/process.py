from argparse import ArgumentParser
from glob import glob
from logging import getLogger
from os import makedirs
from pathlib import Path
from shutil import copyfileobj, rmtree, unpack_archive
from stat import S_IRWXU
from subprocess import CalledProcessError, run
from sys import argv
from typing import List, Union
from urllib.request import urlopen

# Different source files roots.
ALGAE_ROOT = Path(__file__).parent.parent
_DEFAULT_VESSELS_ROOT = ALGAE_ROOT.parent.parent / "vessels"
_DEFAULT_GENERATED_ROOT = ALGAE_ROOT / "sources" / "interaction"

# Flatbuffers compiler downloading coordinates:
_FLATC_VERSION = "v25.2.10"
_FLATC_ARCHIVE = "Linux.flatc.binary.g++-13.zip"
_FLATC_RELEASE_URL = f"https://github.com/google/flatbuffers/releases/download/{_FLATC_VERSION}/{_FLATC_ARCHIVE}"

# Default caerulean installer file name.
_INSTALLER_NAME = "install.pyz"

# Default logger instance.
logger = getLogger(__name__)


def generate(vessels_root: Path = _DEFAULT_VESSELS_ROOT, generated_root: Path = _DEFAULT_GENERATED_ROOT) -> None:
    """
    Generate flatbuffers source files.
    Previous generation results will be removed.
    Library `betterproto` is used for generation.
    """
    sources_root = ALGAE_ROOT / "flatbuffers-compiler"
    if not sources_root.exists():
        logger.debug("Creating cache directory...")
        makedirs(sources_root, exist_ok=True)

    archive_path = sources_root / _FLATC_ARCHIVE
    if not archive_path.exists():
        logger.debug("Compiler archive not found, downloading...")
        with urlopen(_FLATC_RELEASE_URL) as response, open(archive_path, "wb") as out_file:
            copyfileobj(response, out_file)

    executable_path = sources_root / "flatc"
    if not executable_path.exists():
        logger.debug("Compiler binary not found, unpacking...")
        unpack_archive(archive_path, sources_root)
        executable_path.chmod(S_IRWXU)

    makedirs(_DEFAULT_GENERATED_ROOT, exist_ok=True)
    vessels = [str(file) for file in glob(f"{str(vessels_root)}/*.fbs", recursive=True)]
    params = ["--python", "--grpc", "--reflect-types", "--gen-mutable", "--gen-object-api", "--gen-compare", "--python-typing", "--grpc-filename-suffix=", "-I", str(vessels_root), "-o", str(generated_root)]

    try:
        logger.debug(f"Running compiler '{executable_path}' with arguments '{params}' for files '{vessels}'...")
        run([executable_path] + params + vessels, capture_output=True, check=True, text=True)
    except CalledProcessError as e:
        logger.error(f"Code generation error:\n{e.stderr}")
        exit(e.returncode)


def bundle() -> None:
    """
    Bundle caerulean installation script.
    """
    from tomli import loads
    from zipapps import create_app

    pyproject = Path.cwd() / "pyproject.toml"
    dependencies = loads(pyproject.read_text()).get("project", dict()).get("optional-dependencies", dict()).get("setup", list())
    logger.debug(f"Installer dependencies resolved: {dependencies}")

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
    for path in glob("sources/generated/*.fb.*", recursive=True):
        rmtree(path, ignore_errors=True)

    rmtree(".pytest_cache", ignore_errors=True)
    rmtree("build", ignore_errors=True)
    rmtree("dist", ignore_errors=True)
    rmtree("certificates", ignore_errors=True)
    rmtree("flatbuffers-compiler", ignore_errors=True)
    rmtree("sources/interaction/generated", ignore_errors=True)

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


parser = ArgumentParser()
parser.add_argument("-s", "--source", default=_DEFAULT_VESSELS_ROOT, type=Path, help=f"Path to the vessels directory (default: {_DEFAULT_VESSELS_ROOT})")
parser.add_argument("-d", "--destination", default=_DEFAULT_GENERATED_ROOT, type=Path, help=f"Path to the generated files directory (default: {_DEFAULT_GENERATED_ROOT})")

if __name__ == "__main__":
    arguments = vars(parser.parse_args(argv[1:]))
    generate(arguments["source"], arguments["destination"])
