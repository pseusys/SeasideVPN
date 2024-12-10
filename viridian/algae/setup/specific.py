from logging import Logger
from pathlib import Path
from subprocess import DEVNULL, SubprocessError, check_call

# See "https://github.com/chef/os_release" for different "os_release" formats
_BASE_DISTROS = {"debian", "alpine"}

_OS_RELEASE_FILE = Path("/etc/os-release")


def _get_distro() -> str:
    os_id, os_like = None, None
    for line in _OS_RELEASE_FILE.read_text().split("\n"):
        if line.startswith("ID="):
            os_id = line.split("=")[-1].strip("\" '")
        elif line.startswith("ID_LIKE="):
            os_like = line.split("=")[-1].strip("\" '")
    if os_id in _BASE_DISTROS:
        return os_id
    for like in os_like.split(" "):
        if like in _BASE_DISTROS:
            return like
    return os_id


def _install_package_command() -> str:
    platform_version = _get_distro()
    if platform_version == "debian":
        return "apt-get install -y --no-install-recommends {pack}"
    elif platform_version == "alpine":
        return "apk add --no-cache {pack}"
    else:
        raise RuntimeError(f"Current platform '{platform_version}' distribution is either not supported or unknown!")


def check_package(logger: Logger, package: str) -> bool:
    try:
        logger.debug(f"Checking if package {package} exists...")
        check_call(f"command -v {package}", stdout=DEVNULL, stderr=DEVNULL, shell=True)
        logger.debug(f"Package {package} found!")
        return True
    except SubprocessError:
        logger.debug(f"Package {package} not found!")
        return False


def check_install_package(logger: Logger, package: str) -> None:
    if not check_package(logger, package):
        logger.debug(f"Installing package {package}...")
        check_call(_install_package_command().format(pack=package), stdout=DEVNULL, stderr=DEVNULL, shell=True)
        logger.debug(f"Package {package} installed!")


def check_install_packages(logger: Logger, *packages: str) -> None:
    for package in packages:
        check_install_package(logger, package)
