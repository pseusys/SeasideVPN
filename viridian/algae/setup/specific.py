from pathlib import Path
from platform import machine, system
from re import search
from subprocess import DEVNULL, SubprocessError, check_call, check_output
from typing import Optional

from utils import Logging, semver_to_tuple

# See "https://github.com/chef/os_release" for different "os_release" formats
_BASE_DISTROS = {"debian", "alpine"}
_OS_RELEASE_FILE = Path("/etc/os-release")

_SEMVER_REGEX = r"\d+\.\d+\.\d+"


def _get_distro() -> Optional[str]:
    """
    Get the current linux destribution name (or a similar one) from the list in `_BASE_DISTROS`.
    Reads and parses `/etc/os-release` file for that, uses either `ID` or `ID_LIKE` value.
    If the current distribution is not found in `_BASE_DISTROS`, just return the `ID` value.
    :return: linux distribution name or `None` if the file does not exist.
    """
    os_id, os_like = str(), str()
    if not _OS_RELEASE_FILE.exists():
        return None
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
    """
    Run package installation command (using default package manager) for the current linux distribution.
    If the current distribution is not supported, an error will be raised.
    """
    platform_version = _get_distro()
    if platform_version == "debian":
        return "apt-get install -y --no-install-recommends {pack}"
    elif platform_version == "alpine":
        return "apk add --no-cache {pack}"
    else:
        raise RuntimeError(f"Current platform '{platform_version}' distribution is either not supported or unknown!")


def check_package(package: str, version: Optional[str] = None, version_command: str = "--version") -> bool:
    """
    Check if the given package is installed, optionally check its version.
    If the version is not specified, it will not be checked.
    Version should be specified as semantic version, "A.B.C", the same format is expected to be found in the package version output.
    Versions will be compared as 3-integer tuples.
    :param package: package name.
    :param version: required varsion to check, default `None`.
    :param version_command: command to check package version, default "--version".
    :return: `True` if package exists (and version matches, if specified), `False` otherwise.
    """
    logger = Logging.logger_for(__name__)
    try:
        logger.debug(f"Checking if package {package} exists...")
        check_call(f"command -v {package}", stdout=DEVNULL, stderr=DEVNULL, shell=True)
        logger.debug(f"Package {package} found!")
        if version is not None:
            logger.debug(f"Checking package {package} version...")
            semver = search(_SEMVER_REGEX, check_output(f"{package} {version_command}", shell=True).decode())
            if semver is not None:
                package_version = semver.group()
                versions_match = semver_to_tuple(package_version) >= semver_to_tuple(version)
                logger.debug(f"Found package version '{package_version}', required '{version}', versions match: {versions_match}")
                return versions_match
            else:
                logger.debug(f"Semversion is not found in '{package} {version_command}' output!")
                return False
        else:
            logger.debug("Proceeding without checking package version...")
            return True
    except SubprocessError:
        logger.debug(f"Package {package} not found!")
        return False


def check_install_package(package: str) -> None:
    """
    Check if the given package is installed locally, install it from the default package manager if not.
    :param package: package name.
    """
    logger = Logging.logger_for(__name__)
    if not check_package(package):
        logger.debug(f"Installing package {package}...")
        check_call(_install_package_command().format(pack=package), stdout=DEVNULL, stderr=DEVNULL, shell=True)
        logger.debug(f"Package {package} installed!")


def check_install_packages(*packages: str) -> None:
    """
    Check if the given packages are installed locally, install them from the default package manager if not.
    :param packages: package names.
    """
    for package in packages:
        check_install_package(package)


def is_linux() -> bool:
    """
    Check if the current system is linux.
    :return: `True` if linux, `False` otherwise.
    """
    return system() == "Linux"


def is_64_bit() -> bool:
    """
    Check if the current system is 64bit.
    :return: `True` if the system is 64bit, `False` otherwise.
    """
    return machine().endswith("64")


def is_admin() -> bool:
    """
    Check if the current user is superuser.
    :return: `True` if superuser, `False` otherwise.
    """
    try:
        from os import getuid
        return getuid() == 0
    except ImportError:
        return False


# See "https://superuser.com/a/1757852" for different possible architecture names (the list might be not complete though)
def get_arch() -> str:
    """
    Get the current system architecture, whether it is compatible with "amd" or "arm" systems.
    :return: "amd" if the current system is AMD- or Intel-compatible, "arm" if it is ARM-compatible.
    """
    arch = machine()
    if arch.startswith("amd") or arch.startswith("x86_64"):
        return "amd"
    elif arch.startswith("arm") or arch.startswith("aarch"):
        return "arm"
    else:
        raise RuntimeError(f"Unknown processor architecture: {arch}!")
