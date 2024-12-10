from logging import Logger
from pkg_resources import parse_version
from pathlib import Path
from re import search
from subprocess import DEVNULL, SubprocessError, check_call, check_output
from typing import Optional

# See "https://github.com/chef/os_release" for different "os_release" formats
_BASE_DISTROS = {"debian", "alpine"}
_OS_RELEASE_FILE = Path("/etc/os-release")

_SEMVER_REGEX = r"\d+\.\d+\.\d+"


def _get_distro() -> str:
    os_id, os_like = str(), str()
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


def check_package(logger: Logger, package: str, version: Optional[str], version_command: str = "--version") -> bool:
    try:
        logger.debug(f"Checking if package {package} exists...")
        check_call(f"command -v {package}", stdout=DEVNULL, stderr=DEVNULL, shell=True)
        logger.debug(f"Package {package} found!")
        if version is not None:
            logger.debug(f"Checking package {package} version...")
            semver = search(_SEMVER_REGEX, check_output(f"{package} {version_command}", shell=True).decode())
            if semver is not None:
                package_version = semver.group()
                versions_match = parse_version(package_version) >= parse_version(version)
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


def check_install_package(logger: Logger, package: str) -> None:
    if not check_package(logger, package):
        logger.debug(f"Installing package {package}...")
        check_call(_install_package_command().format(pack=package), stdout=DEVNULL, stderr=DEVNULL, shell=True)
        logger.debug(f"Package {package} installed!")


def check_install_packages(logger: Logger, *packages: str) -> None:
    for package in packages:
        check_install_package(logger, package)
