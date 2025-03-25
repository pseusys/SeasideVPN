from argparse import ArgumentParser
from os import getcwd
from pathlib import Path
from sys import argv
from typing import Sequence

from base import Installer
from certificates import check_certificates, generate_certificates
from default import DEFAULT_GENERATED_VALUE, DefaultOptionalAction, local_ip, logging_level
from specific import is_64_bit, is_admin, is_linux
from utils import Logging
from whirlpool import WhirlpoolInstaller

_RAC_NO = "no"
_RAC_BACK = "back"
_RAC_RUN = "run"

_DEFAULT_GENERATE_CERTS = False
_DEFAULT_OVERRIDE_ENV = False
_DEFAULT_RUN_AFTER_CONFIG = _RAC_NO
_DEFAULT_LOG_LEVEL = "INFO"

_ENVIRONMENT_PATH = Path(getcwd()) / "conf.env"


_logging_type = logging_level(_DEFAULT_LOG_LEVEL, True)

parser = ArgumentParser()
parser.add_argument("-g", "--certificates", action="store_true", default=_DEFAULT_GENERATE_CERTS, help=f"Generate self-signed certificates (if they don't exist yet, default: {_DEFAULT_GENERATE_CERTS})")
parser.add_argument("-o", "--override-env-file", action="store_true", default=_DEFAULT_OVERRIDE_ENV, help=f"Override existing environment file (if it exists, default: {_DEFAULT_OVERRIDE_ENV})")
parser.add_argument("-a", "--run-after-config", choices=(_RAC_NO, _RAC_BACK, _RAC_RUN), default=_DEFAULT_RUN_AFTER_CONFIG, help=f"Run caerulean after configuration is done ('{_RAC_NO}' for don't run, '{_RAC_BACK}' for running in the background, '{_RAC_RUN}' for running in foreground, default: {_DEFAULT_RUN_AFTER_CONFIG})")
parser.add_argument("-v", "--verbose", type=_logging_type, default=DEFAULT_GENERATED_VALUE, help=f"Logging level for installation process (default: {_DEFAULT_LOG_LEVEL})")
parser.add_argument("--just-certs", type=local_ip(False), action=DefaultOptionalAction, help="Generate self-signed certificates for the given IP or host and exit (even if they already exist, default: not present)")
subparsers = parser.add_subparsers(title="Caeruleans", description="Install and configure different caeruleans", help="Caerulean name to install")
WhirlpoolInstaller.create_parser(subparsers)


def main(args: Sequence[str] = argv[1:]) -> None:
    """
    Run the installation script with given args.
    :param args: arguments list for argument parser.
    """
    namespace = vars(parser.parse_args(args))
    logger = Logging.init(namespace["verbose"])

    certs_address = namespace.pop("just_certs", None)
    if certs_address is not None:
        logger.info(f"Just generating certificates for {certs_address}...")
        generate_certificates(certs_address, remove_existing=True)
        logger.info("Certificates generated successfully!")
        exit(0)

    if not is_linux() or not is_64_bit():
        logger.error("Installer can run on 64 bit Linux platforms only!")
        exit(1)

    if not is_admin():
        logger.error("Can not install without admin permissions!")
        exit(1)

    installer_class = namespace.pop("installer", None)
    if installer_class is None:
        logger.error("No caerulean selected for installation!")
        exit(1)

    installer: Installer = installer_class(namespace)
    logger.info(f"Running using selected caerulean installer: {type(installer).__name__}")

    if not installer.verify():
        logger.info(f"Verification with {type(installer).__name__} failed!")
        exit(1)

    if namespace["override_env_file"] or not _ENVIRONMENT_PATH.exists():
        logger.info(f"Overriding environment file {str(_ENVIRONMENT_PATH)}...")
        _ENVIRONMENT_PATH.write_text("\n".join(f"{k}={v}" for k, v in installer.create_environment().items()))
        logger.info("Environment file ready!")

    if namespace["certificates"]:
        logger.info("Refreshing certificates if they are not present...")
        installer.refresh_certificates()
        logger.info("Certificates generated successfully!")
    elif not check_certificates():
        logger.error("Certificates not found, consider adding 'cert.key' and 'cert.crt' to 'certificates' directory!")

    logger.info(f"Installing with {type(installer).__name__} installer...")
    installer.install()
    installer.print_info(namespace["verbose"] > _logging_type(_DEFAULT_LOG_LEVEL))
    logger.info("Caerulean installed!")

    if namespace["run_after_config"] != _RAC_NO:
        logger.info(f"Running with {type(installer).__name__} installer...")
        installer.run(namespace["run_after_config"] == _RAC_RUN)
    else:
        logger.warning(f"Configuration is done! Run this command to launch the server when you're ready:\n{installer.run_command}")
