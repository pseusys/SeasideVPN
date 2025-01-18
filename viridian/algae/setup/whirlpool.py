from argparse import ArgumentParser, _SubParsersAction
from os import environ
from pathlib import Path
from shutil import copy, move, rmtree
from subprocess import DEVNULL, Popen, SubprocessError, check_call
from tarfile import open as open_tar
from typing import Dict, Optional
from urllib.request import urlretrieve

from semver import Version

from base import Installer
from certificates import GENERATE_CERTIFICATES_PATH, generate_certificates
from default import DEFAULT_GENERATED_VALUE, local_ip, logging_level, payload_value, port_number
from specific import check_install_packages, check_package, get_arch
from utils import BLUE, BOLD, GREEN, RED, RESET, UNDER, YELLOW

_PARSER_NAME = "whirlpool"
_VERSION = '"0.0.3"'

_DT_COMPILE = "compile"
_DT_DOCKER = "docker"
_DT_BINARY = "binary"

_DEFAULT_SOURCE_TAG = "main"
_DEFAULT_DOCKER_LABEL = "latest"
_DEFAULT_BINARY_NAME = "latest"
_DEFAULT_DISTRIBUTION_TYPE = _DT_BINARY

_PAYLOAD_SIZE = 16
_MIN_PORT_VALUE = 1024
_MAX_PORT_VALUE = (1 << 16) - 1

_DEFAULT_CERTIFICATES_PATH = "certificates"
_DEFAULT_LOG_PATH = "log"
_DEFAULT_MAX_VIRIDIANS = 10
_DEFAULT_MAX_ADMINS = 5
_DEFAULT_WAITING_OVERTIME = 15
_DEFAULT_FIRST_HEALTHCHECK_DELAY = 3
_DEFAULT_MAXIMUM_NEXTIN = 15
_DEFAULT_TUNNEL_MTU = -1
_DEFAULT_TUNNEL_NAME = "seatun"
_DEFAULT_VPN_DATA_LIMIT = -1
_DEFAULT_CONTROL_PACKET_LIMIT = 3
_DEFAULT_ICMP_PACKET_LIMIT = 5
_DEFAULT_BURST_LIMIT_MULTIPLIER = 3
_DEFAULT_LOG_LEVEL = "WARNING"

_GO_VERSION = Version(1, 22)

_SEASIDE_REPO = "https://github.com/pseusys/SeasideVPN"
_SEASIDE_IMAGE = "ghcr.io/pseusys/seasidevpn/caerulean-whirlpool"
_GO_DISTRIBUTION = "https://go.dev/dl/go{ver}.linux-{arch}.tar.gz"

_ACCEPT_IPV6_CONF = Path("/proc/sys/net/ipv6/conf/default/accept_ra")
_PACKET_FORWARDING_CONF = Path("/proc/sys/net/ipv4/ip_forward")

_SHELL_LOGIN = Path("/etc/profile")
_GO_ROOT = Path("/usr/local/go")

_PROTOGO_PACKAGE = "github.com/pseusys/protogo"

_logging_type = logging_level(_DEFAULT_LOG_LEVEL, False)


class WhirlpoolInstaller(Installer):
    @classmethod
    def create_parser(cls, subparser: "_SubParsersAction[ArgumentParser]") -> None:
        parser = subparser.add_parser(_PARSER_NAME, help="Install whirlpool caerulean")
        parser.add_argument("-s", "--source-tag", default=_DEFAULT_SOURCE_TAG, help=f"GitHub branch name for code pulling (will be used only with '--distribution-type={_DT_COMPILE}' and has no effect otherwise, default: {_DEFAULT_SOURCE_TAG})")
        parser.add_argument("-d", "--docker-label", default=_DEFAULT_DOCKER_LABEL, help=f"Docker image label (will be used only with '--distribution-type={_DT_DOCKER}' and has no effect otherwise, default: {_DEFAULT_DOCKER_LABEL})")
        parser.add_argument("-b", "--binary-name", default=_DEFAULT_BINARY_NAME, help=f"Pre-compiled binary type (will be used only with '--distribution-type={_DT_BINARY}' and has no effect otherwise, default: {_DEFAULT_BINARY_NAME})")
        parser.add_argument("-r", "--distribution-type", choices=(_DT_COMPILE, _DT_DOCKER, _DT_BINARY), default=_DEFAULT_DISTRIBUTION_TYPE, help=f"Distribution type to run ('{_DT_COMPILE}' for compiling from source, '{_DT_DOCKER}' for running in Docker, '{_DT_BINARY}' for running a binary, default: {_DEFAULT_DISTRIBUTION_TYPE})")
        parser.add_argument("-o", "--payload-owner", type=payload_value(_PAYLOAD_SIZE), default=DEFAULT_GENERATED_VALUE, help="Whirlpool owner payload value (should be a secure long ASCII string, default: [will be generated])")
        parser.add_argument("-v", "--payload-viridian", nargs="*", action="extend", default=list(), help="Whirlpool viridian payload value (should be secure long ASCII strings, default: empty list)")
        parser.add_argument("-a", "--internal-address", type=local_ip(True), default=DEFAULT_GENERATED_VALUE, help="Internal whirlpool address (default: first host address)")
        parser.add_argument("-e", "--external-address", type=local_ip(True), default=DEFAULT_GENERATED_VALUE, help="External whirlpool address (default: first host address)")
        parser.add_argument("-p", "--control-port", type=port_number(_MIN_PORT_VALUE, _MAX_PORT_VALUE), default=DEFAULT_GENERATED_VALUE, help=f"Seaside control port number (default: random, between {_MIN_PORT_VALUE} and {_MAX_PORT_VALUE})")
        parser.add_argument("--certificates-path", type=str, default=_DEFAULT_CERTIFICATES_PATH, help=f"Path for storing certificates, two files should be present there, 'cert.crt' and 'key.crt' (default: {_DEFAULT_CERTIFICATES_PATH})")
        parser.add_argument("--logs-path", type=str, default=_DEFAULT_LOG_PATH, help=f"Path for storing logs, two files will be created there, 'danger.log' and 'safe.log' (default: {_DEFAULT_LOG_PATH})")
        parser.add_argument("--max-viridians", type=int, default=_DEFAULT_MAX_VIRIDIANS, help=f"Maximum network viridian number (default: {_DEFAULT_MAX_VIRIDIANS})")
        parser.add_argument("--max-admins", type=int, default=_DEFAULT_MAX_ADMINS, help=f"Maximum privileged viridian number (default: {_DEFAULT_MAX_ADMINS})")
        parser.add_argument("--waiting-overtime", type=int, default=_DEFAULT_WAITING_OVERTIME, help=f"Maximum additional waiting time for healthcheck message (default: {_DEFAULT_WAITING_OVERTIME})")
        parser.add_argument("--first-delay", type=int, default=_DEFAULT_FIRST_HEALTHCHECK_DELAY, help=f"Maximum waiting time for the first healthcheck message (default: {_DEFAULT_FIRST_HEALTHCHECK_DELAY})")
        parser.add_argument("--max-nextin", type=int, default=_DEFAULT_MAXIMUM_NEXTIN, help=f"Maximum waiting time between helathchecks (default: {_DEFAULT_MAXIMUM_NEXTIN})")
        parser.add_argument("--tunnel-mtu", type=int, default=_DEFAULT_TUNNEL_MTU, help=f"VPN tunnel interface MTU (default: {_DEFAULT_TUNNEL_MTU})")
        parser.add_argument("--tunnel-name", default=_DEFAULT_TUNNEL_NAME, help=f"VPN tunnel interface name (default: {_DEFAULT_TUNNEL_NAME})")
        parser.add_argument("--vpn-data-limit", type=int, default=_DEFAULT_VPN_DATA_LIMIT, help=f"Limit of data transferred through sea port (default: {_DEFAULT_VPN_DATA_LIMIT})")
        parser.add_argument("--ctrl-packet-limit", type=int, default=_DEFAULT_CONTROL_PACKET_LIMIT, help=f"Limit of control packets transferred through control port (default: {_DEFAULT_CONTROL_PACKET_LIMIT})")
        parser.add_argument("--icmp-packet-limit", type=int, default=_DEFAULT_ICMP_PACKET_LIMIT, help=f"Limit of ICMP (ping) packets transferred (default: {_DEFAULT_ICMP_PACKET_LIMIT})")
        parser.add_argument("--burst-limit-mult", type=int, default=_DEFAULT_BURST_LIMIT_MULTIPLIER, help=f"All firewall limit burst multiplier (default: {_DEFAULT_BURST_LIMIT_MULTIPLIER})")
        parser.add_argument("--log-level", type=_logging_type, default=DEFAULT_GENERATED_VALUE, help=f"Logging level for whirlpool node (default: {_DEFAULT_LOG_LEVEL})")
        parser.set_defaults(installer=cls)

    @property
    def run_command(self) -> str:
        if self._args["distribution_type"] in (_DT_COMPILE, _DT_BINARY):
            return "set -a && . ./conf.env && sudo ./whirlpool.run && disown -r"
        elif self._args["distribution_type"] == _DT_DOCKER:
            return f"docker run --rm --name seaside-whirlpool --env-file=conf.env --sysctl net.ipv6.conf.all.disable_ipv6=1 --network host --privileged {_SEASIDE_IMAGE}:{self._args['docker_label']}"
        else:
            raise RuntimeError(f"Unknown distribution type: {self._args['distribution_type']}")

    def verify(self) -> bool:
        if self._args["distribution_type"] == _DT_DOCKER and not check_package("docker"):
            self._logger.error("Docker not found, can not run in docker!")
            return False
        return True

    def create_environment(self) -> Dict[str, str]:
        environment = dict()
        environment["SEASIDE_PAYLOAD_OWNER"] = self._args["payload_owner"]
        environment["SEASIDE_PAYLOAD_VIRIDIAN"] = ":".join(self._args["payload_viridian"])
        environment["SEASIDE_ADDRESS"] = self._args["internal_address"]
        environment["SEASIDE_EXTERNAL"] = self._args["external_address"]
        environment["SEASIDE_CTRLPORT"] = self._args["control_port"]
        environment["SEASIDE_CERTIFICATE_PATH"] = self._args["certificates_path"]
        environment["SEASIDE_LOG_PATH"]= self._args["logs_path"]
        environment["SEASIDE_MAX_VIRIDIANS"] = self._args["max_viridians"]
        environment["SEASIDE_MAX_ADMINS"] = self._args["max_admins"]
        environment["SEASIDE_WAITING_OVERTIME"] = self._args["waiting_overtime"]
        environment["SEASIDE_FIRST_HEALTHCHECK_DELAY"] = self._args["first_delay"]
        environment["SEASIDE_MAXIMUM_NEXTIN"] = self._args["max_nextin"]
        environment["SEASIDE_TUNNEL_MTU"] = self._args["tunnel_mtu"]
        environment["SEASIDE_TUNNEL_NAME"] = self._args["tunnel_name"]
        environment["SEASIDE_VPN_DATA_LIMIT"] = self._args["vpn_data_limit"]
        environment["SEASIDE_CONTROL_PACKET_LIMIT"] = self._args["ctrl_packet_limit"]
        environment["SEASIDE_ICMP_PACKET_LIMIT"] = self._args["icmp_packet_limit"]
        environment["SEASIDE_BURST_LIMIT_MULTIPLIER"] = self._args["burst_limit_mult"]
        environment["SEASIDE_LOG_LEVEL"] = _logging_type(self._args["log_level"])
        return environment

    def refresh_certificates(self) -> None:
        self._logger.debug("Generating certificates...")
        generate_certificates(self._args["internal_address"], remove_existing=True)
        self._logger.debug("Copying certificates to the caerulean root...")
        caerulean_certs = GENERATE_CERTIFICATES_PATH / "caerulean"
        copy(caerulean_certs / "cert.key", GENERATE_CERTIFICATES_PATH)
        copy(caerulean_certs / "cert.crt", GENERATE_CERTIFICATES_PATH)
        self._logger.debug("Certificates ready!")

    def _configure_server(self) -> None:
        if int(_ACCEPT_IPV6_CONF.read_text()) != 0:
            self._logger.info("Disabling IPv6 for the server...")
            _ACCEPT_IPV6_CONF.write_text("0")
            self._logger.info("IPv6 support disabled!")
        else:
            self._logger.debug("IPv6 already disabled!")
        if int(_PACKET_FORWARDING_CONF.read_text()) != 1:
            self._logger.info("Enabling packet forwarding for the server...")
            _PACKET_FORWARDING_CONF.write_text("1")
            self._logger.info("Packet forwarding enabled!")
        else:
            self._logger.debug("Packet forwarding already disabled!")

    def _install_go(self) -> Path:
        arch = "arm64" if get_arch() == "arm" else "amd64"
        rmtree(_GO_ROOT, ignore_errors=True)
        go_url = _GO_DISTRIBUTION.format(ver=str(_GO_VERSION), arch=arch)
        self._logger.debug(f"Downloading GO from {go_url}...")
        path, _ = urlretrieve(go_url)
        self._logger.debug(f"Extracting GO archive: {str(path)}...")
        with open_tar(path, "r:gz") as archive:
            archive.extractall(_GO_ROOT.parent)
        go_path = _GO_ROOT / "bin"
        with open(_SHELL_LOGIN, "a+") as file:
            file.write(f"export PATH={str(go_path)}:$PATH")
        check_call(f"chmod +x {str(go_path / 'go')}", stdout=DEVNULL, stderr=DEVNULL, shell=True)
        return go_path

    def _install_go_package(self, go_exec: Optional[str], package: str) -> None:
        """Install one GO package with given executable."""
        try:
            self._logger.debug(f"Checking if GO package '{package}' exists...")
            check_call(f"{go_exec} list {package}", stdout=DEVNULL, stderr=DEVNULL, shell=True)
            self._logger.debug(f"GO package '{package}' found!")
        except SubprocessError:
            self._logger.debug(f"GO package '{package}' not found, installing...")
            check_call(f"{go_exec} install {package}@latest", stdout=DEVNULL, stderr=DEVNULL, shell=True)
            self._logger.debug(f"GO package '{package}' installed!")

    def _prepare_environment(self) -> Optional[Path]:
        """Prepare environment for building whirlpool executable: install GO (and also some GO packages)."""
        if not check_package("go", _GO_VERSION, "version"):
            self._logger.info("Installing GO...")
            go_path = self._install_go()
            self._logger.info(f"GO installed to {go_path}!")
        else:
            self._logger.info("Global GO found!")
            go_path = None
        go_exec = "go" if go_path is None else str(go_path / "go")
        self._logger.info(f"Installing GO packages with {go_exec} executable...")
        self._install_go_package(go_exec, _PROTOGO_PACKAGE)
        self._logger.info("All the GO packages installed!")
        return go_path

    def _mark_binary_as_executable(self, executable: Path) -> None:
        """Mark executable as executable so that it can be run from console."""
        check_call(f"chmod +x {str(executable)}", stdout=DEVNULL, stderr=DEVNULL, shell=True)

    def _download_and_build_sources(self, go_path: Optional[Path]) -> None:
        """Download source code from GitHub to ./SeasideVPN directory and build the whirlpool executable."""
        check_install_packages("git", "make")
        exepath = Path("whirlpool.run")
        seapath = Path("SeasideVPN")
        go_env = environ.copy()
        go_env["PATH"] = f"{str(go_path)}:{environ['PATH']}" if go_path is not None else environ["PATH"]
        self._logger.debug(f"PATH prepared for caerulean building: {go_env['PATH']}")
        self._logger.debug("Cloning SeasideVPN repository...")
        check_call(f"git clone -n --branch {self._args['source_tag']} --depth=1 --filter=tree:0 {_SEASIDE_REPO}", stdout=DEVNULL, stderr=DEVNULL, shell=True)
        self._logger.debug("Performing a sparse checkout...")
        check_call("git sparse-checkout set --no-cone caerulean/whirlpool vessels && git checkout", cwd=seapath, stdout=DEVNULL, stderr=DEVNULL, shell=True)
        self._logger.debug("Building whirlpool...")
        check_call("make build", cwd=seapath / "caerulean" / "whirlpool", env=go_env, stdout=DEVNULL, stderr=DEVNULL, shell=True)
        self._logger.debug("Moving executable...")
        move(seapath / "caerulean" / "whirlpool" / "build" / "whirlpool.run", exepath)
        self._logger.debug("Marking executable as executable...")
        self._mark_binary_as_executable(exepath)
        self._logger.debug("Deleting build files...")
        rmtree(seapath)

    def _pull_docker_image(self) -> None:
        """Pull whirlpool image from GitHub Docker image registry."""
        check_call(f"docker pull ghcr.io/pseusys/seasidevpn/caerulean-whirlpool:{self._args['docker_label']}", stdout=DEVNULL, stderr=DEVNULL, shell=True)

    def _download_binary(self) -> None:
        arch = "arm64" if get_arch() == "arm" else "amd64"
        if self._args["binary_name"] == _DEFAULT_BINARY_NAME:
            binary_url = f"{_SEASIDE_REPO}/releases/latest/download/caerulean-whirlpool-executable-{arch}.run"
        else:
            binary_url = f"{_SEASIDE_REPO}/releases/download/{self._args['binary_name']}/caerulean-whirlpool-executable-{arch}.run"
        exepath = Path("whirlpool.run")
        self._logger.debug(f"Downloading whirlpool binary from {binary_url}...")
        urlretrieve(binary_url, exepath)
        self._logger.debug("Marking executable as executable...")
        self._mark_binary_as_executable(exepath)

    def install(self) -> None:
        if self._args["distribution_type"] == _DT_COMPILE:
            self._logger.info("Preparing Seaside Whirlpool build environment...")
            go_executable = self._prepare_environment()
            self._logger.info("Environment prepared, starting build...")
            self._download_and_build_sources(go_executable)
            self._logger.info("Seaside Whirlpool built!")
        elif self._args["distribution_type"] == _DT_DOCKER:
            self._logger.info("Pulling Seaside Whirlpool Docker image...")
            self._pull_docker_image()
            self._logger.info("Seaside Whirlpool Docker image downloaded!")
        elif self._args["distribution_type"] == _DT_BINARY:
            self._logger.info("Downloading Seaside Whirlpool release binary...")
            self._download_binary()
            self._logger.info("Seaside Whirlpool release binary downloaded!")
        else:
            raise RuntimeError(f"Unknown distribution type: {self._args['distribution_type']}")
        self._logger.info("Configuring server...")
        self._configure_server()
        self._logger.info("Server configured!")

    def print_info(self, hide: bool) -> None:
        """Print configuration of the node that will be applied upon running."""
        owner_payload = "***" if hide else self._args["payload_owner"]
        host_name = f"{self._args['internal_address']}:{self._args['control_port']}"
        print("\n\n>> ================================================ >>")
        print(f"{BOLD}{GREEN}Seaside Whirlpool node version {_VERSION} successfully configured!{RESET}")
        print(f"The node address is: {GREEN}{host_name}{RESET}")
        print(f"The administrator payload is: {BLUE}{owner_payload}{RESET}")
        print(f"\tConnection link: {YELLOW}{UNDER}seaside+whirlpool://{host_name}?payload={owner_payload}{RESET}")
        if len(self._args["payload_viridian"]) > 0:
            print(f"The viridian payloads are: {BLUE}{self._args['payload_viridian']}{RESET}")
            for link in self._args["payload_viridian"]:
                print(f"\tConnection link: {YELLOW}{UNDER}seaside+whirlpool://{host_name}?payload={link}{RESET}")
        print(f"{BOLD}{RED}NB! In order to replicate the server, store and reuse the ./conf.env file!{RESET}")
        print("<< ================================================ <<\n\n")

    def run(self, foreground: bool) -> None:
        if foreground:
            self._logger.info("Starting command in the foreground...")
            check_call(self.run_command, shell=True)
        else:
            self._logger.info("Starting command in the background...")
            Popen(self.run_command, stdout=DEVNULL, stderr=DEVNULL, shell=True)
            self._logger.info("Command running in the background!")
