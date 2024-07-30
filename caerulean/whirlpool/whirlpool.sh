#!/bin/bash

set -e

# Prepare environment and launch whirlpool node (locally or in Docker).
# Create environment variables file and certificates directory if necessary.

# Formatting:
BOLD="\033[1m"
UNDER="\033[4m"
BLUE="\033[34m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"



# Global arguments:

# Whirlpool owner payload value
SEASIDE_PAYLOAD_OWNER=$(cat /dev/urandom | base64 | head -c 16)
# Whirlpool viridian payload value
SEASIDE_PAYLOAD_VIRIDIAN=$(cat /dev/urandom | base64 | head -c 16)
# Internal whirlpool address (first host address by default)
SEASIDE_ADDRESS=$(hostname -I | awk '{print $1}')
# External whirlpool address (same as local address by default)
SEASIDE_EXTERNAL=$SEASIDE_ADDRESS
# Seaside control port number (random by default, no TCP processes are expected)
SEASIDE_CTRLPORT=$((1000 + RANDOM % 50000))
# Maximum network viridian number
SEASIDE_MAX_VIRIDIANS=10
# Maximum privileged viridian number
SEASIDE_MAX_ADMINS=5
# Maximum additional waiting time for healthcheck message
SEASIDE_VIRIDIAN_WAITING_OVERTIME=5
# Maximum waiting time for the first healthcheck message
SEASIDE_VIRIDIAN_FIRST_HEALTHCHECK_DELAY=3
# VPN tunnel interface MTU
SEASIDE_TUNNEL_MTU=-1
# Limit of data transferred through sea port
SEASIDE_VPN_DATA_LIMIT=-1
# Limit of control packets transferred through control port
SEASIDE_CONTROL_PACKET_LIMIT=3
# Limit of ICMP (ping) packets transferred
SEASIDE_ICMP_PACKET_LIMIT=5
# All firewall limit burst multiplier
SEASIDE_BURST_LIMIT_MULTIPLIER=3
# Logging level for whirlpool node
SEASIDE_LOG_LEVEL=WARNING

# GitHub branch name for code pulling
WHIRLPOOL_SOURCE_TAG=main
# Docker image label
WHIRLPOOL_DOCKER_LABEL=latest
# Command that will be run after configuration is finished
COMMAND="echo 'whirlpool node running...'"
# Run in Docker container
RUN_IN_DOCKER=false
# Regenerate ./conf.env file
GENERATE_ENV_FILE=false
# Regenerate ./certificates key and cert files
GENERATE_CERTS=false
# Run node after configuration
RUN_NODE=false
# Use no ASCII text formatting
TEXT_MODE=false
# Just generate the certificates and exit
CERTIFY_AND_EXIT=false
# Just print script help and exit
HELP_AND_EXIT=false
# Invalid option flags found
INVALID_OPTIONS_FOUND=false



# Arguments for local installation only:

# Go version (for local installation only)
GO_VERSION="1.22.0"
# Protoc version (for local installation only)
PROTOC_VERSION="3.15.8"



# Functions:

# Check if commands exist, exit with code 1 otherwise.
# #@: Commands to check.
function check_command_exists() {
    for comm in "$@" ; do
        if ! $(command -v "$comm" &> /dev/null) ; then
            echo "Command '$comm' is not found!"
            exit 1
        fi
    done
}

# Regenerate (self-signed) certificas in ./certificates directory.
# Certificates will be valid for 1000 years, prime256v1 algorithm will be used.
# #1: IP address to authorize the certificate for.
function generate_certificates() {
    $(check_command_exists openssl &> /dev/null) || apt-get install -y --no-install-recommends openssl

    if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] ; then
        local ALTNAMES="subjectAltName = IP:$1"
    else
        local ALTNAMES="subjectAltName = DNS:$1"
    fi

    local SUBJECT="/C=TS/ST=TestState/L=PC/O=SeasideVPN/OU=viridian-algae/CN=Algae"
    local VALIDITY=365250
    local ALGORITHM=prime256v1

    rm -rf certificates/
    mkdir certificates/
    openssl ecparam -genkey -name "$ALGORITHM" -noout -out certificates/cert.key
    openssl req -new -x509 -sha256 -key certificates/cert.key -out certificates/cert.crt -days "$VALIDITY" -addext "$ALTNAMES" -subj "$SUBJECT"
}

# Check if the GO dependencies are installed and install them.
# Update $PATH and ~/.bashrc file during installation.
function check_installation() {
    $(check_command_exists wget tar unzip &> /dev/null) || apt-get install -y --no-install-recommends wget tar zip

    if ! $(check_command_exists go &> /dev/null) ; then
        wget -q https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz -O /tmp/golang.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/golang.tar.gz
        echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin
    fi

    if ! $(check_command_exists protoc &> /dev/null) ; then
        wget -q https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOC_VERSION/protoc-$PROTOC_VERSION-linux-x86_64.zip -O /tmp/protoc.zip
        rm -rf /usr/local/protoc
        unzip -q /tmp/protoc.zip -d /usr/local/protoc
        echo "export PATH=\$PATH:/usr/local/protoc/bin" >> ~/.bashrc
        export PATH=$PATH:/usr/local/protoc/bin
    fi

    local GEN_PROTOC="google.golang.org/protobuf/cmd/protoc-gen-go"
    $(go list "$GEN_PROTOC" &> /dev/null) || go install "$GEN_PROTOC@latest"

    local GEN_GRPC="google.golang.org/grpc/cmd/protoc-gen-go-grpc"
    $(go list "$GEN_GRPC" &> /dev/null) || go install "$GEN_GRPC@latest"
}

# Configure linux system to support node execution.
# Enable IPv4 packet forwarding between interfaces.
# Disable IPv6 router solicitation for new tunnel interface.
function configure_server() {
    local DEFAULT_IPV6="/proc/sys/net/ipv6/conf/default/accept_ra"
    [[ $(cat "$DEFAULT_IPV6") != 0 ]] || echo 0 > "$DEFAULT_IPV6"

    local IPV4_FORWARD="/proc/sys/net/ipv4/ip_forward"
    [[ $(cat "$IPV4_FORWARD") != 1 ]] || echo 1 > "$IPV4_FORWARD"
}

# Regenerate ./conf.env file, write all the environmental variables required for node there.
function generate_env_file() {
    rm -f conf.env
    touch conf.env
    echo "SEASIDE_PAYLOAD_OWNER=$SEASIDE_PAYLOAD_OWNER" >> conf.env
    echo "SEASIDE_PAYLOAD_VIRIDIAN=$SEASIDE_PAYLOAD_VIRIDIAN" >> conf.env
    echo "SEASIDE_ADDRESS=$SEASIDE_ADDRESS" >> conf.env
    echo "SEASIDE_EXTERNAL=$SEASIDE_EXTERNAL" >> conf.env
    echo "SEASIDE_CTRLPORT=$SEASIDE_CTRLPORT" >> conf.env
    echo "SEASIDE_MAX_VIRIDIANS=$SEASIDE_MAX_VIRIDIANS" >> conf.env
    echo "SEASIDE_MAX_ADMINS=$SEASIDE_MAX_ADMINS" >> conf.env
    echo "SEASIDE_VIRIDIAN_WAITING_OVERTIME=$SEASIDE_VIRIDIAN_WAITING_OVERTIME" >> conf.env
    echo "SEASIDE_VIRIDIAN_FIRST_HEALTHCHECK_DELAY=$SEASIDE_VIRIDIAN_FIRST_HEALTHCHECK_DELAY" >> conf.env
    echo "SEASIDE_TUNNEL_MTU=$SEASIDE_TUNNEL_MTU" >> conf.env
    echo "SEASIDE_VPN_DATA_LIMIT=$SEASIDE_VPN_DATA_LIMIT" >> conf.env
    echo "SEASIDE_CONTROL_PACKET_LIMIT=$SEASIDE_CONTROL_PACKET_LIMIT" >> conf.env
    echo "SEASIDE_ICMP_PACKET_LIMIT=$SEASIDE_ICMP_PACKET_LIMIT" >> conf.env
    echo "SEASIDE_BURST_LIMIT_MULTIPLIER=$SEASIDE_BURST_LIMIT_MULTIPLIER" >> conf.env
    echo "SEASIDE_LOG_LEVEL=$SEASIDE_LOG_LEVEL" >> conf.env
}

# Download node source code from GitHub.
# Code will be stored in ./SeasideVPN sirectory.
# #1: git branch to clone.
function download_whirlpool_distribution() {
    $(check_command_exists git make &> /dev/null) || apt-get install -y --no-install-recommends git make

    git clone -n --branch "$1" --depth=1 --filter=tree:0 https://github.com/pseusys/SeasideVPN
    cd SeasideVPN
    git sparse-checkout set --no-cone caerulean/whirlpool vessels
    git checkout
    cd caerulean/whirlpool
    make build
    cd ../../..
}

# Print configuration of the node that will be applied upon running.
function print_server_info() {
    VERSION='"0.0.2"'
    echo -e "\n\n>> ================================================ >>"
    echo -e "${BOLD}${GREEN}Seaside Whirlpool node version ${VERSION} successfully configured!${RESET}"
    echo -e "The node address is: ${BLUE}$SEASIDE_ADDRESS:$SEASIDE_CTRLPORT${RESET}"
    echo -e "The administrator payload is: ${BLUE}$SEASIDE_PAYLOAD_OWNER${RESET}"
    echo -e "\tConnection link: ${YELLOW}${UNDER}seaside+whirlpool://$SEASIDE_ADDRESS:$SEASIDE_CTRLPORT?payload=$SEASIDE_PAYLOAD_OWNER${RESET}"
    echo -e "The viridian payload is: ${BLUE}$SEASIDE_PAYLOAD_VIRIDIAN${RESET}"
    echo -e "\tConnection link: ${YELLOW}${UNDER}seaside+whirlpool://$SEASIDE_ADDRESS:$SEASIDE_CTRLPORT?payload=$SEASIDE_PAYLOAD_VIRIDIAN${RESET}"
    echo -e "${BOLD}${RED}NB! In order to replicate the server, store and reuse the ./conf.env file!${RESET}"
    echo -e "<< ================================================ <<\n\n"
}

# Print help information.
function help() {
    echo -e "${BOLD}Welcome to SeasideVPN Wirlpool node build & run script!${RESET}"
    echo -e "You are a few steps away from successfully running the Whirlpool node!"
    echo -e "Here are the few things you might want to configure (with special flags):"
    echo -e "\t${BLUE}-o [SEASIDE_PAYLOAD_OWNER]${RESET}: Set administrator payload value."
    echo -e "\t${BLUE}-v [SEASIDE_PAYLOAD_VIRIDIAN]${RESET}: Set viridian payload value."
    echo -e "\t${BLUE}-a [SEASIDE_ADDRESS]${RESET}: Internal IP address or host name of the node."
    echo -e "\t${BLUE}-e [SEASIDE_EXTERNAL]${RESET}: External IP address or host name of the node."
    echo -e "\t${BLUE}-c [SEASIDE_CTRLPORT]${RESET}: Control port of the node."
    echo -e "\t${BLUE}-n [SEASIDE_MAX_VIRIDIANS]${RESET}: Maximum amount of regular veridians of the node."
    echo -e "\t${BLUE}-x [SEASIDE_MAX_ADMINS]${RESET}: Maximum amount of privileged veridians of the node."
    echo -e "\t${BLUE}-w [SEASIDE_VIRIDIAN_WAITING_OVERTIME]${RESET}: Maximum additional waiting time for healthcheck message."
    echo -e "\t${BLUE}-f [SEASIDE_VIRIDIAN_FIRST_HEALTHCHECK_DELAY]${RESET}: Maximum waiting time for the first healthcheck message."
    echo -e "\t${BLUE}-m [SEASIDE_TUNNEL_MTU]${RESET}: MTU value of the node tunnel."
    echo -e "\t${BLUE}-d [SEASIDE_VPN_DATA_LIMIT]${RESET}: Maximum amount of data transferred through VPN."
    echo -e "\t${BLUE}-p [SEASIDE_CONTROL_PACKET_LIMIT]${RESET}: Maximum amount of control packets."
    echo -e "\t${BLUE}-i [SEASIDE_ICMP_PACKET_LIMIT]${RESET}: Maximum amount of ICMP (ping) packets."
    echo -e "\t${BLUE}-b [SEASIDE_BURST_LIMIT_MULTIPLIER]${RESET}: Burst limit multiplier."
    echo -e "\t${BLUE}-l [SEASIDE_LOG_LEVEL]${RESET}: Node logging level."
    echo -e "\t${BLUE}-u [WHIRLPOOL_SOURCE_TAG]${RESET}: GitHub branch name for code pulling."
    echo -e "\t${BLUE}-y [WHIRLPOOL_DOCKER_LABEL]${RESET}: Docker image label."
    echo -e "\t${BLUE}-k${RESET}: Run node in Docker instead of compiling and running locally."
    echo -e "\t${BLUE}-g${RESET}: Regenerate environment file (./conf.env) instead of using existing."
    echo -e "\t${BLUE}-s${RESET}: Generate self-signed certificates (./certificates/) instead of using existing."
    echo -e "\t${BLUE}-r${RESET}: Run node after configuring instead of printing run command and exiting."
    echo -e "\t${BLUE}-t${RESET}: Do not use ASCII special sequences for output coloring and styling."
    echo -e "\t${BLUE}-h${RESET}: Print this message again and exit."
    echo -e "${YELLOW}NB! See 'SeasideVPN/caerulean/whirlpool/example.conf.env' for detailed description of the environment variables.${RESET}"
}



# CLI flags and options:

while getopts "o:v:a:e:c:n:x:w:f:m:d:p:i:b:l:u:y:kgsrtzh" flag
do
    case "${flag}" in
        o) SEASIDE_PAYLOAD_OWNER=${OPTARG};;
        v) SEASIDE_PAYLOAD_VIRIDIAN=${OPTARG};;
        a) SEASIDE_ADDRESS=${OPTARG};;
        e) SEASIDE_EXTERNAL=${OPTARG};;
        c) SEASIDE_CTRLPORT=${OPTARG};;
        n) SEASIDE_MAX_VIRIDIANS=${OPTARG};;
        x) SEASIDE_MAX_ADMINS=${OPTARG};;
        w) SEASIDE_VIRIDIAN_WAITING_OVERTIME=${OPTARG};;
        f) SEASIDE_VIRIDIAN_FIRST_HEALTHCHECK_DELAY=${OPTARG};;
        m) SEASIDE_TUNNEL_MTU=${OPTARG};;
        d) SEASIDE_VPN_DATA_LIMIT=${OPTARG};;
        p) SEASIDE_CONTROL_PACKET_LIMIT=${OPTARG};;
        i) SEASIDE_ICMP_PACKET_LIMIT=${OPTARG};;
        b) SEASIDE_BURST_LIMIT_MULTIPLIER=${OPTARG};;
        l) SEASIDE_LOG_LEVEL=${OPTARG};;
        u) WHIRLPOOL_SOURCE_TAG=${OPTARG};;
        y) WHIRLPOOL_DOCKER_LABEL=${OPTARG};;
        k) RUN_IN_DOCKER=true;;
        g) GENERATE_ENV_FILE=true;;
        s) GENERATE_CERTS=true;;
        r) RUN_NODE=true;;
        t) TEXT_MODE=true;;
        z) CERTIFY_AND_EXIT=true;;
        h) HELP_AND_EXIT=true;;
        *) INVALID_OPTIONS_FOUND=true;;
    esac
done

if [ "$TEXT_MODE" = true ] ; then
    BOLD=""
    UNDER=""
    BLUE=""
    GREEN=""
    YELLOW=""
    RED=""
    RESET=""
fi

if [ "$CERTIFY_AND_EXIT" = true ] ; then
    generate_certificates "$SEASIDE_ADDRESS"
    echo -e "Certificates generated successfully for ${SEASIDE_ADDRESS}"
    exit 0
fi

if [ "$HELP_AND_EXIT" = true ] ; then
    help
    exit 1
fi

if [ "$INVALID_OPTIONS_FOUND" = true ] ; then
    echo -e "${RED}Invalid flag found: $flag${RESET}"
    exit 1
fi

if [ "$EUID" -ne 0 ] ; then
    echo "${RED}Installation should be done with superuser privileges (sudo ...)!${RESET}"
    exit 1
fi



# Script body:

echo -e "${BLUE}Configuring whirlpool node started!${RESET}"

if [ "$GENERATE_ENV_FILE" = true ] ; then
    echo -e "Generating environment file 'conf.env'..."
    generate_env_file
    echo -e "${GREEN}Environment file configuration done!${RESET}"
fi

if [ "$GENERATE_CERTS" = true ] ; then
    echo -e "Generating certificates..."
    generate_certificates "$SEASIDE_ADDRESS"
    echo -e "${GREEN}Certificates generated successfully!${RESET}"
else
    echo -e "${GREEN}Certificate generation skipped!${RESET}"
    if ! [[ -f certificates/cert.key && -f certificates/cert.crt ]] ; then
        echo -e "${RED}One of the certificate files not found!${RESET}"
        exit 1
    fi
fi

if [ "$RUN_IN_DOCKER" = true ] ; then
    echo -e "Running whirlpool node in Docker..."
    if $(check_command_exists docker &> /dev/null) ; then
        echo -e "${RED}Docker not available!${RESET}"
        exit 1
    fi
    COMMAND="docker run --env-file=conf.env --network=host --privileged ghcr.io/pseusys/seasidevpn/caerulean-whirlpool:$WHIRLPOOL_DOCKER_LABEL"
else
    echo -e "Running whirlpool node locally..."
    echo -e "Checking and installing requirements..."
    check_installation
    echo -e "${GREEN}All requirements installed!${RESET}"
    echo -e "Configuring server..."
    configure_server
    echo -e "${GREEN}Server configured!${RESET}"
    echo -e "Downloading whirlpool distribution..."
    download_whirlpool_distribution "$WHIRLPOOL_SOURCE_TAG"
    echo -e "${GREEN}Whirlpool distribution downloaded!${RESET}"
    COMMAND="set -a && source conf.env && SeasideVPN/caerulean/whirlpool/build/whirlpool.run"
fi

set -a && source conf.env && print_server_info && set +a

if [ "$RUN_NODE" = true ] ; then
    echo -e "${GREEN}Configuration done, running whirlpool node!${RESET}"
    eval "$COMMAND"
else
    echo -e "${GREEN}Configuration done, you're all set up!${RESET}"
    echo -e "${BLUE}Just run '${RESET}${BOLD}$COMMAND${RESET}${BLUE}' whenever you're ready!${RESET}"
fi
