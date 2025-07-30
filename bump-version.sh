#!/bin/bash

set -e

# Change current version number in all project files.
# Running this script implies there are no "CURRENT_VERSION" strings in the project.
# Otherwise the strings will be replaced.
# NB! Other package versions should be specified like "^PACKAGE_VERSION".

# Formatting:
BOLD="\033[1m"
BLUE="\033[34m"
RED="\033[31m"
RESET="\033[0m"



# Global arguments:

# Current project version
CURRENT_VERSION="0.0.4"
# New project version (same as current by default)
NEW_VERSION="$CURRENT_VERSION"
# Files that require versioning
VERSIONED_FILES=(
    "Makefile" \
    "README.md" \
    "bump-version.sh" \
    ".github/package.json" \
    "viridian/algae/pyproject.toml" \
    "viridian/algae/README.md" \
    "viridian/algae/sources/version.py" \
    "viridian/algae/setup/whirlpool.py" \
    "viridian/reef/Cargo.toml" \
    "viridian/reef/README.md" \
    "viridian/reef/src/lib/mod.rs" \
    "caerulean/whirlpool/README.md" \
    "caerulean/whirlpool/protocol/protocol_utils.go"
)



# Functions:

function help() {
    echo -e "${BOLD}Version bumping script usage:${RESET}"
    echo -e "\t${BLUE}-v [NEW_VERSION]${RESET}: New version for the project files."
    echo -e "\t${BLUE}-h${RESET}: Print this message again and exit."
}



# CLI flags and options:

while getopts "v:h" flag
do
    case "${flag}" in
        v) NEW_VERSION=${OPTARG};;
        h) help && exit 0;;
        *) echo -e "${RED}Invalid flag found: $flag${RESET}" && exit 1;;
    esac
done



# Script body:

for file in "${VERSIONED_FILES[@]}" ; do
    sed -i -e "s/\"$CURRENT_VERSION\"/\"$NEW_VERSION\"/g" "$file"
done
