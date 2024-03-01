.ONESHELL:
.DEFAULT_GOAL := help

SHELL=/bin/bash
.SHELLFLAGS=-O globstar -c -e

VERSION="0.0.1"

BOLD=\033[1m
BLUE=\033[34m
RED=\033[31m
RESET=\033[0m



help-whirlpool:
	@ # Print help message of caerulean whirlpool
	make -C caerulean/whirlpool -s help
.PHONY: help-whirlpool

help-algae:
	@ # Print help message of viridian algae
	poetry -C viridian/algae run help
.PHONY: help-algae

help:
	@ # Print general help message
	echo -e "$(BOLD)Welcome to SeasideVPN project version $(VERSION)!$(RESET)"
	echo -e "SeasideVPN is a simple PPTP UDP and VPN system, designed for speed, security and undetectability."
	echo -e "$(BOLD)Available test targets$(RESET):"
	echo -e "\t$(BLUE)make test$(RESET): test all system parts."
	echo -e "\t$(BLUE)make test-whirlpool$(RESET): test caerulean whirlpool."
	echo -e "\t$(BLUE)make test-algae$(RESET): test viridian algae (+ integration tests)."
	echo -e "$(BOLD)Available lint targets$(RESET):"
	echo -e "\t$(BLUE)make lint$(RESET): test all system parts."
	echo -e "\t$(BLUE)make lint-whirlpool$(RESET): lint caerulean whirlpool."
	echo -e "\t$(BLUE)make lint-algae$(RESET): lint viridian algae."
	echo -e "\t$(BLUE)make lint-scripts$(RESET): lint JavaScript and Bash scripts in the project."
	echo -e "$(BOLD)Available clean targets$(RESET):"
	echo -e "\t$(BLUE)make clean$(RESET): clean all system part build and Docker artifacts."
	echo -e "\t$(BLUE)make clean-whirlpool$(RESET): clean caerulean whirlpool."
	echo -e "\t$(BLUE)make clean-algae$(RESET): clean viridian algae."
	echo -e "$(BOLD)Available misc targets$(RESET):"
	echo -e "\t$(BLUE)make bump-version VERSION=[NEW_VERSION]$(RESET): change project version specification to $(BLUE)[NEW_VERSION]$(RESET)."
	echo -e "\t$(BLUE)make install-algae$(RESET): install the viridian algae dependencies required for build system running."
	echo -e "\t$(BLUE)make install-algae-all$(RESET): install all the viridian algae dependencies."
.PHONY: help



bump-version:
	@ # Change all project parts version to $(VERSION)
	bash bump-version.sh -v $(VERSION)
.PHONY: bump-version



install-algae:
	@ # Install viridian algae requirements for poetry, linting, installing and running Docker
	poetry -C viridian/algae install --without client,devel
.PHONY: install-algae

install-algae-all:
	@ # Install all the viridian algae requirements (insluding the ones for running)
	poetry -C viridian/algae install
.PHONY: install-algae



test-whirlpool:
	@ # Run caerulean algae tests (in a docker container)
	make -C caerulean/whirlpool -s test
.PHONY: test-whirlpool

test-algae: install-algae
	@ # Run caerulean algae tests (in a docker container)
	poetry -C viridian/algae run test_all
.PHONY: test-algae

test: test-whirlpool test-algae
	@ # Run all the system part tests
.PHONY: test



lint-whirlpool:
	@ # Lint caerulean whirlpool (in a docker container)
	make -C caerulean/whirlpool -s lint
.PHONY: lint-whirlpool

lint-algae: install-algae-all
	@ # Lint viridian algae (locally, formatting available)
	poetry -C viridian/algae run lint
.PHONY: lint-algae

lint-scripts:
	@ # Lint all the scripts in project (*.sh and .github/*.mjs scripts)
	shellcheck -x -e SC1091,SC2129,SC2002,SC2091 **/*.sh
	npm run --prefix .github/scripts lint-scripts
.PHONY: lint-scripts

lint: lint-whirlpool lint-algae lint-scripts
	@ # Lint all the system parts
.PHONY: lint



clean-whirlpool:
	@ # Clean caerulean whirlpool (including build and docker artifacts)
	make -C caerulean/whirlpool -s clean
.PHONY: clean-whirlpool

clean-algae: install-algae
	@ # Clean viridian algae (including build and docker artifacts)
	poetry -C viridian/algae run clean
.PHONY: clean-algae

clean: clean-whirlpool clean-algae
	@ # Clean all the system parts
.PHONY: clean
