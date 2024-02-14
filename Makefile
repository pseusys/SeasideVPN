.ONESHELL:
.DEFAULT_GOAL := help

BOLD=\033[1m
BLUE=\033[34m
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
	echo "${BOLD}Available test targets${RESET}:"
	echo "\t${BLUE}make test${RESET}: test all system parts."
	echo "\t${BLUE}make test-whirlpool${RESET}: test caerulean whirlpool."
	echo "\t${BLUE}make test-algae${RESET}: test viridian algae (+ integration tests)."
	echo "${BOLD}Available lint targets${RESET}:"
	echo "\t${BLUE}make lint${RESET}: test all system parts."
	echo "\t${BLUE}make lint-whirlpool${RESET}: lint caerulean whirlpool."
	echo "\t${BLUE}make lint-algae${RESET}: lint viridian algae."
	echo "${BOLD}Available clean targets${RESET}:"
	echo "\t${BLUE}make clean${RESET}: clean all system part build and Docker artifacts."
	echo "\t${BLUE}make clean-whirlpool${RESET}: clean caerulean whirlpool."
	echo "\t${BLUE}make clean-algae${RESET}: clean viridian algae."
	echo "${BOLD}Available misc targets${RESET}:"
	echo "\t${BLUE}make install-algae${RESET}: install the viridian algae dependencies required for build system running."
	echo "\t${BLUE}make install-algae-all${RESET}: install all the viridian algae dependencies."
.PHONY: help



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

lint: lint-whirlpool lint-algae
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
