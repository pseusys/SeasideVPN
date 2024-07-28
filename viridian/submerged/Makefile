.ONESHELL:
.EXPORT_ALL_VARIABLES:
.DEFAULT_GOAL := help

SHELL=/bin/bash
.SHELLFLAGS=-c -e

DOCKER_BUILDKIT = 1

BOLD=\033[1m
BLUE=\033[34m
GREEN=\033[32m
YELLOW=\033[33m
RESET=\033[0m

SANDBOX_IMAGE := submerged-bullseye-latest
SANDBOX_CONTAINER := submerged-cli-sandbox



help:
	@ # Print available make target information
	echo -e "help"
.PHONY: help



build:
	@ # Build submerged locally
	cargo build
.PHONY: build

run:
	@ # Run submerged locally
	cargo run --bin standard
.PHONY: run

sandbox:
	@ # Run submerged in Docker sandbox image
	docker build --tag ${SANDBOX_IMAGE} --file Dockerfile ../..
	docker run --privileged -it --rm --network=host --name ${SANDBOX_CONTAINER} --volume ./src:/seaside/viridian/submerged/src ${SANDBOX_IMAGE}
.PHONY: sandbox



clean:
	@ # Clean all submerged build artifacts
	rm -rf target
	rm -f Cargo.lock
	docker rm -f ${SANDBOX_CONTAINER}
	docker rmi -f ${SANDBOX_IMAGE}
.PHONY: clean
