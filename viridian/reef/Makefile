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

SANDBOX_IMAGE := reef-bullseye-latest
SANDBOX_CONTAINER := reef-cli-sandbox



help:
	@ # Print available make target information
	echo -e "help"
.PHONY: help



build:
	@ # Build reef locally
	cargo build
.PHONY: build

run:
	@ # Run reef locally
	cargo run --bin cli
.PHONY: run



test-integration:
	@ # Run reef integration tests in Docker
	docker compose -f docker/compose.yml up --build
.PHONY: test-integration

test: test-integration
.PHONY: test



clean:
	@ # Clean all reef build artifacts
	rm -rf target
	rm -f Cargo.lock
	docker rm -f ${SANDBOX_CONTAINER}
	docker rmi -f ${SANDBOX_IMAGE}
.PHONY: clean
