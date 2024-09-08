.ONESHELL:
.EXPORT_ALL_VARIABLES:
.DEFAULT_GOAL := help

SHELL=/bin/bash
.SHELLFLAGS=-c -e

BOLD=\033[1m
BLUE=\033[34m
GREEN=\033[32m
YELLOW=\033[33m
RESET=\033[0m

SEASIDE_ADDRESS := 10.87.82.87



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
	cargo run --features cli-exec --bin cli
.PHONY: run



test-integration:
	@ # Run reef integration tests in Docker
	bash ../../caerulean/whirlpool/whirlpool.sh -za ${SEASIDE_ADDRESS}
	docker compose -f ../algae/docker/compose.default.yml build whirlpool
	docker compose -f docker/compose.yml up --build
	docker rm -f seaside-reef seaside-echo seaside-external-router seaside-internal-router seaside-whirlpool
	docker network rm seaside-reef_sea-cli-int seaside-reef_sea-rout-ext seaside-reef_sea-rout-int seaside-reef_sea-serv-ext
	docker rmi -f seaside-reef-reef seaside-reef-echo seaside-reef-ext-router seaside-reef-int-router seaside-reef-whirlpool
.PHONY: test-integration

test: test-integration
.PHONY: test



clean:
	@ # Clean all reef build artifacts
	rm -rf target
	rm -f Cargo.lock
.PHONY: clean
