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



help:
	@ # Print available make target information
	echo -e "help"
.PHONY: help



build:
	@ # Build reef locally TODO: add feature strict, checking warnings, docs, removing debug info
	cargo build --all-features
.PHONY: build

run: build
	@ # Run reef locally
	cargo run --features cli-exec --bin cli
.PHONY: run



test-unit:
	@ # Run unit tests inside of the testing docker container
ifndef CI
	docker build -f docker/Dockerfile --target test -t seaside-reef-test ../..
else
	docker build -f docker/Dockerfile --target test -t seaside-reef-test -q ../..
endif
	docker run --privileged --rm --name seaside-reef-test --sysctl net.ipv6.conf.all.disable_ipv6=1 --entrypoint cargo seaside-reef-test test --package reef --lib -- --nocapture --show-output
.PHONY: test-unit

test-integration:
	@ # Run reef integration tests in Docker
	bash ../../caerulean/whirlpool/whirlpool.sh -za "$$(yq -r '.services.whirlpool.environment.SEASIDE_ADDRESS' docker/compose.yml)" 2> /dev/null
	docker compose -f ../algae/docker/compose.default.yml build whirlpool echo 2> /dev/null
	docker compose -f docker/compose.yml up --build --abort-on-container-exit --exit-code-from reef
	rm -rf certificates
.PHONY: test-integration

test: test-unit test-integration
.PHONY: test



clean:
	@ # Clean all reef build artifacts
	rm -rf target certificates
	rm -f Cargo.lock
	docker rm -f seaside-reef seaside-echo seaside-external-router seaside-internal-router seaside-whirlpool
	docker network rm seaside-reef_sea-cli-int seaside-reef_sea-rout-ext seaside-reef_sea-rout-int seaside-reef_sea-serv-ext
	docker rmi -f seaside-reef-reef seaside-reef-echo seaside-reef-ext-router seaside-reef-int-router seaside-reef-whirlpool
.PHONY: clean
