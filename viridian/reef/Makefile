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

WINDIVERT_VERSION=2.2.2
WINDIVERT_PATH=windivert-bin

WINDIVERT_TEMP=windivert-source
WINDIVERT_SOURCE=WinDivert-$(WINDIVERT_VERSION)-A
WNDIVERT_URL=https://github.com/basil00/WinDivert/releases/download/v$(WINDIVERT_VERSION)/$(WINDIVERT_SOURCE).zip

SYS_ARCH := $(shell uname -m | grep -q '64' && echo 'x64' || echo 'x32')


help:
	@ # Print available make target information
	echo -e "help"
.PHONY: help



dependencies:
	@ # Dowload and unpack windivert distribution
ifeq ($(OS),Windows_NT)
	curl -sSL -o $(WINDIVERT_SOURCE).zip $(WNDIVERT_URL)
	mkdir -p $(WINDIVERT_TEMP)
	unzip -q -o $(WINDIVERT_SOURCE).zip -d $(WINDIVERT_TEMP)
	mkdir -p $(WINDIVERT_PATH)
	mv $(WINDIVERT_TEMP)/$(WINDIVERT_SOURCE)/$(SYS_ARCH)/* $(WINDIVERT_PATH)/
	rm -rf $(WINDIVERT_TEMP)
endif
.PHONY: dependencies

build: dependencies
	@ # Build reef locally TODO: add feature strict, checking warnings, docs, removing debug info
	cargo build --all-features
.PHONY: build

run: build
	@ # Run reef locally
	cargo run --features cli-exec --bin cli
.PHONY: run



test:
	@ # Run tests inside of the testing docker container
	docker build -f Dockerfile --target tester -t seaside-reef-test ../..
	docker run --privileged --rm --name seaside-reef-test --sysctl net.ipv6.conf.all.disable_ipv6=1 --entrypoint cargo seaside-reef-test test --package SeasideVPN-Reef --lib -- --nocapture --show-output
.PHONY: test



clean:
	@ # Clean all reef build artifacts
	rm -rf target
	rm -f Cargo.lock
	docker rmi -f seaside-reef-test
.PHONY: clean
