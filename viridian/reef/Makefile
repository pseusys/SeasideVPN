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

BUILD_TYPE=debug

WINDIVERT_VERSION=2.2.2
WINDIVERT_PATH=windivert-bin
BINARY_PATH=target/$(BUILD_TYPE)/

WINDIVERT_TEMP=windivert-source
WINDIVERT_SOURCE=WinDivert-$(WINDIVERT_VERSION)-A
WINDIVERT_URL=https://github.com/basil00/WinDivert/releases/download/v$(WINDIVERT_VERSION)/$(WINDIVERT_SOURCE).zip


UNAME_M := $(shell uname -m)

ifeq ($(UNAME_M),x86_64)
	WINDIVERT_ARCH := x64
    WINTUN_ARCH := amd64
else ifeq ($(UNAME_M),i686)
	WINDIVERT_ARCH := x32
    WINTUN_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
	WINDIVERT_ARCH := x64
    WINTUN_ARCH := arm64
else ifeq ($(UNAME_M),armv7l)
	WINDIVERT_ARCH := x32
    WINTUN_ARCH := arm
else
    $(error Unsupported uname architecture: $(UNAME_M))
endif



help:
	@ # Print available make target information
	echo -e "help"
.PHONY: help



dependencies:
	@ # Download and unpack dependencies
ifeq ($(OS),Windows_NT)
	echo "Downloading WinDivert library version $(WINDIVERT_VERSION)..."
	curl -sSL -o $(WINDIVERT_SOURCE).zip $(WINDIVERT_URL)
	mkdir -p $(WINDIVERT_TEMP)
	unzip -q -o $(WINDIVERT_SOURCE).zip -d $(WINDIVERT_TEMP)
	mkdir -p $(WINDIVERT_PATH)
	mv $(WINDIVERT_TEMP)/$(WINDIVERT_SOURCE)/$(WINDIVERT_ARCH)/* $(WINDIVERT_PATH)/
	rm -rf $(WINDIVERT_TEMP)
	echo "All dependencies ready!"
endif
.PHONY: dependencies

runtime:
	@ # Move dependencies next to the executable
ifeq ($(OS),Windows_NT)
	echo "Copying dependencies next to the executable..."
	mkdir -p $(BINARY_PATH)
	cp $(WINDIVERT_PATH)/*.dll $(WINDIVERT_PATH)/*.sys $(BINARY_PATH)
	echo "All dependencies in place!"
endif
.PHONY: runtime

build: dependencies
	@ # Build reef locally TODO: add feature strict, checking warnings, docs, removing debug info
ifeq ($(BUILD_TYPE),release)
	cargo build --all-features --release
else
	cargo build --all-features
endif
.PHONY: build

run: build runtime
	@ # Run reef locally
	cargo run --features cli-exec --bin cli
.PHONY: run



test:
	@ # Run tests inside of the testing docker container
	docker build -f Dockerfile --target tester -t seaside-reef-test ../..
	docker run --privileged --rm --name seaside-reef-test --sysctl net.ipv6.conf.all.disable_ipv6=1 --entrypoint cargo seaside-reef-test test --package SeasideVPN-Reef --lib -- --nocapture --show-output
.PHONY: test

lint: build
	cargo fmt --all -- --check
.PHONY: lint



clean:
	@ # Clean all reef build artifacts
	rm -rf target certificates
	rm -f Cargo.lock
	docker rmi -f seaside-reef-test
.PHONY: clean
