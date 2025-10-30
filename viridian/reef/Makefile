.ONESHELL:
.EXPORT_ALL_VARIABLES:
.DEFAULT_GOAL := help

SHELL := /bin/bash
.SHELLFLAGS := -c -e

BUILD_TYPE := debug
BINARY_PATH := target/$(BUILD_TYPE)



help:
	@ # Print available make target information
	echo -e "help"
.PHONY: help



# Building and dependency management:

WINDIVERT_VERSION := 2.2.2
WINDIVERT_PATH := windivert-bin

WINDIVERT_TEMP := windivert-source
WINDIVERT_SOURCE := WinDivert-$(WINDIVERT_VERSION)-A
WINDIVERT_URL := https://github.com/basil00/WinDivert/releases/download/v$(WINDIVERT_VERSION)/$(WINDIVERT_SOURCE).zip


UNAME_M := $(shell uname -m)

ifeq ($(UNAME_M),x86_64)
	WINDIVERT_ARCH := x64
else ifeq ($(UNAME_M),i686)
	WINDIVERT_ARCH := x32
else ifeq ($(UNAME_M),aarch64)
	WINDIVERT_ARCH := x64
else ifeq ($(UNAME_M),armv7l)
	WINDIVERT_ARCH := x32
else
    $(error Unsupported uname architecture: $(UNAME_M))
endif


dependencies:
	@ # Download and unpack standalone dependencies
ifeq ($(OS),Windows_NT)
	echo "Downloading WinDivert library version $(WINDIVERT_VERSION)..."
	curl -sSL -o $(WINDIVERT_SOURCE).zip $(WINDIVERT_URL)
	mkdir -p $(WINDIVERT_TEMP)
	unzip -q -o $(WINDIVERT_SOURCE).zip -d $(WINDIVERT_TEMP)
	mkdir -p $(WINDIVERT_PATH)
	mv $(WINDIVERT_TEMP)/$(WINDIVERT_SOURCE)/$(WINDIVERT_ARCH)/* $(WINDIVERT_PATH)/
	rm -rf $(WINDIVERT_TEMP)
	echo "All standalone dependencies ready!"
endif
.PHONY: dependencies

runtime:
	@ # Move standalone dependencies next to the executable
ifeq ($(OS),Windows_NT)
	echo "Copying dependencies next to the executable..."
	mkdir -p $(BINARY_PATH)
	cp $(WINDIVERT_PATH)/*.dll $(WINDIVERT_PATH)/*.sys $(BINARY_PATH)
	echo "All standalone dependencies in place!"
endif
.PHONY: runtime

build: dependencies
	@ # Build standalone reef locally TODO: add feature strict, checking warnings, docs, removing debug info
ifeq ($(BUILD_TYPE),release)
	cargo build --release --bin cli
else
	cargo build --bin cli
endif
.PHONY: build

run: build runtime
	@ # Run standalone reef locally
	cargo run --bin cli
.PHONY: run



build-lib:
	@ # Build standalone reef locally TODO: add feature strict, checking warnings, docs, removing debug info
ifeq ($(BUILD_TYPE),release)
	cargo build --release --lib
else
	cargo build --lib
endif
.PHONY: build-lib



# Testing and code quality:

test:
	@ # Run tests inside of the testing docker container
	docker build -f Dockerfile --target tester -t seaside-reef-test ../..
	docker run --privileged --rm --name seaside-reef-test --sysctl net.ipv6.conf.all.disable_ipv6=1 --entrypoint cargo seaside-reef-test test --workspace -- --nocapture --show-output
.PHONY: test

lint: build
	@ # Perform format check of all the rust code
	cargo fmt --all -- --check
.PHONY: lint



# Artifact cleaning:

clean:
	@ # Clean all the artifacts for any targets
	cargo clean
	rm -f Cargo.lock
	rm -rf shared_library/include
	docker rmi -f seaside-reef-test
.PHONY: clean
