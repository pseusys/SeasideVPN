.ONESHELL:
.EXPORT_ALL_VARIABLES:
.DEFAULT_GOAL := help

SHELL=/bin/bash
.SHELLFLAGS=-c -e

BUILD_TYPE=debug

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    PLATFORM := linux
else ifeq ($(UNAME_S),Darwin)
    PLATFORM := macos
else
    PLATFORM := windows
endif



help:
	@ # Print available make target information
	echo -e "help"
.PHONY: help



# TODO: add deployment script for protos and images
install:
	mkdir -p protos
	cp -rf ../../vessels/* protos/
	flutter pub get
	dart run build_runner build
.PHONY: install

run: install
	flutter run -d $(PLATFORM)
.PHONY: run



clean:
	@ # Clean all littoral build artifacts
	rm -rf build
	rm -f pubspec.lock
.PHONY: clean
