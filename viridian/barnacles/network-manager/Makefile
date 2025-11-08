.ONESHELL:
.EXPORT_ALL_VARIABLES:
.DEFAULT_GOAL := help

SHELL := /bin/bash
.SHELLFLAGS := -c -e

BUILD_TYPE := debug
RUNNING_IN_DOCKER := false

help:
	@ # Print available make target information
	echo -e "help"
.PHONY: help



# Compilation flags:

GCC_COMPILATION_FLAGS_BASE :=
ifeq ($(BUILD_TYPE),debug)
	GCC_COMPILATION_FLAGS_BASE := $(GCC_COMPILATION_FLAGS_BASE) -Og
endif
GCC_COMPILATION_FLAGS := $(GCC_COMPILATION_FLAGS_BASE) -Wall -Wextra -Wpedantic -Wshadow -Wpointer-arith -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -Werror

RAW_GCC_FLAGS_GLIB := $(shell pkg-config --cflags --libs glib-2.0)
GCC_FLAGS_GLIB := $(GCC_COMPILATION_FLAGS_BASE) $(RAW_GCC_FLAGS_GLIB:-I%=-isystem %)

RAW_GCC_FLAGS_LIBNM := $(shell pkg-config --cflags --libs libnm)
GCC_FLAGS_LIBNM := $(GCC_COMPILATION_FLAGS) $(RAW_GCC_FLAGS_LIBNM:-I%=-isystem %)

RAW_GCC_FLAGS_GTK3 := $(shell pkg-config --cflags --libs libnm gtk+-3.0)
GCC_FLAGS_GTK3 := $(GCC_COMPILATION_FLAGS) $(RAW_GCC_FLAGS_GTK3:-I%=-isystem %)

RAW_GCC_FLAGS_GTK4 := $(shell pkg-config --cflags --libs libnm gtk4)
GCC_FLAGS_GTK4 := $(GCC_COMPILATION_FLAGS) $(RAW_GCC_FLAGS_GTK4:-I%=-isystem %)

RAW_GCC_FLAGS_LIBSECRET := $(shell pkg-config --cflags --libs libnm libsecret-1)
GCC_FLAGS_LIBSECRET := $(GCC_COMPILATION_FLAGS) $(RAW_GCC_FLAGS_LIBSECRET:-I%=-isystem %)



# Building and setting up system:

BUILD_ARCH := $(shell dpkg-architecture -qDEB_HOST_MULTIARCH)

PLUGIN_NAME := seasidevpn
SERVICE_NAME := org.freedesktop.NetworkManager.$(PLUGIN_NAME)

LIB_DIR := /usr/lib/NetworkManager/VPN
BIN_DIR := /usr/lib/$(BUILD_ARCH)
PLUGIN_DIR := $(BIN_DIR)/NetworkManager
SERVICE_DIR := /usr/libexec
NM_DBUS_DIR := /usr/share/dbus-1/system.d
PLUGIN_INTERFACE_BASE := $(PLUGIN_DIR)/libnm-vpn-editor-$(PLUGIN_NAME)

VIRIDIAN_DIR := ../..
REEF_DIR := $(VIRIDIAN_DIR)/reef
NM_CONFIGURATION_DIR := configuration
NM_INCLUDE_DIR := include
NM_PLUGIN_DIR := plugin
NM_EDITOR_DIR := editor
NM_BUILD_DIR := build
NM_BIN_DIR := $(REEF_DIR)/target/$(BUILD_TYPE)
SHARED_LIBRARY := $(REEF_DIR)/shared_library/include

INSTALL_BIN := $(BIN_DIR)/libseaside.so
INSTALL_PLUGIN := $(SERVICE_DIR)/nm-$(PLUGIN_NAME)-service
INSTALL_NAME := $(LIB_DIR)/nm-$(PLUGIN_NAME)-service.name
INSTALL_CONF := $(NM_DBUS_DIR)/nm-$(PLUGIN_NAME)-service.conf
INSTALL_EDITOR := $(PLUGIN_DIR)/libnm-vpn-plugin-$(PLUGIN_NAME).so
INSTALL_INTERFACE_GTK3 := $(PLUGIN_INTERFACE_BASE)-gtk3.so
INSTALL_INTERFACE_GTK4 := $(PLUGIN_INTERFACE_BASE)-gtk4.so
INSTALL_DIALOG := $(SERVICE_DIR)/nm-$(PLUGIN_NAME)-auth-dialog

EXTRA_FLAGS := -DSEASIDE_PLUGIN_SERVICE="\"$(SERVICE_NAME)\"" -DEDITOR_INTERFACE_PATH="\"$(PLUGIN_INTERFACE_BASE)\""
EDITOR_PLUGIN_INCLUDES := -I$(SHARED_LIBRARY) -I$(NM_INCLUDE_DIR)

CLANG_CONFIGURATION_FILE := $(VIRIDIAN_DIR)/.clang-tidy
CLANG_FORMATTING_FILE := $(VIRIDIAN_DIR)/.clang-format

CLANG_STATIC_ANALYSIS_ARGS := --config-file=$(CLANG_CONFIGURATION_FILE) --quiet
CLANG_FORMATTING_ARGS := --Werror --sort-includes --style=file:$(CLANG_FORMATTING_FILE) **/*.c **/*.h



# Build accessories:

create-build-directory:
	@ # Ensure build directory exists
	mkdir -p $(NM_BUILD_DIR)
.PHONY: create-build-directory

$(SHARED_LIBRARY)/seaside.h:
	@ # Compile rust shared library
	$(MAKE) -C $(REEF_DIR) -s --no-print-directory build-lib

$(NM_INCLUDE_DIR)/common.h: $(SHARED_LIBRARY)/seaside.h
	@ # The common header depends on the rust shared library

$(NM_BUILD_DIR)/resources.gen.c: $(NM_EDITOR_DIR)/gresource.xml | create-build-directory
	@ # Generate GLib resources source file
	glib-compile-resources $< --sourcedir=$(NM_EDITOR_DIR) --target=$@ --generate-source



# Compile C wrappers:

$(NM_BUILD_DIR)/resources.gen.o: $(NM_BUILD_DIR)/resources.gen.c | create-build-directory
	@
	gcc -c $< -o $@ $(GCC_FLAGS_GLIB)

$(NM_BUILD_DIR)/auth_dialog.o: $(NM_EDITOR_DIR)/auth_dialog.c | create-build-directory
	@
	clang-tidy $(CLANG_STATIC_ANALYSIS_ARGS) $< -- $(GCC_FLAGS_LIBSECRET)
	gcc -fPIC -c $< -o $@ $(GCC_FLAGS_LIBSECRET)

$(NM_BUILD_DIR)/editor.o: $(NM_EDITOR_DIR)/editor.c $(NM_EDITOR_DIR)/editor.h $(NM_INCLUDE_DIR)/common.h | create-build-directory
	@
	clang-tidy $(CLANG_STATIC_ANALYSIS_ARGS) $< -- $(EDITOR_PLUGIN_INCLUDES) $(EXTRA_FLAGS) $(GCC_FLAGS_LIBNM)
	gcc -fPIC $(EDITOR_PLUGIN_INCLUDES) -c $< -o $@ $(EXTRA_FLAGS) $(GCC_FLAGS_LIBNM)

$(NM_BUILD_DIR)/interface_gtk3.o: $(NM_EDITOR_DIR)/interface_gtk3.c $(NM_EDITOR_DIR)/interface.h $(NM_EDITOR_DIR)/editor.h | create-build-directory
	@
	clang-tidy $(CLANG_STATIC_ANALYSIS_ARGS) $< -- $(EDITOR_PLUGIN_INCLUDES) $(EXTRA_FLAGS) $(GCC_FLAGS_GTK3)
	gcc -fPIC $(EDITOR_PLUGIN_INCLUDES) -c $< -o $@ $(EXTRA_FLAGS) $(GCC_FLAGS_GTK3)

$(NM_BUILD_DIR)/interface_gtk4.o: $(NM_EDITOR_DIR)/interface_gtk4.c $(NM_EDITOR_DIR)/interface.h $(NM_EDITOR_DIR)/editor.h | create-build-directory
	@
	clang-tidy $(CLANG_STATIC_ANALYSIS_ARGS) $< -- $(EDITOR_PLUGIN_INCLUDES) $(EXTRA_FLAGS) $(GCC_FLAGS_GTK4)
	gcc -fPIC $(EDITOR_PLUGIN_INCLUDES) -c $< -o $@ $(EXTRA_FLAGS) $(GCC_FLAGS_GTK4)

$(NM_BUILD_DIR)/plugin.o: $(NM_PLUGIN_DIR)/plugin.c $(NM_PLUGIN_DIR)/plugin.h $(SHARED_LIBRARY)/seaside.h $(NM_INCLUDE_DIR)/common.h | create-build-directory
	@
	clang-tidy $(CLANG_STATIC_ANALYSIS_ARGS) $< -- $(EDITOR_PLUGIN_INCLUDES) $(EXTRA_FLAGS) $(GCC_FLAGS_LIBNM)
	gcc -fPIC $(EDITOR_PLUGIN_INCLUDES) -c $< -o $@ $(EXTRA_FLAGS) $(GCC_FLAGS_LIBNM)



# Link C wrappers:

$(NM_BUILD_DIR)/auth_dialog: $(NM_BUILD_DIR)/auth_dialog.o
	@
	gcc $^ -o $@ $(GCC_FLAGS_LIBSECRET)

$(NM_BUILD_DIR)/editor.so: $(NM_BUILD_DIR)/editor.o
	@
	gcc -shared $^ -o $@ $(GCC_FLAGS_LIBNM)

$(NM_BUILD_DIR)/interface-gtk3.so: $(NM_BUILD_DIR)/interface_gtk3.o $(NM_BUILD_DIR)/resources.gen.o
	@
	gcc -shared $^ -o $@ $(GCC_FLAGS_GTK3)

$(NM_BUILD_DIR)/interface-gtk4.so: $(NM_BUILD_DIR)/interface_gtk4.o $(NM_BUILD_DIR)/resources.gen.o
	@
	gcc -shared $^ -o $@ $(GCC_FLAGS_GTK4)

$(NM_BUILD_DIR)/plugin: $(NM_BUILD_DIR)/plugin.o
	@
	gcc $^ -o $@ $(GCC_FLAGS_LIBNM)



# Build everything:

editor-build: $(NM_BUILD_DIR)/auth_dialog $(NM_BUILD_DIR)/editor.so $(NM_BUILD_DIR)/interface-gtk3.so $(NM_BUILD_DIR)/interface-gtk4.so
	@
.PHONY: editor-build

plugin-build: $(NM_BUILD_DIR)/plugin
	@
.PHONY: plugin-build

config-build: create-build-directory
	@ # Build network manager reef configuration
	sed "s|SEASIDE-PLUGIN-NAME|$(PLUGIN_NAME)|" $(NM_CONFIGURATION_DIR)/descriptor.ini > $(NM_BUILD_DIR)/descriptor.ini.gen
	sed -i "s|DBUS-SERVICE-NAME|$(SERVICE_NAME)|" $(NM_BUILD_DIR)/descriptor.ini.gen
	sed -i "s|PATH-TO-SEASIDEVPN-PLUGIN|$(INSTALL_PLUGIN)|" $(NM_BUILD_DIR)/descriptor.ini.gen
	sed -i "s|PATH-TO-SEASIDEVPN-EDITOR|$(INSTALL_EDITOR)|" $(NM_BUILD_DIR)/descriptor.ini.gen
	sed -i "s|SEASIDE-AUTH-DIALOG|$(INSTALL_DIALOG)|" $(NM_BUILD_DIR)/descriptor.ini.gen
.PHONY: config-build

build: editor-build plugin-build config-build
	@ # Build network manager reef plugin
.PHONY: build



# Install and run the artifacts:

install: build
	@ # Install network manager reef plugin
	sudo install -D -m 755 $(NM_BUILD_DIR)/plugin $(INSTALL_PLUGIN)
	sudo install -D -m 644 $(NM_BUILD_DIR)/descriptor.ini.gen $(INSTALL_NAME)
	sudo install -D -m 644 $(NM_CONFIGURATION_DIR)/service.conf $(INSTALL_CONF)
	sudo install -D -m 644 $(NM_BUILD_DIR)/editor.so $(INSTALL_EDITOR)
	sudo install -D -m 644 $(NM_BUILD_DIR)/interface-gtk3.so $(INSTALL_INTERFACE_GTK3)
	sudo install -D -m 644 $(NM_BUILD_DIR)/interface-gtk4.so $(INSTALL_INTERFACE_GTK4)
	sudo install -D -m 755 $(NM_BUILD_DIR)/auth_dialog $(INSTALL_DIALOG)
	sudo install -D -m 644 $(NM_BIN_DIR)/libseaside.so $(INSTALL_BIN)
ifneq ($(RUNNING_IN_DOCKER),true)
	sudo systemctl restart NetworkManager
endif
.PHONY: install

run: install
	@
	cd $(SERVICE_DIR)
ifeq ($(BUILD_TYPE),debug)
	sudo -E G_MESSAGES_DEBUG=all ./nm-$(PLUGIN_NAME)-service
else
	sudo ./nm-$(PLUGIN_NAME)-service
endif
.PHONY: install



# Lint C sources:

lint:
	@
	clang-format --dry-run $(CLANG_FORMATTING_ARGS)
.PHONY: lint

format:
	@
	clang-format -i $(CLANG_FORMATTING_ARGS)
.PHONY: format



# Artifact cleaning:

clean:
	@ # Clean network manager plugin build artifacts
	rm -rf $(NM_BUILD_DIR)
	sudo rm -f $(INSTALL_PLUGIN) $(INSTALL_NAME) $(INSTALL_CONF) $(INSTALL_EDITOR) $(INSTALL_INTERFACE_GTK3) $(INSTALL_INTERFACE_GTK4) $(INSTALL_DIALOG) $(INSTALL_BIN)
.PHONY: clean
