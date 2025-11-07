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



# Building and setting up system:
G_C_FLAGS := $(shell pkg-config --cflags --libs libnm)
ifeq ($(BUILD_TYPE),debug)
	G_C_FLAGS := $(G_C_FLAGS) -Og
endif

G_C_FLAGS_GTK_3 := $(G_C_FLAGS) $(shell pkg-config --cflags --libs gtk+-3.0)
G_C_FLAGS_GTK_4 := $(G_C_FLAGS) $(shell pkg-config --cflags --libs gtk4)
G_C_FLAGS_SECRET := $(G_C_FLAGS) $(shell pkg-config --cflags --libs libsecret-1)
BUILD_ARCH := $(shell dpkg-architecture -qDEB_HOST_MULTIARCH)

PLUGIN_NAME := seasidevpn
SERVICE_NAME := org.freedesktop.NetworkManager.$(PLUGIN_NAME)

LIB_DIR := /usr/lib/NetworkManager/VPN
BIN_DIR := /usr/lib/$(BUILD_ARCH)
PLUGIN_DIR := $(BIN_DIR)/NetworkManager
SERVICE_DIR := /usr/libexec
NM_DBUS_DIR := /usr/share/dbus-1/system.d
PLUGIN_INTERFACE_BASE := $(PLUGIN_DIR)/libnm-vpn-editor-$(PLUGIN_NAME)

REEF_DIR := ../../reef
NM_CONFIGURATION_DIR := configuration
NM_PLUGIN_DIR := plugin
NM_EDITOR_DIR := editor
NM_BUILD_DIR := build
NM_BIN_DIR := $(REEF_DIR)/target/$(BUILD_TYPE)

INSTALL_BIN := $(BIN_DIR)/libseaside.so
INSTALL_PLUGIN := $(SERVICE_DIR)/nm-$(PLUGIN_NAME)-service
INSTALL_NAME := $(LIB_DIR)/nm-$(PLUGIN_NAME)-service.name
INSTALL_CONF := $(NM_DBUS_DIR)/nm-$(PLUGIN_NAME)-service.conf
INSTALL_EDITOR := $(PLUGIN_DIR)/libnm-vpn-plugin-$(PLUGIN_NAME).so
INSTALL_INTERFACE_GTK3 := $(PLUGIN_INTERFACE_BASE)-gtk3.so
INSTALL_INTERFACE_GTK4 := $(PLUGIN_INTERFACE_BASE)-gtk4.so
INSTALL_DIALOG := $(SERVICE_DIR)/nm-$(PLUGIN_NAME)-auth-dialog

EXTRA_FLAGS := -DSEASIDE_PLUGIN_SERVICE="\"$(SERVICE_NAME)\"" -DEDITOR_INTERFACE_PATH="\"$(PLUGIN_INTERFACE_BASE)\""


dir-build:
	@ # Create build directory
	mkdir -p $(NM_BUILD_DIR)
.PHONY: dir-build

editor-build: dir-build
	@ # Build network manager reef editor
	glib-compile-resources $(NM_EDITOR_DIR)/gresource.xml --sourcedir=$(NM_EDITOR_DIR) --target=$(NM_BUILD_DIR)/resources.gen.c --generate-source
	gcc $(NM_EDITOR_DIR)/auth_dialog.c -o $(NM_BUILD_DIR)/auth_dialog $(G_C_FLAGS_SECRET)
	gcc -fPIC -shared $(NM_EDITOR_DIR)/editor.c $(NM_EDITOR_DIR)/editor.h -o $(NM_BUILD_DIR)/editor.so $(G_C_FLAGS) $(EXTRA_FLAGS)
	gcc -fPIC -shared $(NM_EDITOR_DIR)/*.h $(NM_EDITOR_DIR)/interface_gtk3.c $(NM_BUILD_DIR)/resources.gen.c -o $(NM_BUILD_DIR)/interface-gtk3.so $(EXTRA_FLAGS) $(G_C_FLAGS_GTK_3)
	gcc -fPIC -shared $(NM_EDITOR_DIR)/*.h $(NM_EDITOR_DIR)/interface_gtk4.c $(NM_BUILD_DIR)/resources.gen.c -o $(NM_BUILD_DIR)/interface-gtk4.so $(EXTRA_FLAGS) $(G_C_FLAGS_GTK_4)
.PHONY: editor-build

plugin-build: dir-build
	@ # Build network manager reef plugin
	$(MAKE) -C $(REEF_DIR) -s --no-print-directory build-lib
	gcc -fPIC $(NM_PLUGIN_DIR)/plugin.c $(NM_PLUGIN_DIR)/plugin.h -o $(NM_BUILD_DIR)/plugin $(G_C_FLAGS)
.PHONY: plugin-build

config-build: dir-build
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
	cd $(SERVICE_DIR)
ifeq ($(BUILD_TYPE),debug)
	sudo -E G_MESSAGES_DEBUG=all ./nm-$(PLUGIN_NAME)-service
else
	sudo ./nm-$(PLUGIN_NAME)-service
endif
.PHONY: install



# Artifact cleaning:

clean:
	@ # Clean network manager plugin build artifacts
	rm -rf $(NM_BUILD_DIR)
	sudo rm -f $(INSTALL_PLUGIN) $(INSTALL_NAME) $(INSTALL_CONF) $(INSTALL_EDITOR) $(INSTALL_INTERFACE_GTK3) $(INSTALL_INTERFACE_GTK4) $(INSTALL_DIALOG) $(INSTALL_BIN)
.PHONY: clean
