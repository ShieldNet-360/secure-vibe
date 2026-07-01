# Makefile for building a macOS .pkg installer for secure-vibe.
#
# Prerequisites:
#   - macOS with Xcode Command Line Tools (pkgbuild, productbuild)
#   - Pre-built secure-vibe universal or platform binary at $(BINARY)
#
# Usage:
#   make BINARY=../../dist-build/secure-vibe-darwin-arm64 VERSION=2026.05.12
#   # produces: build/secure-vibe-$(VERSION).pkg

BINARY   ?= ../../secure-vibe
VERSION  ?= 0.0.0
INSTALL_DIR = /usr/local/bin
IDENTIFIER = com.secure-vibe.secure-vibe
BUILD_DIR  = build
PKG_ROOT   = $(BUILD_DIR)/pkg-root

.PHONY: all clean

all: $(BUILD_DIR)/secure-vibe-$(VERSION).pkg

$(BUILD_DIR)/secure-vibe-$(VERSION).pkg: $(BUILD_DIR)/component.pkg distribution.xml
	productbuild \
		--distribution distribution.xml \
		--package-path $(BUILD_DIR) \
		--version "$(VERSION)" \
		$@

$(BUILD_DIR)/component.pkg: $(PKG_ROOT)$(INSTALL_DIR)/secure-vibe
	pkgbuild \
		--identifier "$(IDENTIFIER)" \
		--version "$(VERSION)" \
		--root $(PKG_ROOT) \
		--install-location / \
		$@

$(PKG_ROOT)$(INSTALL_DIR)/secure-vibe: $(BINARY)
	mkdir -p $(dir $@)
	cp $(BINARY) $@
	chmod 755 $@

clean:
	rm -rf $(BUILD_DIR)
