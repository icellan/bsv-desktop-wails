#!/bin/bash
# Build script for BSV Desktop Wails app
# Thin wrapper around Makefile. Use `make help` for all targets.
#
# Usage:
#   ./build.sh            - Production build for current platform
#   ./build.sh --package  - Build macOS .app bundle + DMG

set -e

if [[ "$1" == "--package" ]]; then
  make build-mac
  make package-mac
else
  make build
fi
