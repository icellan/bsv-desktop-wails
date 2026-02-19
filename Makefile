# BSV Desktop Wails - Build System
# Usage: make [target]

# --- Variables ---
APP_NAME     := BSV-Desktop
BUNDLE_ID    := org.bsvblockchain.bsv-desktop
FRONTEND_DIR := frontend
OUTPUT_DIR   := build/bin
ICON_SRC     := build/appicon.png

VERSION      ?= $(shell git describe --tags --always 2>/dev/null || echo "dev")
# Strip leading 'v' from tag (v1.2.3 -> 1.2.3)
CLEAN_VERSION = $(shell echo $(VERSION) | sed 's/^v//')

BUILD_TAGS   := desktop,production
LDFLAGS      := -X main.version=$(CLEAN_VERSION)
CGO_FLAGS    := CGO_ENABLED=1

# Platform-specific
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  CGO_LDFLAGS := -framework UniformTypeIdentifiers
endif

# Wails binary (may not be in PATH)
WAILS := $(shell which wails 2>/dev/null || echo $(HOME)/go/bin/wails)

# --- Targets ---

.PHONY: all dev build build-mac build-win build-linux bindings frontend clean test package-mac help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

all: frontend bindings build ## Full build (frontend + bindings + binary)

dev: ## Build and run in dev mode
	@./dev.sh

build: frontend ## Production build for current platform
	@echo "=== Building $(APP_NAME) $(CLEAN_VERSION) ==="
	@mkdir -p $(OUTPUT_DIR)
	$(CGO_FLAGS) CGO_LDFLAGS="$(CGO_LDFLAGS)" \
		go build -mod=vendor -tags $(BUILD_TAGS) -ldflags '$(LDFLAGS)' -o $(OUTPUT_DIR)/$(APP_NAME) .
	@echo "Binary: $(OUTPUT_DIR)/$(APP_NAME)"

build-mac: frontend ## macOS .app bundle
	@echo "=== Building macOS .app bundle ==="
	@mkdir -p $(OUTPUT_DIR)
	$(CGO_FLAGS) CGO_LDFLAGS="-framework UniformTypeIdentifiers" \
		go build -mod=vendor -tags $(BUILD_TAGS) -ldflags '$(LDFLAGS)' -o $(OUTPUT_DIR)/$(APP_NAME) .
	@# Create .app bundle structure
	@mkdir -p "$(OUTPUT_DIR)/$(APP_NAME).app/Contents/MacOS"
	@mkdir -p "$(OUTPUT_DIR)/$(APP_NAME).app/Contents/Resources"
	@cp $(OUTPUT_DIR)/$(APP_NAME) "$(OUTPUT_DIR)/$(APP_NAME).app/Contents/MacOS/$(APP_NAME)"
	@# Generate .icns icon
	@$(MAKE) --no-print-directory _gen-icns
	@# Generate Info.plist
	@sed -e 's/$${VERSION}/$(CLEAN_VERSION)/g' \
	     -e 's/$${APP_NAME}/$(APP_NAME)/g' \
	     -e 's/$${BUNDLE_ID}/$(BUNDLE_ID)/g' \
	     build/darwin/Info.plist.tmpl > "$(OUTPUT_DIR)/$(APP_NAME).app/Contents/Info.plist"
	@echo "App bundle: $(OUTPUT_DIR)/$(APP_NAME).app"

build-win: frontend ## Windows build (requires Windows or cross-compile)
	@echo "=== Building Windows .exe ==="
	@mkdir -p $(OUTPUT_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
		go build -mod=vendor -tags $(BUILD_TAGS) -ldflags '$(LDFLAGS) -H windowsgui' -o $(OUTPUT_DIR)/$(APP_NAME).exe .
	@echo "Binary: $(OUTPUT_DIR)/$(APP_NAME).exe"

build-linux: frontend ## Linux build
	@echo "=== Building Linux binary ==="
	@mkdir -p $(OUTPUT_DIR)
	CGO_ENABLED=1 \
		go build -mod=vendor -tags $(BUILD_TAGS) -ldflags '$(LDFLAGS)' -o $(OUTPUT_DIR)/$(APP_NAME) .
	@echo "Binary: $(OUTPUT_DIR)/$(APP_NAME)"

bindings: ## Regenerate Wails TypeScript bindings
	@echo "=== Generating Wails bindings ==="
	@$(WAILS) generate module

frontend: ## Install deps and build frontend
	@echo "=== Building frontend ==="
	@cd $(FRONTEND_DIR) && npm install --silent && npm run build

clean: ## Remove build artifacts
	@echo "=== Cleaning ==="
	@rm -rf $(OUTPUT_DIR)
	@rm -rf $(FRONTEND_DIR)/dist
	@rm -rf build/icons.iconset
	@echo "Clean complete"

test: ## Run Go tests and frontend type-check
	@echo "=== Running Go tests ==="
	go test -v -count=1 ./...
	@echo ""
	@echo "=== TypeScript type check ==="
	@cd $(FRONTEND_DIR) && npx tsc --noEmit
	@echo "All checks passed"

package-mac: ## Create .dmg from .app bundle (macOS only)
	@echo "=== Creating DMG ==="
	@test -d "$(OUTPUT_DIR)/$(APP_NAME).app" || (echo "Error: run 'make build-mac' first" && exit 1)
	@rm -f "$(OUTPUT_DIR)/$(APP_NAME)-$(CLEAN_VERSION).dmg"
	@hdiutil create -volname "$(APP_NAME)" \
		-srcfolder "$(OUTPUT_DIR)/$(APP_NAME).app" \
		-ov -format UDZO \
		"$(OUTPUT_DIR)/$(APP_NAME)-$(CLEAN_VERSION).dmg"
	@echo "DMG: $(OUTPUT_DIR)/$(APP_NAME)-$(CLEAN_VERSION).dmg"

# --- Internal targets ---

_gen-icns: ## (internal) Generate .icns from appicon.png
	@if [ -f "$(ICON_SRC)" ]; then \
		echo "  Generating .icns icon..."; \
		ICONSET="build/icons.iconset"; \
		mkdir -p "$$ICONSET"; \
		sips -z 16 16     "$(ICON_SRC)" --out "$$ICONSET/icon_16x16.png"      > /dev/null 2>&1; \
		sips -z 32 32     "$(ICON_SRC)" --out "$$ICONSET/icon_16x16@2x.png"   > /dev/null 2>&1; \
		sips -z 32 32     "$(ICON_SRC)" --out "$$ICONSET/icon_32x32.png"      > /dev/null 2>&1; \
		sips -z 64 64     "$(ICON_SRC)" --out "$$ICONSET/icon_32x32@2x.png"   > /dev/null 2>&1; \
		sips -z 128 128   "$(ICON_SRC)" --out "$$ICONSET/icon_128x128.png"    > /dev/null 2>&1; \
		sips -z 256 256   "$(ICON_SRC)" --out "$$ICONSET/icon_128x128@2x.png" > /dev/null 2>&1; \
		sips -z 256 256   "$(ICON_SRC)" --out "$$ICONSET/icon_256x256.png"    > /dev/null 2>&1; \
		sips -z 512 512   "$(ICON_SRC)" --out "$$ICONSET/icon_256x256@2x.png" > /dev/null 2>&1; \
		sips -z 512 512   "$(ICON_SRC)" --out "$$ICONSET/icon_512x512.png"    > /dev/null 2>&1; \
		sips -z 1024 1024 "$(ICON_SRC)" --out "$$ICONSET/icon_512x512@2x.png" > /dev/null 2>&1; \
		iconutil -c icns "$$ICONSET" -o "$(OUTPUT_DIR)/$(APP_NAME).app/Contents/Resources/appicon.icns"; \
		rm -rf "$$ICONSET"; \
	else \
		echo "  Warning: $(ICON_SRC) not found, skipping icon generation"; \
	fi
