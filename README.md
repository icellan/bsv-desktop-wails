# BSV Desktop

A native desktop wallet for the BSV blockchain, built with [Wails](https://wails.io/) (Go backend + React frontend). Implements the [BRC-100](https://brc.dev/100) wallet HTTP interface, enabling third-party applications to interact with the wallet over a local HTTPS/HTTP server.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   BSV Desktop App                    │
│                                                      │
│  ┌─────────────────────┐  ┌───────────────────────┐  │
│  │   React Frontend    │  │    Go Backend          │  │
│  │                     │  │                        │  │
│  │  StorageWailsProxy ─┼──┤→ StorageProxyService   │  │
│  │  wailsFunctions    ─┼──┤→ NativeService         │  │
│  │  fetchProxy        ─┼──┤→ WalletService         │  │
│  │                     │  │                        │  │
│  └─────────────────────┘  │  HTTPServer (BRC-100)  │  │
│                           │   ├ HTTPS :2121        │  │
│                           │   └ HTTP  :3321        │  │
│                           │                        │  │
│                           │  GORM + SQLite Storage │  │
│                           └───────────────────────-┘  │
└──────────────────────────────────────────────────────┘
```

**Go Backend** — Full wallet implementation using [go-wallet-toolbox](https://github.com/bsv-blockchain/go-wallet-toolbox). Handles key management, transaction creation, certificate operations, blockchain monitoring, and storage via GORM/SQLite. Exposes a BRC-100 compliant HTTP/HTTPS server for external app integration.

**React Frontend** — TypeScript UI ported from the Electron version. Communicates with the Go backend through Wails bindings (no IPC bridge needed). Uses Material UI, React Router, and the [@bsv/wallet-toolbox](https://www.npmjs.com/package/@bsv/wallet-toolbox) client library.

**Wails Bindings** — Auto-generated TypeScript wrappers that let the frontend call Go methods directly. Replaces the Electron IPC transport layer with zero-overhead native calls.

## Prerequisites

- **Go** 1.25+ ([go.dev](https://go.dev/dl/))
- **Node.js** LTS (18+) with npm
- **Wails CLI** v2.11+ — `go install github.com/wailsapp/wails/v2/cmd/wails@latest`
- **macOS**: Xcode Command Line Tools (`xcode-select --install`)
- **Linux**: `libgtk-3-dev`, `libwebkit2gtk-4.0-dev`
- **Windows**: WebView2 runtime (included in Windows 11, available for Windows 10)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/icellan/bsv-desktop-wails.git
cd bsv-desktop-wails

# Install frontend dependencies
cd frontend && npm install && cd ..

# Development mode (builds and runs the app)
make dev
# or: ./dev.sh
# or with hot reload: ./dev.sh --hot
```

## Build

All builds are managed through the Makefile. Run `make help` to see all targets.

```bash
# Production build for current platform
make build

# macOS .app bundle
make build-mac

# macOS .dmg installer
make build-mac && make package-mac

# Linux binary
make build-linux

# Windows .exe (on Windows or with cross-compiler)
make build-win

# Run tests (Go + TypeScript type check)
make test

# Clean all build artifacts
make clean
```

### Versioning

The version is injected at build time via Go linker flags. The Makefile sources the version from git tags automatically:

```bash
# Build with a specific version
make build VERSION=v1.0.0

# Version from git tags (default behavior)
git tag v1.0.0
make build  # binary reports version "1.0.0"
```

Without a git tag, the version defaults to `dev`.

### Manual Build (without Make)

If you prefer not to use Make:

```bash
# Build frontend
cd frontend && npm install && npm run build && cd ..

# Generate Wails bindings
wails generate module

# Build Go binary (macOS)
CGO_ENABLED=1 CGO_LDFLAGS="-framework UniformTypeIdentifiers" \
  go build -tags desktop,production -ldflags "-X main.version=1.0.0" -o build/bin/BSV-Desktop .
```

## Project Structure

```
.
├── main.go                    # Wails app entry point, embeds frontend/dist
├── app.go                     # App lifecycle (startup, shutdown, version)
├── wallet_service.go          # BRC-100 wallet method dispatcher
├── wallet_args.go             # SDK type aliases for JSON deserialization
├── storage_proxy_service.go   # Storage proxy (frontend ↔ GORM/SQLite)
├── http_server.go             # BRC-100 HTTP/HTTPS server
├── ssl_cert.go                # Self-signed TLS certificate management
├── native_service.go          # Platform features (file dialogs, focus, etc.)
├── integration_test.go        # Storage proxy smoke test
├── Makefile                   # Build targets
├── build.sh                   # Build script (delegates to Make)
├── dev.sh                     # Development mode script
├── wails.json                 # Wails project configuration
├── build/
│   ├── appicon.png            # Application icon
│   └── darwin/
│       ├── Info.plist         # macOS plist (Wails template)
│       ├── Info.dev.plist     # macOS dev plist (Wails template)
│       └── Info.plist.tmpl    # macOS plist template (used by Makefile)
├── frontend/
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── src/
│       ├── main.tsx           # React entry point
│       ├── fetchProxy.ts      # Fetch proxy for manifest requests
│       ├── wailsFunctions.ts  # Wails binding wrappers
│       └── lib/               # UI components, pages, context providers
└── .github/workflows/
    ├── ci.yml                 # PR validation (build + lint + typecheck)
    └── release.yml            # Multi-platform release pipeline
```

## Go Backend Services

### WalletService

Dispatches BRC-100 wallet method calls. Supports the full wallet interface:

- **Actions**: `createAction`, `signAction`, `abortAction`, `listActions`, `internalizeAction`
- **Outputs**: `listOutputs`, `relinquishOutput`
- **Certificates**: `acquireCertificate`, `listCertificates`, `proveCertificate`, `relinquishCertificate`
- **Cryptography**: `encrypt`, `decrypt`, `createHmac`, `verifyHmac`, `createSignature`, `verifySignature`
- **Keys**: `getPublicKey`, `revealCounterpartyKeyLinkage`, `revealSpecificKeyLinkage`
- **Discovery**: `discoverByIdentityKey`, `discoverByAttributes`
- **Network**: `getHeight`, `getHeaderForHeight`, `getNetwork`, `getVersion`
- **Auth**: `isAuthenticated`, `waitForAuthentication`

### StorageProxyService

Bridges the frontend's TypeScript `WalletStorageManager` to the Go GORM storage layer:

- `MakeAvailable(identityKey, chain)` — Creates SQLite database, runs migrations
- `CallMethod(identityKey, chain, method, argsJSON)` — Dispatches storage operations
- Supports action CRUD, certificate operations, output queries, and sync operations

### HTTPServer

BRC-100 compliant HTTP interface for external application integration:

- **HTTPS**: `https://127.0.0.1:2121` (self-signed certificate, auto-generated)
- **HTTP**: `http://127.0.0.1:3321`
- Serves a `manifest.json` at the root for app discovery
- Full CORS support for browser-based applications

### NativeService

Platform-specific features exposed to the frontend:

- File download/save dialogs
- Mnemonic backup to `~/.bsv-desktop/`
- Window focus management
- Manifest proxy (CORS bypass for external manifest.json fetches)

## Data Storage

All persistent data is stored in `~/.bsv-desktop/`:

```
~/.bsv-desktop/
├── wallet-<identityKey>-<chain>.sqlite    # Wallet database(s)
├── certs/
│   ├── server.crt                         # Self-signed TLS certificate
│   └── server.key                         # TLS private key
└── mnemonic<timestamp>.txt                # Mnemonic backups (read-only)
```

## Testing

```bash
# Run all Go tests
make test

# Run only the integration smoke test
go test -tags desktop,production -run TestStorageProxySmoke -v .

# Run only the version test
go test -tags desktop,production -run TestVersionVariable -v .

# Frontend type check
cd frontend && npx tsc --noEmit
```

The integration test validates the full storage pipeline: `StorageProxyService` -> `MakeAvailable` (GORM migration + SQLite creation) -> `CallMethod("findOrInsertUser")` -> cleanup.

## CI/CD

### Pull Request Validation (`.github/workflows/ci.yml`)

Runs on every PR against `main`:
1. `go build ./...` — verifies Go compilation
2. `go vet ./...` — static analysis
3. `go test ./...` — runs all Go tests
4. `npm ci && npm run build` — verifies frontend builds
5. `npx tsc --noEmit` — TypeScript type check

### Release Pipeline (`.github/workflows/release.yml`)

Triggered by pushing a `v*.*.*` tag. Builds for all three platforms in parallel:

**macOS** (`macos-latest`):
- Builds `.app` bundle with proper Info.plist and .icns icon
- Code signs with Apple Developer ID certificate
- Notarizes with Apple notary service
- Packages as `.dmg`

**Linux** (`ubuntu-22.04`):
- Builds native binary
- GPG signs the binary
- Generates `SHA256SUMS` (also GPG signed)

**Windows** (`windows-2022`):
- Builds `.exe` with `-H windowsgui`
- Code signs with DigiCert Software Trust Manager

All artifacts are uploaded to a draft GitHub Release.

### Required Secrets

| Secret | Platform | Purpose |
|--------|----------|---------|
| `APPLE_DEVELOPER_ID_CERT` | macOS | Base64-encoded .p12 certificate |
| `APPLE_DEVELOPER_ID_CERT_PASS` | macOS | Certificate password |
| `APPLE_KEYCHAIN_PASSWORD` | macOS | Temporary keychain password |
| `APPLE_ID` | macOS | Apple ID for notarization |
| `APPLE_ID_PASS` | macOS | App-specific password for notarization |
| `APPLE_TEAM_ID` | macOS | Apple Developer Team ID |
| `APP_IMAGE_GPG_KEY` | Linux | GPG private key for signing |
| `DIGICERT_CLIENT_AUTH_CERT` | Windows | DigiCert client auth certificate |
| `DIGICERT_CLIENT_AUTH_PASS` | Windows | DigiCert certificate password |
| `DIGICERT_HOST` | Windows | DigiCert SSM host |
| `DIGICERT_KEY_LOCKER_API_KEY` | Windows | DigiCert API key |
| `DIGICERT_CODE_SIGNING_SHA1_HASH` | Windows | Certificate fingerprint |

### Creating a Release

```bash
git tag v1.0.0
git push origin v1.0.0
```

This triggers the release workflow. Once all platform builds complete, a draft release is created on GitHub with all signed artifacts.

## License

See [LICENSE](LICENSE) for details.
