#!/bin/bash
# Dev mode script for BSV Desktop Wails app
# Workaround for Wails v2 type analysis bug with complex Go dependencies
#
# Usage:
#   ./dev.sh          - Build and run (serves pre-built frontend)
#   ./dev.sh --hot    - Build and run with Vite HMR (hot reload for frontend)

set -e

FRONTEND_DIR="frontend"
OUTPUT_DIR="build/bin"
OUTPUT_NAME="BSV-Desktop-dev"
VITE_PORT=34115

cleanup() {
  echo ""
  echo "Shutting down..."
  [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null
  [ -n "$VITE_PID" ] && kill "$VITE_PID" 2>/dev/null
  wait "$APP_PID" 2>/dev/null
  wait "$VITE_PID" 2>/dev/null
  echo "Done."
}
trap cleanup EXIT INT TERM

# Step 1: Build frontend
echo "[1/3] Building frontend..."
cd "$FRONTEND_DIR"
npm run build --silent 2>/dev/null
cd ..

# Step 2: Build Go binary with dev tags
echo "[2/3] Building Go binary (dev mode)..."
CGO_ENABLED=1 CGO_LDFLAGS="-framework UniformTypeIdentifiers" \
  go build -mod=vendor -tags dev,desktop -o "$OUTPUT_DIR/$OUTPUT_NAME" .

# Step 3: Run
echo "[3/3] Starting BSV Desktop..."

if [ "$1" = "--hot" ]; then
  echo "  Starting Vite dev server on port $VITE_PORT..."
  cd "$FRONTEND_DIR"
  npx vite --port "$VITE_PORT" &
  VITE_PID=$!
  cd ..
  sleep 2
  echo "  Starting app with HMR..."
  FRONTEND_DEVSERVER_URL="http://localhost:$VITE_PORT" \
    "./$OUTPUT_DIR/$OUTPUT_NAME" -assetdir "./$FRONTEND_DIR/dist" &
  APP_PID=$!
else
  echo "  Starting app (static frontend)..."
  "./$OUTPUT_DIR/$OUTPUT_NAME" -assetdir "./$FRONTEND_DIR/dist" &
  APP_PID=$!
fi

echo ""
echo "=== BSV Desktop running ==="
echo "  App window should be visible"
echo "  HTTPS API: https://127.0.0.1:2121"
echo "  HTTP API:  http://127.0.0.1:3321"
[ "$1" = "--hot" ] && echo "  Vite HMR:  http://localhost:$VITE_PORT"
echo "  Press Ctrl+C to stop"
echo ""

wait "$APP_PID"
