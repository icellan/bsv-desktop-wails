package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStorageProxySmoke validates the storage proxy -> GORM -> SQLite pipeline end-to-end.
func TestStorageProxySmoke(t *testing.T) {
	// Use a temp directory for the SQLite database
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	// Use a fake 66-char hex identity key (33-byte compressed public key)
	testIdentityKey := "02" + strings.Repeat("ab", 32)
	testChain := "test"

	svc := NewStorageProxyService()

	// Step 1: MakeAvailable should initialize DB and run migrations
	settingsJSON, err := svc.MakeAvailable(testIdentityKey, testChain)
	if err != nil {
		t.Fatalf("MakeAvailable failed: %v", err)
	}
	if settingsJSON == "" {
		t.Fatal("MakeAvailable returned empty settings")
	}

	// Verify SQLite file was created
	bsvDir := filepath.Join(tmpDir, ".bsv-desktop")
	entries, err := os.ReadDir(bsvDir)
	if err != nil {
		t.Fatalf("Failed to read data dir: %v", err)
	}
	found := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sqlite") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("SQLite database file was not created")
	}

	// Step 2: Call "makeAvailable" via CallMethod (initializes WSM internal auth)
	makeAvailResult, err := svc.CallMethod(testIdentityKey, testChain, "makeAvailable", "[]")
	if err != nil {
		t.Fatalf("CallMethod makeAvailable failed: %v", err)
	}
	t.Logf("makeAvailable result: %s", makeAvailResult)

	// Step 3: CallMethod with findOrInsertUser
	userArg, _ := json.Marshal(testIdentityKey)
	argsJSON, _ := json.Marshal([]json.RawMessage{userArg})

	result, err := svc.CallMethod(testIdentityKey, testChain, "findOrInsertUser", string(argsJSON))
	if err != nil {
		t.Fatalf("CallMethod findOrInsertUser failed: %v", err)
	}
	if result == "" {
		t.Fatal("findOrInsertUser returned empty result")
	}

	// Step 3: Cleanup
	svc.Cleanup()
}

// TestVersionVariable verifies the version variable is set (defaults to "dev").
func TestVersionVariable(t *testing.T) {
	if version == "" {
		t.Fatal("version variable is empty")
	}
	// In test context without ldflags, should be "dev"
	if version != "dev" {
		t.Logf("version = %q (set via ldflags)", version)
	}
}
