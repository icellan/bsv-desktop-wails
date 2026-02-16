package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/defs"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/services"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/storage"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/wdk"
)

// parseAuthFromArgs extracts an AuthID from the first argument (passed by the TS WalletStorageManager)
// and returns the remaining args. If the first arg is not a valid auth object, returns a zero AuthID
// and the original args unchanged.
func parseAuthFromArgs(args []json.RawMessage) (wdk.AuthID, []json.RawMessage) {
	if len(args) < 1 {
		return wdk.AuthID{}, args
	}
	var auth wdk.AuthID
	if err := json.Unmarshal(args[0], &auth); err != nil || auth.IdentityKey == "" {
		return wdk.AuthID{}, args
	}
	return auth, args[1:]
}

// StorageProxyService provides Wails-bound methods that mirror the Electron IPC storage interface.
// The frontend's StorageWailsProxy calls these methods instead of StorageElectronIPC.
//
// Architecture:
// - The TypeScript WalletStorageManager is the sole coordinator of active/backup stores and auth.
// - This Go service is a dumb storage provider: it routes calls to storage.Provider (GORM/SQLite).
// - Auth is passed from the TS WSM as the first argument to methods that need it.
// - There is NO Go-side WalletStorageManager — all store management happens in TypeScript.
type StorageProxyService struct {
	mu       sync.RWMutex
	storages map[string]*storage.Provider
	services map[string]*services.WalletServices
	logger   *slog.Logger
}

// NewStorageProxyService creates a new StorageProxyService
func NewStorageProxyService() *StorageProxyService {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	return &StorageProxyService{
		storages: make(map[string]*storage.Provider),
		services: make(map[string]*services.WalletServices),
		logger:   logger,
	}
}

func (s *StorageProxyService) storageKey(identityKey, chain string) string {
	return identityKey + "-" + chain
}

func (s *StorageProxyService) getOrCreateStorage(identityKey, chain string) (*storage.Provider, error) {
	key := s.storageKey(identityKey, chain)

	s.mu.RLock()
	if p, ok := s.storages[key]; ok {
		s.mu.RUnlock()
		return p, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	if p, ok := s.storages[key]; ok {
		return p, nil
	}

	network, err := defs.ParseBSVNetworkStr(chain)
	if err != nil {
		return nil, fmt.Errorf("invalid network: %w", err)
	}

	// Database path
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home dir: %w", err)
	}
	bsvDir := filepath.Join(homeDir, ".bsv-desktop")
	if err := os.MkdirAll(bsvDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create data dir: %w", err)
	}
	dbPath := filepath.Join(bsvDir, fmt.Sprintf("wallet-%s-%s.sqlite", identityKey, chain))

	// Services
	svcConfig := defs.DefaultServicesConfig(network)
	svc := services.New(s.logger, svcConfig)
	s.services[key] = svc

	// Storage
	dbConfig := defs.DefaultDBConfig()
	dbConfig.Engine = defs.DBTypeSQLite
	dbConfig.SQLite.ConnectionString = dbPath

	provider, err := storage.NewGORMProvider(network, svc,
		storage.WithDBConfig(dbConfig),
		storage.WithFeeModel(defs.DefaultFeeModel()),
		storage.WithCommission(defs.DefaultCommission()),
		storage.WithLogger(s.logger),
		storage.WithBackgroundBroadcasterContext(context.Background()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	s.storages[key] = provider
	s.logger.Info("Created storage provider", "key", key, "db", dbPath)
	return provider, nil
}

// IsAvailable checks if storage can be used for the given identity
func (s *StorageProxyService) IsAvailable(identityKey string, chain string) (bool, error) {
	_, err := s.getOrCreateStorage(identityKey, chain)
	if err != nil {
		return false, err
	}
	return true, nil
}

// MakeAvailable initializes the database, runs migrations, and returns TableSettings.
func (s *StorageProxyService) MakeAvailable(identityKey string, chain string) (string, error) {
	s.logger.Info("MakeAvailable called", "identityKey", identityKey[:16]+"...", "chain", chain)

	provider, err := s.getOrCreateStorage(identityKey, chain)
	if err != nil {
		return "", err
	}

	ctx := context.Background()

	// Run migrations first
	if _, err := provider.Migrate(ctx, "BSV Desktop Wallet", identityKey); err != nil {
		return "", fmt.Errorf("migration failed: %w", err)
	}

	// Return the actual TableSettings (with storageIdentityKey, storageName, chain, etc.)
	settings, err := provider.MakeAvailable(ctx)
	if err != nil {
		return "", fmt.Errorf("MakeAvailable failed: %w", err)
	}

	result, err := json.Marshal(settings)
	if err != nil {
		return "", fmt.Errorf("failed to marshal settings: %w", err)
	}

	s.logger.Info("MakeAvailable result", "settings", string(result))
	return string(result), nil
}

// InitializeServices sets up blockchain services on the storage
func (s *StorageProxyService) InitializeServices(identityKey string, chain string) error {
	_, err := s.getOrCreateStorage(identityKey, chain)
	if err != nil {
		return err
	}
	// Services are created in getOrCreateStorage and already connected
	return nil
}

// CallMethod proxies a storage method call with JSON-serialized args.
// The TS WalletStorageManager passes auth as the first arg for methods that need it.
func (s *StorageProxyService) CallMethod(identityKey string, chain string, method string, argsJSON string) (string, error) {
	key := s.storageKey(identityKey, chain)

	s.mu.RLock()
	provider := s.storages[key]
	s.mu.RUnlock()

	if provider == nil {
		return "", fmt.Errorf("storage not initialized - call MakeAvailable first")
	}

	// Parse args as raw JSON messages to allow typed deserialization per method
	var args []json.RawMessage
	if argsJSON != "" && argsJSON != "[]" {
		if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
			return "", fmt.Errorf("failed to parse args: %w", err)
		}
	}

	s.logger.Info("CallMethod", "method", method, "key", key, "numArgs", len(args))

	ctx := context.Background()

	result, err := callStorageMethod(ctx, provider, method, args)
	if err != nil {
		s.logger.Error("CallMethod failed", "method", method, "error", err)
		return "", err
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %w", err)
	}

	// Log full result for key methods to debug active storage issues
	if method == "findOrInsertUser" || method == "makeAvailable" || method == "setActive" {
		s.logger.Info("CallMethod result", "method", method, "result", string(resultJSON))
	} else {
		s.logger.Info("CallMethod result", "method", method, "resultLen", len(resultJSON))
	}

	return string(resultJSON), nil
}

// Cleanup destroys all storage connections
func (s *StorageProxyService) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key := range s.storages {
		s.logger.Info("Cleaning up storage", "key", key)
		delete(s.storages, key)
	}
	s.services = make(map[string]*services.WalletServices)
}

// callStorageMethod dispatches a method call to the storage.Provider.
// The TS WalletStorageManager passes auth as the first arg for methods that need it.
// Auth-free methods (makeAvailable, findOrInsertUser, migrate) are called directly.
func callStorageMethod(ctx context.Context, provider *storage.Provider, method string, args []json.RawMessage) (any, error) {
	switch method {

	// === Storage management (no auth) ===

	case "migrate":
		var storageName, storageIdentityKey string
		if len(args) >= 1 {
			json.Unmarshal(args[0], &storageName)
		}
		if len(args) >= 2 {
			json.Unmarshal(args[1], &storageIdentityKey)
		}
		return provider.Migrate(ctx, storageName, storageIdentityKey)

	case "makeAvailable":
		return provider.MakeAvailable(ctx)

	case "findOrInsertUser":
		if len(args) < 1 {
			return nil, fmt.Errorf("findOrInsertUser requires 1 arg")
		}
		var identityKey string
		if err := json.Unmarshal(args[0], &identityKey); err != nil {
			return nil, fmt.Errorf("failed to parse findOrInsertUser args: %w", err)
		}
		return provider.FindOrInsertUser(ctx, identityKey)

	case "setActive":
		// TS WSM calls: setActive(auth, storageIdentityKey)
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("setActive requires storageIdentityKey arg")
		}
		var storageIdentityKey string
		if err := json.Unmarshal(rest[0], &storageIdentityKey); err != nil {
			return nil, fmt.Errorf("failed to parse setActive storageIdentityKey: %w", err)
		}
		return nil, provider.SetActive(ctx, auth, storageIdentityKey)

	case "destroy":
		return nil, nil

	// === Action operations (auth as first arg from TS WSM) ===

	case "createAction":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("createAction requires args")
		}
		var a wdk.ValidCreateActionArgs
		if err := json.Unmarshal(rest[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse createAction args: %w", err)
		}
		return provider.CreateAction(ctx, auth, a)

	case "processAction":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("processAction requires args")
		}
		var a wdk.ProcessActionArgs
		if err := json.Unmarshal(rest[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse processAction args: %w", err)
		}
		return provider.ProcessAction(ctx, auth, a)

	case "abortAction":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("abortAction requires args")
		}
		var a wdk.AbortActionArgs
		if err := json.Unmarshal(rest[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse abortAction args: %w", err)
		}
		return provider.AbortAction(ctx, auth, a)

	case "internalizeAction":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("internalizeAction requires args")
		}
		var a wdk.InternalizeActionArgs
		if err := json.Unmarshal(rest[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse internalizeAction args: %w", err)
		}
		return provider.InternalizeAction(ctx, auth, a)

	// === List/query operations (auth as first arg from TS WSM) ===

	case "listActions":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("listActions requires args")
		}
		var a wdk.ListActionsArgs
		if err := json.Unmarshal(rest[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse listActions args: %w", err)
		}
		return provider.ListActions(ctx, auth, a)

	case "listCertificates":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("listCertificates requires args")
		}
		var a wdk.ListCertificatesArgs
		if err := json.Unmarshal(rest[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse listCertificates args: %w", err)
		}
		return provider.ListCertificates(ctx, auth, a)

	case "listOutputs":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("listOutputs requires args")
		}
		var a wdk.ListOutputsArgs
		if err := json.Unmarshal(rest[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse listOutputs args: %w", err)
		}
		return provider.ListOutputs(ctx, auth, a)

	case "listTransactions":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("listTransactions requires args")
		}
		var a wdk.ListTransactionsArgs
		if err := json.Unmarshal(rest[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse listTransactions args: %w", err)
		}
		return provider.ListTransactions(ctx, auth, a)

	// === Certificate operations (auth as first arg from TS WSM) ===

	case "insertCertificateAuth":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("insertCertificateAuth requires args")
		}
		var cert wdk.TableCertificateX
		if err := json.Unmarshal(rest[0], &cert); err != nil {
			return nil, fmt.Errorf("failed to parse insertCertificateAuth args: %w", err)
		}
		return provider.InsertCertificateAuth(ctx, auth, &cert)

	case "relinquishCertificate":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("relinquishCertificate requires args")
		}
		var a wdk.RelinquishCertificateArgs
		if err := json.Unmarshal(rest[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse relinquishCertificate args: %w", err)
		}
		return nil, provider.RelinquishCertificate(ctx, auth, a)

	case "relinquishOutput":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("relinquishOutput requires args")
		}
		var a wdk.RelinquishOutputArgs
		if err := json.Unmarshal(rest[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse relinquishOutput args: %w", err)
		}
		return nil, provider.RelinquishOutput(ctx, auth, a)

	// === Output/basket queries (auth as first arg from TS WSM) ===

	case "findOutputBasketsAuth":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("findOutputBasketsAuth requires args")
		}
		var a wdk.FindOutputBasketsArgs
		if err := json.Unmarshal(rest[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse findOutputBasketsAuth args: %w", err)
		}
		return provider.FindOutputBasketsAuth(ctx, auth, a)

	case "findOutputsAuth":
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 1 {
			return nil, fmt.Errorf("findOutputsAuth requires args")
		}
		var a wdk.FindOutputsArgs
		if err := json.Unmarshal(rest[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse findOutputsAuth args: %w", err)
		}
		return provider.FindOutputsAuth(ctx, auth, a)

	// === Sync operations ===

	case "getSyncChunk":
		if len(args) < 1 {
			return nil, fmt.Errorf("getSyncChunk requires 1 arg")
		}
		var a wdk.RequestSyncChunkArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse getSyncChunk args: %w", err)
		}
		return provider.GetSyncChunk(ctx, a)

	case "findOrInsertSyncStateAuth":
		// TS WSM calls: findOrInsertSyncStateAuth(auth, storageIdentityKey, storageName)
		auth, rest := parseAuthFromArgs(args)
		if len(rest) < 2 {
			return nil, fmt.Errorf("findOrInsertSyncStateAuth requires storageIdentityKey and storageName args")
		}
		var storageIdentityKey, storageName string
		json.Unmarshal(rest[0], &storageIdentityKey)
		json.Unmarshal(rest[1], &storageName)
		return provider.FindOrInsertSyncStateAuth(ctx, auth, storageIdentityKey, storageName)

	case "processSyncChunk":
		if len(args) < 2 {
			return nil, fmt.Errorf("processSyncChunk requires 2 args")
		}
		var reqArgs wdk.RequestSyncChunkArgs
		var chunk wdk.SyncChunk
		if err := json.Unmarshal(args[0], &reqArgs); err != nil {
			return nil, fmt.Errorf("failed to parse processSyncChunk reqArgs: %w", err)
		}
		if err := json.Unmarshal(args[1], &chunk); err != nil {
			return nil, fmt.Errorf("failed to parse processSyncChunk chunk: %w", err)
		}
		return provider.ProcessSyncChunk(ctx, reqArgs, &chunk)

	default:
		return nil, fmt.Errorf("storage method %q not implemented in Go proxy", method)
	}
}
