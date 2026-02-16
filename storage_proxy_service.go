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

// StorageProxyService provides Wails-bound methods that mirror the Electron IPC storage interface.
// The frontend's StorageWailsProxy calls these methods instead of StorageElectronIPC.
//
// Architecture:
// - storage.Provider implements wdk.WalletStorageProvider (methods WITH auth AuthID param)
// - storage.WalletStorageManager wraps Provider and implements wdk.WalletStorage (auth-free methods)
// - The TypeScript WalletStorageManager calls high-level methods (createAction, listActions, etc.)
// - Low-level CRUD methods (insertCertificate, findOutputs, etc.) are NOT called by WalletStorageManager
type StorageProxyService struct {
	mu       sync.RWMutex
	storages map[string]*storage.Provider
	managers map[string]*storage.WalletStorageManager
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
		managers: make(map[string]*storage.WalletStorageManager),
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

// MakeAvailable initializes the database, runs migrations, and creates the WalletStorageManager
func (s *StorageProxyService) MakeAvailable(identityKey string, chain string) (string, error) {
	provider, err := s.getOrCreateStorage(identityKey, chain)
	if err != nil {
		return "", err
	}

	ctx := context.Background()

	settings, err := provider.Migrate(ctx, "BSV Desktop Wallet", identityKey)
	if err != nil {
		return "", fmt.Errorf("migration failed: %w", err)
	}

	// Create WalletStorageManager wrapping the provider
	key := s.storageKey(identityKey, chain)
	wsm := storage.NewWalletStorageManager(identityKey, s.logger, provider)

	s.mu.Lock()
	s.managers[key] = wsm
	s.mu.Unlock()

	result, err := json.Marshal(settings)
	if err != nil {
		return "", fmt.Errorf("failed to marshal settings: %w", err)
	}

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

// CallMethod proxies a storage method call with JSON-serialized args
func (s *StorageProxyService) CallMethod(identityKey string, chain string, method string, argsJSON string) (string, error) {
	key := s.storageKey(identityKey, chain)

	s.mu.RLock()
	wsm := s.managers[key]
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

	ctx := context.Background()

	result, err := callStorageMethod(ctx, wsm, provider, method, args)
	if err != nil {
		return "", err
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %w", err)
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
	s.managers = make(map[string]*storage.WalletStorageManager)
	s.services = make(map[string]*services.WalletServices)
}

// callStorageMethod dispatches a method call to the WalletStorageManager or Provider.
// The WalletStorageManager handles auth internally for most methods.
// Sync methods go directly to the Provider since they're excluded from WSM.
func callStorageMethod(ctx context.Context, wsm *storage.WalletStorageManager, provider *storage.Provider, method string, args []json.RawMessage) (any, error) {
	switch method {

	// === Storage management ===

	case "migrate":
		var storageName, storageIdentityKey string
		if len(args) >= 1 {
			json.Unmarshal(args[0], &storageName)
		}
		if len(args) >= 2 {
			json.Unmarshal(args[1], &storageIdentityKey)
		}
		if wsm != nil {
			return wsm.Migrate(ctx, storageName, storageIdentityKey)
		}
		return provider.Migrate(ctx, storageName, storageIdentityKey)

	case "makeAvailable":
		if wsm != nil {
			return wsm.MakeAvailable(ctx)
		}
		return provider.MakeAvailable(ctx)

	case "findOrInsertUser":
		if len(args) < 1 {
			return nil, fmt.Errorf("findOrInsertUser requires 1 arg")
		}
		var identityKey string
		if err := json.Unmarshal(args[0], &identityKey); err != nil {
			return nil, fmt.Errorf("failed to parse findOrInsertUser args: %w", err)
		}
		if wsm != nil {
			return wsm.FindOrInsertUser(ctx, identityKey)
		}
		return provider.FindOrInsertUser(ctx, identityKey)

	case "setActive":
		if len(args) < 1 {
			return nil, fmt.Errorf("setActive requires 1 arg")
		}
		var storageIdentityKey string
		if err := json.Unmarshal(args[0], &storageIdentityKey); err != nil {
			return nil, fmt.Errorf("failed to parse setActive args: %w", err)
		}
		if wsm != nil {
			return nil, wsm.SetActive(ctx, storageIdentityKey)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return nil, provider.SetActive(ctx, auth, storageIdentityKey)

	case "destroy":
		return nil, nil

	// === Action operations ===

	case "createAction":
		if len(args) < 1 {
			return nil, fmt.Errorf("createAction requires 1 arg")
		}
		var a wdk.ValidCreateActionArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse createAction args: %w", err)
		}
		if wsm != nil {
			return wsm.CreateAction(ctx, a)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return provider.CreateAction(ctx, auth, a)

	case "processAction":
		if len(args) < 1 {
			return nil, fmt.Errorf("processAction requires 1 arg")
		}
		var a wdk.ProcessActionArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse processAction args: %w", err)
		}
		if wsm != nil {
			return wsm.ProcessAction(ctx, a)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return provider.ProcessAction(ctx, auth, a)

	case "abortAction":
		if len(args) < 1 {
			return nil, fmt.Errorf("abortAction requires 1 arg")
		}
		var a wdk.AbortActionArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse abortAction args: %w", err)
		}
		if wsm != nil {
			return wsm.AbortAction(ctx, a)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return provider.AbortAction(ctx, auth, a)

	case "internalizeAction":
		if len(args) < 1 {
			return nil, fmt.Errorf("internalizeAction requires 1 arg")
		}
		var a wdk.InternalizeActionArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse internalizeAction args: %w", err)
		}
		if wsm != nil {
			return wsm.InternalizeAction(ctx, a)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return provider.InternalizeAction(ctx, auth, a)

	// === List/query operations ===

	case "listActions":
		if len(args) < 1 {
			return nil, fmt.Errorf("listActions requires 1 arg")
		}
		var a wdk.ListActionsArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse listActions args: %w", err)
		}
		if wsm != nil {
			return wsm.ListActions(ctx, a)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return provider.ListActions(ctx, auth, a)

	case "listCertificates":
		if len(args) < 1 {
			return nil, fmt.Errorf("listCertificates requires 1 arg")
		}
		var a wdk.ListCertificatesArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse listCertificates args: %w", err)
		}
		if wsm != nil {
			return wsm.ListCertificates(ctx, a)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return provider.ListCertificates(ctx, auth, a)

	case "listOutputs":
		if len(args) < 1 {
			return nil, fmt.Errorf("listOutputs requires 1 arg")
		}
		var a wdk.ListOutputsArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse listOutputs args: %w", err)
		}
		if wsm != nil {
			return wsm.ListOutputs(ctx, a)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return provider.ListOutputs(ctx, auth, a)

	case "listTransactions":
		if len(args) < 1 {
			return nil, fmt.Errorf("listTransactions requires 1 arg")
		}
		var a wdk.ListTransactionsArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse listTransactions args: %w", err)
		}
		if wsm != nil {
			return wsm.ListTransactions(ctx, a)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return provider.ListTransactions(ctx, auth, a)

	// === Certificate operations ===

	case "insertCertificateAuth":
		if len(args) < 1 {
			return nil, fmt.Errorf("insertCertificateAuth requires 1 arg")
		}
		var cert wdk.TableCertificateX
		if err := json.Unmarshal(args[0], &cert); err != nil {
			return nil, fmt.Errorf("failed to parse insertCertificateAuth args: %w", err)
		}
		if wsm != nil {
			return wsm.InsertCertificateAuth(ctx, &cert)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return provider.InsertCertificateAuth(ctx, auth, &cert)

	case "relinquishCertificate":
		if len(args) < 1 {
			return nil, fmt.Errorf("relinquishCertificate requires 1 arg")
		}
		var a wdk.RelinquishCertificateArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse relinquishCertificate args: %w", err)
		}
		if wsm != nil {
			return nil, wsm.RelinquishCertificate(ctx, a)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return nil, provider.RelinquishCertificate(ctx, auth, a)

	case "relinquishOutput":
		if len(args) < 1 {
			return nil, fmt.Errorf("relinquishOutput requires 1 arg")
		}
		var a wdk.RelinquishOutputArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse relinquishOutput args: %w", err)
		}
		if wsm != nil {
			return nil, wsm.RelinquishOutput(ctx, a)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return nil, provider.RelinquishOutput(ctx, auth, a)

	// === Output/basket queries ===

	case "findOutputBasketsAuth":
		if len(args) < 1 {
			return nil, fmt.Errorf("findOutputBasketsAuth requires 1 arg")
		}
		var a wdk.FindOutputBasketsArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse findOutputBasketsAuth args: %w", err)
		}
		if wsm != nil {
			return wsm.FindOutputBasketsAuth(ctx, a)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return provider.FindOutputBasketsAuth(ctx, auth, a)

	case "findOutputsAuth":
		if len(args) < 1 {
			return nil, fmt.Errorf("findOutputsAuth requires 1 arg")
		}
		var a wdk.FindOutputsArgs
		if err := json.Unmarshal(args[0], &a); err != nil {
			return nil, fmt.Errorf("failed to parse findOutputsAuth args: %w", err)
		}
		if wsm != nil {
			return wsm.FindOutputsAuth(ctx, a)
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		return provider.FindOutputsAuth(ctx, auth, a)

	// === Sync operations (not on WalletStorageManager, use Provider directly) ===

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
		if len(args) < 2 {
			return nil, fmt.Errorf("findOrInsertSyncStateAuth requires 2 args")
		}
		auth, err := getProviderAuth(ctx, provider)
		if err != nil {
			return nil, err
		}
		var storageIdentityKey, storageName string
		json.Unmarshal(args[0], &storageIdentityKey)
		json.Unmarshal(args[1], &storageName)
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

	// === Low-level CRUD stubs ===
	// These methods exist on the TypeScript WalletStorageProvider interface but are internal
	// to StorageKnex and NOT called by the TypeScript WalletStorageManager.
	// If any of these are actually needed at runtime, they will produce an error
	// that can be diagnosed and the specific method implemented.
	default:
		return nil, fmt.Errorf("storage method %q not implemented in Go proxy (may be a low-level CRUD method not used by WalletStorageManager)", method)
	}
}

// getProviderAuth resolves the AuthID by looking up the user in the storage provider.
// This is used as a fallback when the WalletStorageManager is not available.
func getProviderAuth(ctx context.Context, provider *storage.Provider) (wdk.AuthID, error) {
	// The WalletStorageManager normally handles auth resolution.
	// When using the provider directly, we need to get auth another way.
	// Return an empty auth - the provider should handle this based on its internal state.
	return wdk.AuthID{}, fmt.Errorf("direct provider auth not available - ensure WalletStorageManager is initialized")
}
