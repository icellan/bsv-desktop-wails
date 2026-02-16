package main

import (
	"context"
	"log/slog"
	"os"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// version is set at build time via -ldflags "-X main.version=x.y.z"
var version = "dev"

// App struct manages the application lifecycle
type App struct {
	ctx          context.Context
	cancel       context.CancelFunc
	logger       *slog.Logger
	httpServer   *HTTPServer
	walletSvc    *WalletService
	nativeSvc    *NativeService
}

// NewApp creates a new App application struct
func NewApp() *App {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	return &App{
		logger: logger,
	}
}

// startup is called when the app starts
func (a *App) startup(ctx context.Context) {
	appCtx, cancel := context.WithCancel(ctx)
	a.ctx = appCtx
	a.cancel = cancel

	a.logger.Info("BSV Desktop starting up")

	// Start HTTP server for BRC-100 interface
	a.httpServer = NewHTTPServer(a.logger)
	go func() {
		if err := a.httpServer.Start(appCtx); err != nil {
			a.logger.Error("HTTP server error", "error", err)
		}
	}()

	a.logger.Info("BSV Desktop startup complete")
}

// domReady is called after front-end resources have been loaded
func (a *App) domReady(ctx context.Context) {
	a.logger.Info("DOM ready")
}

// shutdown is called when the app is closing
func (a *App) shutdown(ctx context.Context) {
	a.logger.Info("BSV Desktop shutting down")

	if a.httpServer != nil {
		a.httpServer.Stop()
	}

	if a.cancel != nil {
		a.cancel()
	}

	a.logger.Info("BSV Desktop shutdown complete")
}

// GetAppVersion returns the application version
func (a *App) GetAppVersion() string {
	return version
}

// GetAppName returns the application name
func (a *App) GetAppName() string {
	return "BSV Desktop"
}

// OpenExternalURL opens a URL in the default browser
func (a *App) OpenExternalURL(url string) {
	wailsRuntime.BrowserOpenURL(a.ctx, url)
}
