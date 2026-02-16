package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()
	walletService := NewWalletService()
	nativeService := NewNativeService()
	storageProxyService := NewStorageProxyService()

	err := wails.Run(&options.App{
		Title:  "BSV Desktop",
		Width:  1200,
		Height: 800,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 255, G: 255, B: 255, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		OnDomReady:       app.domReady,
		Bind: []interface{}{
			app,
			walletService,
			nativeService,
			storageProxyService,
		},
	})

	if err != nil {
		log.Fatal("Error:", err.Error())
	}
}
