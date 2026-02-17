package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var appIcon []byte

func main() {
	walletService := NewWalletService()
	app := NewApp(walletService)
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
		Mac: &mac.Options{
			About: &mac.AboutInfo{
				Title:   "BSV Desktop",
				Message: "BSV Blockchain Desktop Wallet\nVersion " + version,
				Icon:    appIcon,
			},
		},
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
