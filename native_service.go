package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// NativeService provides platform-specific operations bound to Wails
type NativeService struct {
	ctx context.Context
}

// NewNativeService creates a new NativeService
func NewNativeService() *NativeService {
	return &NativeService{}
}

// SetContext sets the Wails context (called from app.startup)
func (n *NativeService) SetContext(ctx context.Context) {
	n.ctx = ctx
}

// --- Focus Management ---

// IsFocused checks if the window is focused
func (n *NativeService) IsFocused() bool {
	// Wails v2 doesn't have a direct IsFocused check, but the window is focused
	// if it's in the foreground. We'll return true as a default.
	return true
}

// RequestFocus brings the window to the foreground
func (n *NativeService) RequestFocus() {
	if n.ctx == nil {
		return
	}
	wailsRuntime.WindowShow(n.ctx)
	wailsRuntime.WindowUnminimise(n.ctx)
	wailsRuntime.WindowSetAlwaysOnTop(n.ctx, true)

	// Remove always-on-top after a brief moment
	go func() {
		time.Sleep(100 * time.Millisecond)
		wailsRuntime.WindowSetAlwaysOnTop(n.ctx, false)
	}()
}

// RelinquishFocus minimizes the window
func (n *NativeService) RelinquishFocus() {
	if n.ctx == nil {
		return
	}
	wailsRuntime.WindowMinimise(n.ctx)
}

// --- File Operations ---

// FileResult represents the result of a file operation
type FileResult struct {
	Success  bool   `json:"success"`
	Path     string `json:"path,omitempty"`
	Error    string `json:"error,omitempty"`
	Canceled bool   `json:"canceled,omitempty"`
}

// DownloadFile saves content to the Downloads folder
func (n *NativeService) DownloadFile(fileName string, content []byte) FileResult {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return FileResult{Success: false, Error: err.Error()}
	}

	downloadsDir := filepath.Join(homeDir, "Downloads")
	finalPath := filepath.Join(downloadsDir, fileName)

	// Handle duplicate file names
	ext := filepath.Ext(fileName)
	stem := strings.TrimSuffix(fileName, ext)
	counter := 1
	for {
		if _, err := os.Stat(finalPath); os.IsNotExist(err) {
			break
		}
		if ext != "" {
			finalPath = filepath.Join(downloadsDir, fmt.Sprintf("%s (%d)%s", stem, counter, ext))
		} else {
			finalPath = filepath.Join(downloadsDir, fmt.Sprintf("%s (%d)", stem, counter))
		}
		counter++
	}

	if err := os.WriteFile(finalPath, content, 0o644); err != nil {
		return FileResult{Success: false, Error: err.Error()}
	}

	return FileResult{Success: true, Path: finalPath}
}

// SaveFileDialog opens a save dialog and writes content to the selected path
func (n *NativeService) SaveFileDialog(defaultPath string, content []byte) FileResult {
	if n.ctx == nil {
		return FileResult{Success: false, Error: "context not initialized"}
	}

	filePath, err := wailsRuntime.SaveFileDialog(n.ctx, wailsRuntime.SaveDialogOptions{
		DefaultFilename: defaultPath,
	})
	if err != nil {
		return FileResult{Success: false, Error: err.Error()}
	}
	if filePath == "" {
		return FileResult{Success: false, Canceled: true}
	}

	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		return FileResult{Success: false, Error: err.Error()}
	}

	return FileResult{Success: true, Path: filePath}
}

// SaveMnemonic saves a mnemonic to ~/.bsv-desktop/ with read-only permissions
func (n *NativeService) SaveMnemonic(mnemonic string) FileResult {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return FileResult{Success: false, Error: err.Error()}
	}

	bsvDir := filepath.Join(homeDir, ".bsv-desktop")
	if err := os.MkdirAll(bsvDir, 0o755); err != nil {
		return FileResult{Success: false, Error: err.Error()}
	}

	fileName := fmt.Sprintf("mnemonic%d.txt", time.Now().UnixMilli())
	filePath := filepath.Join(bsvDir, fileName)

	if err := os.WriteFile(filePath, []byte(mnemonic), 0o400); err != nil {
		return FileResult{Success: false, Error: err.Error()}
	}

	return FileResult{Success: true, Path: filePath}
}

// --- Manifest Proxy ---

// ManifestProxyResult represents the result of a manifest proxy request
type ManifestProxyResult struct {
	Status  int        `json:"status"`
	Headers [][]string `json:"headers"`
	Body    string     `json:"body"`
}

// ProxyFetchManifest fetches a manifest.json file, bypassing CORS restrictions
func (n *NativeService) ProxyFetchManifest(rawURL string) (ManifestProxyResult, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ManifestProxyResult{}, fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Scheme != "https" {
		return ManifestProxyResult{}, fmt.Errorf("only HTTPS URLs are allowed")
	}

	pathname := strings.ToLower(parsed.Path)
	if !strings.HasSuffix(pathname, "/manifest.json") && pathname != "/manifest.json" {
		return ManifestProxyResult{}, fmt.Errorf("only manifest.json files are allowed")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return ManifestProxyResult{}, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "bsv-desktop-wails/1.0")
	req.Header.Set("Accept", "application/json, */*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return ManifestProxyResult{}, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ManifestProxyResult{}, fmt.Errorf("failed to read response: %w", err)
	}

	headers := make([][]string, 0)
	for key, values := range resp.Header {
		for _, val := range values {
			headers = append(headers, []string{key, val})
		}
	}

	return ManifestProxyResult{
		Status:  resp.StatusCode,
		Headers: headers,
		Body:    string(body),
	}, nil
}

// GetPlatform returns the current OS platform
func (n *NativeService) GetPlatform() string {
	return runtime.GOOS
}
