package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTPServer provides the BRC-100 HTTP/HTTPS interface for external apps
type HTTPServer struct {
	logger       *slog.Logger
	httpsServer  *http.Server
	httpServer   *http.Server
	walletSvc    *WalletService
	mu           sync.RWMutex
}

// NewHTTPServer creates a new HTTP server
func NewHTTPServer(logger *slog.Logger) *HTTPServer {
	return &HTTPServer{
		logger: logger,
	}
}

// SetWalletService sets the wallet service for handling requests
func (s *HTTPServer) SetWalletService(ws *WalletService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.walletSvc = ws
}

// Start starts both HTTPS (2121) and HTTP (3321) servers
func (s *HTTPServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	handler := s.corsMiddleware(mux)

	// Generate self-signed certificate for HTTPS
	certPEM, keyPEM, certPath, err := GenerateOrLoadSelfSignedCert()
	if err != nil {
		s.logger.Warn("Failed to generate SSL certificate, running HTTP only", "error", err)
	} else {
		// Ensure cert is trusted by the system (adds to macOS keychain)
		if err := EnsureCertTrusted(certPath); err != nil {
			s.logger.Warn("Failed to install certificate to system trust store", "error", err)
		} else {
			s.logger.Info("SSL certificate trusted by system")
		}
		// Start HTTPS server on port 2121
		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			s.logger.Warn("Failed to parse TLS certificate", "error", err)
		} else {
			s.httpsServer = &http.Server{
				Addr:    "127.0.0.1:2121",
				Handler: handler,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{tlsCert},
				},
			}

			go func() {
				ln, err := net.Listen("tcp", s.httpsServer.Addr)
				if err != nil {
					s.logger.Error("HTTPS server failed to listen", "error", err)
					return
				}
				tlsLn := tls.NewListener(ln, s.httpsServer.TLSConfig)
				s.logger.Info("HTTPS server listening", "addr", "https://127.0.0.1:2121")
				if err := s.httpsServer.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
					s.logger.Error("HTTPS server error", "error", err)
				}
			}()
		}
	}

	// Start HTTP server on port 3321
	s.httpServer = &http.Server{
		Addr:    "127.0.0.1:3321",
		Handler: handler,
	}

	go func() {
		s.logger.Info("HTTP server listening", "addr", "http://127.0.0.1:3321")
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server error", "error", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	return nil
}

// Stop gracefully shuts down the servers
func (s *HTTPServer) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			s.logger.Error("HTTPS server shutdown error", "error", err)
		}
		s.logger.Info("HTTPS server stopped")
	}

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Error("HTTP server shutdown error", "error", err)
		}
		s.logger.Info("HTTP server stopped")
	}
}

// corsMiddleware adds CORS headers to all responses
func (s *HTTPServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Expose-Headers", "*")
		w.Header().Set("Access-Control-Allow-Private-Network", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleRequest handles all incoming HTTP requests
func (s *HTTPServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Serve manifest.json
	if path == "/manifest.json" && r.Method == "GET" {
		s.serveManifest(w, r)
		return
	}

	// Parse origin
	origin := parseOrigin(r)
	if origin == "" {
		s.writeError(w, http.StatusBadRequest, "Origin header is required")
		return
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(r.Body, 50<<20)) // 50MB limit
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}
	defer r.Body.Close()

	// Strip leading slash to get method name
	method := strings.TrimPrefix(path, "/")

	s.mu.RLock()
	ws := s.walletSvc
	s.mu.RUnlock()

	if ws == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Wallet not initialized")
		return
	}

	// Call wallet method
	result, err := ws.CallWalletMethod(method, string(body), origin)
	if err != nil {
		s.logger.Error("Wallet method error", "method", method, "error", err)
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, result)
}

// serveManifest returns the BRC-100 manifest
func (s *HTTPServer) serveManifest(w http.ResponseWriter, _ *http.Request) {
	manifest := map[string]any{
		"short_name": "BSV Desktop",
		"name":       "BSV Desktop",
		"icons": []map[string]any{
			{
				"src":   "favicon.ico",
				"sizes": "64x64 32x32 24x24 16x16",
				"type":  "image/x-icon",
			},
		},
		"start_url":        ".",
		"display":          "standalone",
		"theme_color":      "#000000",
		"background_color": "#ffffff",
		"babbage": map[string]any{
			"trust": map[string]any{
				"name":      "BSV Desktop",
				"note":      "Allows basic payments between counterparties",
				"icon":      "https://localhost:2121/favicon.ico",
				"publicKey": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(manifest)
}

// writeError writes a JSON error response
func (s *HTTPServer) writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"message": message})
}

// parseOrigin extracts the origin from request headers
func parseOrigin(r *http.Request) string {
	rawOrigin := r.Header.Get("Origin")
	rawOriginator := r.Header.Get("Originator")

	if rawOrigin != "" {
		// Extract host from full origin URL
		if strings.Contains(rawOrigin, "://") {
			parts := strings.SplitN(rawOrigin, "://", 2)
			if len(parts) == 2 {
				return parts[1]
			}
		}
		return rawOrigin
	}

	if rawOriginator != "" {
		if strings.Contains(rawOriginator, "://") {
			parts := strings.SplitN(rawOriginator, "://", 2)
			if len(parts) == 2 {
				return parts[1]
			}
		}
		return rawOriginator
	}

	return ""
}
