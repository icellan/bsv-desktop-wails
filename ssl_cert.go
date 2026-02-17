package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// GenerateOrLoadSelfSignedCert generates or loads a self-signed TLS certificate.
// Returns certPEM, keyPEM, certPath, error.
func GenerateOrLoadSelfSignedCert() ([]byte, []byte, string, error) {
	certDir, err := getCertDir()
	if err != nil {
		return nil, nil, "", err
	}

	certPath := filepath.Join(certDir, "server.crt")
	keyPath := filepath.Join(certDir, "server.key")

	// Try to load existing certificate
	if certPEM, keyPEM, ok := loadExistingCert(certPath, keyPath); ok {
		return certPEM, keyPEM, certPath, nil
	}

	// Generate new certificate
	return generateNewCert(certPath, keyPath)
}

func getCertDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	certDir := filepath.Join(homeDir, ".bsv-desktop", "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create cert directory: %w", err)
	}

	return certDir, nil
}

func loadExistingCert(certPath, keyPath string) ([]byte, []byte, bool) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, false
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, false
	}

	// Parse and validate expiration
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, false
	}

	if time.Now().After(cert.NotAfter) {
		return nil, nil, false // Expired
	}

	return certPEM, keyPEM, true
}

func generateNewCert(certPath, keyPath string) ([]byte, []byte, string, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"BSV Desktop"},
			Country:      []string{"US"},
			Province:     []string{"California"},
			Locality:     []string{"San Francisco"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // 1 year

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Self-sign certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// Save to disk
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, nil, "", fmt.Errorf("failed to write certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, "", fmt.Errorf("failed to write key: %w", err)
	}

	return certPEM, keyPEM, certPath, nil
}

// EnsureCertTrusted checks if the self-signed cert is trusted by the system
// and attempts to install it if not. On macOS this adds it to the login keychain.
func EnsureCertTrusted(certPath string) error {
	if runtime.GOOS != "darwin" {
		return nil // Only macOS for now
	}

	// Check if already prompted
	promptedFlag := filepath.Join(filepath.Dir(certPath), ".ssl-prompted")
	if _, err := os.Stat(promptedFlag); err == nil {
		// Check if already trusted
		if isCertTrustedMac() {
			return nil
		}
	}

	// Check if already trusted
	if isCertTrustedMac() {
		return nil
	}

	// Install cert to user login keychain (without -d to avoid needing admin elevation)
	cmd := exec.Command("security", "add-trusted-cert", "-r", "trustRoot",
		"-k", filepath.Join(os.Getenv("HOME"), "Library/Keychains/login.keychain-db"),
		certPath)
	if err := cmd.Run(); err != nil {
		// Mark as prompted even on failure so we don't keep asking
		os.WriteFile(promptedFlag, []byte(time.Now().Format(time.RFC3339)), 0o644)
		return fmt.Errorf("failed to install certificate: %w", err)
	}

	// Mark as prompted
	os.WriteFile(promptedFlag, []byte(time.Now().Format(time.RFC3339)), 0o644)
	return nil
}

func isCertTrustedMac() bool {
	cmd := exec.Command("security", "find-certificate", "-c", "localhost", "-p",
		filepath.Join(os.Getenv("HOME"), "Library/Keychains/login.keychain-db"))
	return cmd.Run() == nil
}
