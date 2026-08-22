package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const codexFingerprintDeploymentSaltFile = ".codex-fingerprint-salt"

func ensureCodexFingerprintDeploymentSalt(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	if salt := strings.TrimSpace(cfg.Gateway.CodexFingerprintDeploymentSalt); salt != "" {
		if len(salt) < 32 {
			return fmt.Errorf("gateway.codex_fingerprint_deployment_salt must contain at least 32 characters")
		}
		cfg.Gateway.CodexFingerprintDeploymentSalt = salt
		return nil
	}

	if dataDir := codexFingerprintPersistentDataDir(); dataDir != "" {
		salt, err := loadOrCreateCodexFingerprintDeploymentSalt(dataDir)
		if err != nil {
			return err
		}
		cfg.Gateway.CodexFingerprintDeploymentSalt = salt
		return nil
	}

	// Local binaries without a persistent data directory still get a stable scope
	// from deployment configuration. Container deployments use the persisted file.
	material := strings.Join([]string{
		strings.TrimSpace(cfg.Database.Host),
		strconv.Itoa(cfg.Database.Port),
		strings.TrimSpace(cfg.Database.DBName),
		strings.TrimSpace(cfg.Server.FrontendURL),
		strings.TrimSpace(cfg.JWT.Secret),
	}, "\x00")
	digest := sha256.Sum256([]byte("codex-fingerprint-deployment\x00" + material))
	cfg.Gateway.CodexFingerprintDeploymentSalt = hex.EncodeToString(digest[:])
	return nil
}

func codexFingerprintPersistentDataDir() string {
	if dataDir := strings.TrimSpace(os.Getenv("DATA_DIR")); dataDir != "" {
		return dataDir
	}
	if info, err := os.Stat("/app/data"); err == nil && info.IsDir() {
		return "/app/data"
	}
	return ""
}

func loadOrCreateCodexFingerprintDeploymentSalt(dataDir string) (string, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return "", fmt.Errorf("empty data directory")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", fmt.Errorf("create data directory: %w", err)
	}
	path := filepath.Join(dataDir, codexFingerprintDeploymentSaltFile)
	if salt, err := readCodexFingerprintDeploymentSalt(path); err == nil {
		return salt, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	salt, err := generateJWTSecret(32)
	if err != nil {
		return "", fmt.Errorf("generate deployment salt: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return readCodexFingerprintDeploymentSalt(path)
		}
		return "", fmt.Errorf("create deployment salt file: %w", err)
	}
	if _, err = f.WriteString(salt + "\n"); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("write deployment salt file: %w", err)
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close deployment salt file: %w", closeErr)
	}
	return salt, nil
}

func readCodexFingerprintDeploymentSalt(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	salt := strings.TrimSpace(string(data))
	if len(salt) < 32 {
		return "", fmt.Errorf("deployment salt file %q must contain at least 32 characters", path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", fmt.Errorf("secure deployment salt file: %w", err)
	}
	return salt, nil
}
