package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadOrCreateCodexFingerprintDeploymentSaltPersists(t *testing.T) {
	dataDir := t.TempDir()
	first, err := loadOrCreateCodexFingerprintDeploymentSalt(dataDir)
	require.NoError(t, err)
	require.Len(t, first, 64)

	second, err := loadOrCreateCodexFingerprintDeploymentSalt(dataDir)
	require.NoError(t, err)
	require.Equal(t, first, second)

	path := filepath.Join(dataDir, codexFingerprintDeploymentSaltFile)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestEnsureCodexFingerprintDeploymentSaltHonorsConfiguredValue(t *testing.T) {
	want := strings.Repeat("scope-a", 8)
	cfg := &Config{Gateway: GatewayConfig{CodexFingerprintDeploymentSalt: "  " + want + "  "}}

	require.NoError(t, ensureCodexFingerprintDeploymentSalt(cfg))
	require.Equal(t, want, cfg.Gateway.CodexFingerprintDeploymentSalt)
}

func TestEnsureCodexFingerprintDeploymentSaltRejectsShortValue(t *testing.T) {
	cfg := &Config{Gateway: GatewayConfig{CodexFingerprintDeploymentSalt: "short"}}
	require.ErrorContains(t, ensureCodexFingerprintDeploymentSalt(cfg), "at least 32 characters")
}

func TestLoadPersistsCodexFingerprintDeploymentSaltInDataDir(t *testing.T) {
	resetViperWithJWTSecret(t)
	dataDir := t.TempDir()
	t.Setenv("DATA_DIR", dataDir)

	cfg, err := Load()
	require.NoError(t, err)
	require.Len(t, cfg.Gateway.CodexFingerprintDeploymentSalt, 64)
	stored, err := os.ReadFile(filepath.Join(dataDir, codexFingerprintDeploymentSaltFile))
	require.NoError(t, err)
	require.Equal(t, cfg.Gateway.CodexFingerprintDeploymentSalt, strings.TrimSpace(string(stored)))
}
