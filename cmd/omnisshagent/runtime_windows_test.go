//go:build windows

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"github.com/masahide/OmniSSHAgent/internal/config"
	"github.com/masahide/OmniSSHAgent/internal/logging"
	"github.com/masahide/OmniSSHAgent/internal/tray"
	"golang.org/x/crypto/ssh/agent"
)

func TestHotReloadPreservesEmbeddedKeysAndMovesSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	level := new(slog.LevelVar)
	logDir := filepath.Join(t.TempDir(), "logs")
	logger, logWriter := logging.NewWithLevel(logDir, level)
	defer logWriter.Close()
	b, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := config.RuntimeConfig{BackendType: config.BackendEmbedded, CygwinEnabled: true, CygwinPath: filepath.Join(dir, "first.sock"), ConnectTimeout: time.Second}
	h := &runtimeHost{tray: tray.New("", "", nil), logger: logger, level: level, logWriter: logWriter, backend: b, current: cfg}
	defer func() {
		if err := h.stop(); err != nil {
			t.Error(err)
		}
	}()
	if err := h.apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.CygwinPath); err != nil {
		t.Fatal(err)
	}
	oldApp := h.application
	cfg.FluentIcon = true
	if err := h.apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if h.application != oldApp {
		t.Fatal("tray icon change restarted adapters")
	}
	disabledStartup := false
	cfg.KeePassXC.StartOnRequest = &disabledStartup
	if err := h.apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if h.application != oldApp {
		t.Fatal("equivalent startup switch restarted adapters")
	}
	cfg.LogLevel = slog.LevelDebug
	if err := h.apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if h.application != oldApp || level.Level() != slog.LevelDebug {
		t.Fatal("log-level change restarted adapters or failed to apply")
	}
	if _, err := os.Stat(logDir); !os.IsNotExist(err) {
		t.Fatalf("disabled startup wrote logs: %v", err)
	}
	cfg.LoggingEnabled = true
	if err := h.apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if h.application != oldApp {
		t.Fatal("enabling logging restarted adapters")
	}
	logger.Info("logging enabled")
	cfg.LoggingEnabled = false
	if err := h.apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if h.application != oldApp {
		t.Fatal("disabling logging restarted adapters")
	}
	logger.Error("logging disabled")
	files, err := os.ReadDir(logDir)
	if err != nil || len(files) != 1 {
		t.Fatalf("log files=%d err=%v", len(files), err)
	}
	data, err := os.ReadFile(filepath.Join(logDir, files[0].Name()))
	if err != nil || !strings.Contains(string(data), "logging enabled") || strings.Contains(string(data), "logging disabled") {
		t.Fatalf("incorrect logging toggle output: %s err=%v", data, err)
	}
	oldPath := cfg.CygwinPath
	cfg.CygwinPath = filepath.Join(dir, "second.sock")
	if err := h.apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("previous socket remains: %v", err)
	}
	if _, err := os.Stat(cfg.CygwinPath); err != nil {
		t.Fatal(err)
	}
	if h.backend != b {
		t.Fatal("embedded backend was replaced")
	}
	keys, err := h.backend.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys lost during reload: count=%d err=%v", len(keys), err)
	}
}
