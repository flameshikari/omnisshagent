//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/masahide/OmniSSHAgent/internal/app"
	"github.com/masahide/OmniSSHAgent/internal/backend"
	"github.com/masahide/OmniSSHAgent/internal/config"
	"github.com/masahide/OmniSSHAgent/internal/keepassxc"
	"github.com/masahide/OmniSSHAgent/internal/logging"
	"github.com/masahide/OmniSSHAgent/internal/tray"
)

type runtimeHost struct {
	tray        *tray.Tray
	logger      *slog.Logger
	level       *slog.LevelVar
	logWriter   *logging.DailyWriter
	current     config.RuntimeConfig
	backend     backend.Backend
	application *app.Application
	cancel      context.CancelFunc
}

func (h *runtimeHost) stop() error {
	if h.cancel != nil {
		h.cancel()
	}
	if h.application == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.application.Shutdown(ctx); err != nil {
		return err
	}
	h.application = nil
	return nil
}

func (h *runtimeHost) apply(ctx context.Context, cfg config.RuntimeConfig) error {
	h.tray.SetFluentIcon(cfg.FluentIcon)
	if h.logWriter != nil {
		if err := h.logWriter.SetEnabled(cfg.LoggingEnabled); err != nil {
			return fmt.Errorf("update logging: %w", err)
		}
	}
	previous := h.current
	previous.LogLevel = cfg.LogLevel
	previous.LoggingEnabled = cfg.LoggingEnabled
	previous.ShowSignNotifications = cfg.ShowSignNotifications
	previous.FluentIcon = cfg.FluentIcon
	if previous.KeePassXC.ShouldStart() == cfg.KeePassXC.ShouldStart() {
		previous.KeePassXC.StartOnRequest = cfg.KeePassXC.StartOnRequest
	}
	if h.application != nil && cfg == previous {
		h.level.Set(cfg.LogLevel)
		h.current = cfg
		h.tray.SetState(h.application.State())
		return nil
	}
	b := h.backend
	// Keep embedded keys in memory while restarting only the adapters. External
	// backend clients are cheap and must pick up a changed pipe or timeout.
	if b == nil || cfg.BackendType != config.BackendEmbedded || h.current.BackendType != config.BackendEmbedded {
		var err error
		b, err = newBackend(cfg)
		if err != nil {
			return err
		}
	}
	if err := h.stop(); err != nil {
		return fmt.Errorf("stop previous interfaces: %w", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	h.cancel = cancel
	if contextual, ok := b.(interface{ SetContext(context.Context) }); ok {
		contextual.SetContext(runCtx)
	}
	h.level.Set(cfg.LogLevel)
	h.tray.SetBackend(b)
	h.backend, h.current = b, cfg
	wrapped := b
	if cfg.KeePassXC.Enabled || cfg.KeePassXC.ShouldStart() {
		start := cfg.KeePassXC.ShouldStart()
		unlocker := &keepassxc.Unlocker{Executable: cfg.KeePassXC.Executable, Database: cfg.KeePassXC.Database, KeyLoadDelay: cfg.KeyLoadDelay, AllowStart: &start, StartOnly: !cfg.KeePassXC.Enabled}
		wrapped = keepassxc.Wrap(runCtx, b, unlocker.Unlock, h.logger)
	}
	h.application = app.New(newComponents(cfg, wrapped, h.logger), h.tray, h.logger)
	h.application.Run(runCtx)
	h.logger.Info("configuration applied")
	return nil
}
