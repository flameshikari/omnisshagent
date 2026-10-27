//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/masahide/OmniSSHAgent/internal/app"
	"github.com/masahide/OmniSSHAgent/internal/backend"
	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"github.com/masahide/OmniSSHAgent/internal/backend/openssh"
	"github.com/masahide/OmniSSHAgent/internal/cli"
	"github.com/masahide/OmniSSHAgent/internal/config"
	"github.com/masahide/OmniSSHAgent/internal/control"
	"github.com/masahide/OmniSSHAgent/internal/interfaces"
	"github.com/masahide/OmniSSHAgent/internal/interfaces/cygwin"
	"github.com/masahide/OmniSSHAgent/internal/interfaces/opensshpipe"
	"github.com/masahide/OmniSSHAgent/internal/interfaces/pageant"
	"github.com/masahide/OmniSSHAgent/internal/logging"
	"github.com/masahide/OmniSSHAgent/internal/singleton"
	"github.com/masahide/OmniSSHAgent/internal/tray"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	result := cli.Run(args, os.Stdout, os.Stderr)
	if !result.StartApplication {
		return result.Code
	}
	mutex, err := singleton.Acquire(`Local\OmniSSHAgent`)
	if errors.Is(err, singleton.ErrAlreadyRunning) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if tray.ActivateExisting(ctx) {
			return cli.ExitOK
		}
		return cli.ExitAlreadyRunning
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return cli.ExitWindows
	}
	defer mutex.Close()
	shutdownEvent, err := control.NewShutdownEvent(control.ShutdownEventName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return cli.ExitWindows
	}
	defer shutdownEvent.Close()

	configPath, err := config.DefaultConfigPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return cli.ExitInternal
	}
	logDir, err := config.DefaultLogDirectory()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return cli.ExitInternal
	}
	_, createErr := config.CreateDefault(configPath)
	initialConfig, initialErr := config.Load(configPath)
	var logLevel slog.LevelVar
	logger, logCloser := logging.NewWithLevel(logDir, &logLevel)
	defer func() { _ = logCloser.Close() }()
	_ = logCloser.SetEnabled(initialErr == nil && initialConfig.Logging.IsEnabled())
	previousOutput := log.Writer()
	log.SetOutput(logCloser.Diagnostics())
	defer log.SetOutput(previousOutput)
	logger.Info("application starting", "version", cli.Version, "config_path", configPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := shutdownEvent.Wait(ctx); err == nil {
			cancel()
		}
	}()
	t := tray.New(configPath, logDir, cancel)
	t.SetFluentIcon(initialConfig.Tray.FluentIcon)
	trayDone := make(chan error, 1)
	go func() { trayDone <- t.Run(ctx) }()

	if createErr != nil {
		logger.Error("create configuration failed", "error", createErr)
	}
	host := &runtimeHost{tray: t, logger: logger, level: &logLevel, logWriter: logCloser}
	watcher := &config.Watcher{Path: configPath}
	reload := func() {
		changed, err := watcher.Changed()
		if !changed {
			return
		}
		var cfg config.RuntimeConfig
		if err == nil {
			cfg, err = config.LoadRuntime(configPath)
		}
		if err != nil {
			logger.Error("configuration error; previous configuration retained", "error", err)
			t.SetState(app.StateConfigurationError)
			return
		}
		if err := host.apply(ctx, cfg); err != nil {
			logger.Error("apply configuration failed", "error", err)
			t.SetState(app.StateDegraded)
		}
	}
	reload()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	trayStopped := false
	exitCode := cli.ExitOK
running:
	for {
		select {
		case <-ticker.C:
			reload()
		case err := <-trayDone:
			trayStopped = true
			if err != nil {
				logger.Error("tray stopped unexpectedly", "error", err)
				exitCode = cli.ExitWindows
			}
			break running
		case <-ctx.Done():
			break running
		}
	}
	cancel()
	if err := host.stop(); err != nil {
		logger.Error("shutdown timeout", "error", err)
	}
	if !trayStopped {
		select {
		case <-trayDone:
		case <-time.After(10 * time.Second):
			logger.Error("tray shutdown timeout")
		}
	}
	logger.Info("application stopped", "executable", filepath.Base(os.Args[0]))
	return exitCode
}

func newBackend(runtimeConfig config.RuntimeConfig) (backend.Backend, error) {
	switch runtimeConfig.BackendType {
	case config.BackendWindowsOpenSSH:
		return openssh.New(runtimeConfig.BackendPipePath, runtimeConfig.ConnectTimeout), nil
	case config.BackendEmbedded:
		return embedded.NewWithConfirmation(tray.ConfirmSignature)
	default:
		return nil, fmt.Errorf("unsupported runtime backend type %q", runtimeConfig.BackendType)
	}
}

func newComponents(runtimeConfig config.RuntimeConfig, backendClient backend.Backend, logger *slog.Logger) []interfaces.Component {
	var components []interfaces.Component
	if runtimeConfig.BackendType == config.BackendEmbedded {
		components = append(components, opensshpipe.New(backendClient, logger))
	}
	if runtimeConfig.PageantEnabled {
		components = append(components, pageant.New(backendClient, logger))
	}
	if runtimeConfig.CygwinEnabled {
		components = append(components, cygwin.New(backendClient, runtimeConfig.CygwinPath, runtimeConfig.ConnectTimeout, logger))
	}
	return components
}
