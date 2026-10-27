package config

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const (
	ApplicationName       = "OmniSSHAgent"
	SchemaVersion         = 1
	BackendWindowsOpenSSH = "windows-openssh"
	BackendEmbedded       = "embedded"
	MiddlewareKeePassXC   = "keepassxc"
	DefaultBackendPipe    = "openssh-ssh-agent"
	DefaultConnectTimeout = 5 * time.Second
)

type Config struct {
	Version    int               `toml:"version"`
	Backend    BackendConfig     `toml:"backend"`
	Interfaces InterfaceConfig   `toml:"interfaces"`
	Tray       TrayConfig        `toml:"tray"`
	Logging    LoggingConfig     `toml:"logging"`
	KeePassXC  KeePassXCConfig   `toml:"keepassxc"`
	Middleware *MiddlewareConfig `toml:"middleware,omitempty"`
}

type KeePassXCConfig struct {
	Enabled        bool   `toml:"enabled"`
	Executable     string `toml:"executable"`
	StartOnRequest *bool  `toml:"start_on_request,omitempty"`
	Database       string `toml:"database"`
	KeyLoadDelay   string `toml:"key_load_delay"`
}

func (c KeePassXCConfig) ShouldStart() bool {
	if c.StartOnRequest != nil {
		return *c.StartOnRequest
	}
	return c.Enabled && c.Executable != "" // Preserve configurations written before the startup switch existed.
}

type BackendConfig struct {
	Type           string `toml:"type"`
	Pipe           string `toml:"pipe"`
	ConnectTimeout string `toml:"connect_timeout"`
}

type InterfaceConfig struct {
	Pageant PageantConfig `toml:"pageant"`
	Cygwin  CygwinConfig  `toml:"cygwin"`
}

type PageantConfig struct {
	Enabled bool `toml:"enabled"`
}

type CygwinConfig struct {
	Enabled    bool   `toml:"enabled"`
	SocketPath string `toml:"socket_path"`
}

type TrayConfig struct {
	ShowSignNotifications bool `toml:"show_sign_notifications"`
	FluentIcon            bool `toml:"fluent_icon"`
}

type LoggingConfig struct {
	Enabled *bool  `toml:"enabled,omitempty"`
	Level   string `toml:"level"`
}

func (c LoggingConfig) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

type RuntimeConfig struct {
	ConfigPath            string
	LogDirectory          string
	BackendType           string
	BackendPipePath       string
	ConnectTimeout        time.Duration
	CygwinPath            string
	PageantEnabled        bool
	CygwinEnabled         bool
	ShowSignNotifications bool
	FluentIcon            bool
	LogLevel              slog.Level
	LoggingEnabled        bool
	KeePassXC             KeePassXCConfig
	KeyLoadDelay          time.Duration
}

func Default() Config {
	loggingEnabled := true
	return Config{
		Version: SchemaVersion,
		Backend: BackendConfig{
			Type:           BackendWindowsOpenSSH,
			Pipe:           DefaultBackendPipe,
			ConnectTimeout: DefaultConnectTimeout.String(),
		},
		Interfaces: InterfaceConfig{
			Pageant: PageantConfig{Enabled: true},
			Cygwin:  CygwinConfig{Enabled: true},
		},
		Tray:      TrayConfig{ShowSignNotifications: false},
		Logging:   LoggingConfig{Enabled: &loggingEnabled, Level: "info"},
		KeePassXC: KeePassXCConfig{KeyLoadDelay: "2s"},
	}
}

func Decode(r io.Reader) (Config, error) {
	var cfg Config
	decoder := toml.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	return cfg, nil
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer f.Close()
	return Decode(f)
}

func Validate(cfg Config, configPath, logDirectory, userProfile string) (RuntimeConfig, error) {
	if cfg.Version != SchemaVersion {
		return RuntimeConfig{}, fmt.Errorf("unsupported version %d", cfg.Version)
	}
	var pipe string
	timeout := DefaultConnectTimeout
	switch cfg.Backend.Type {
	case BackendWindowsOpenSSH:
		pipe = strings.TrimSpace(cfg.Backend.Pipe)
		if pipe == "" {
			return RuntimeConfig{}, fmt.Errorf("backend.pipe must not be empty")
		}
		if !strings.HasPrefix(strings.ToLower(pipe), `\\.\pipe\`) {
			if strings.ContainsAny(pipe, `\/`) {
				return RuntimeConfig{}, fmt.Errorf("backend.pipe must be a pipe name or \\\\.\\pipe\\ path")
			}
			pipe = `\\.\pipe\` + pipe
		}
		parsed, err := time.ParseDuration(cfg.Backend.ConnectTimeout)
		if err != nil || parsed <= 0 {
			return RuntimeConfig{}, fmt.Errorf("backend.connect_timeout must be a positive duration")
		}
		timeout = parsed
	case BackendEmbedded:
		// The embedded backend always exposes the standard OpenSSH pipe and
		// does not make outbound backend connections. These legacy fields are
		// intentionally ignored so users can switch modes without erasing them.
	case "":
		fallthrough
	default:
		return RuntimeConfig{}, fmt.Errorf("unsupported backend.type %q", cfg.Backend.Type)
	}
	cygwinPath := cfg.Interfaces.Cygwin.SocketPath
	if cygwinPath == "" {
		if userProfile == "" {
			return RuntimeConfig{}, fmt.Errorf("USERPROFILE is unavailable")
		}
		cygwinPath = filepath.Join(userProfile, ".ssh", "omnisshagent-cygwin.sock")
	} else if !filepath.IsAbs(cygwinPath) {
		return RuntimeConfig{}, fmt.Errorf("interfaces.cygwin.socket_path must be absolute")
	}
	var level slog.Level
	switch strings.ToLower(cfg.Logging.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return RuntimeConfig{}, fmt.Errorf("logging.level must be debug, info, warn, or error")
	}
	if cfg.MiddlewareProgram() != MiddlewareKeePassXC {
		return RuntimeConfig{}, fmt.Errorf("middleware.program must be keepassxc")
	}
	keepass := cfg.EffectiveKeePassXC()
	delay := 2 * time.Second
	if keepass.KeyLoadDelay != "" {
		var err error
		delay, err = time.ParseDuration(keepass.KeyLoadDelay)
		if err != nil || delay < 0 {
			return RuntimeConfig{}, fmt.Errorf("keepassxc.key_load_delay must be a non-negative duration")
		}
	}
	executableField := "keepassxc.executable"
	if cfg.Middleware != nil {
		if _, exists := cfg.Middleware.Programs[MiddlewareKeePassXC]; exists {
			executableField = "middleware.programs.keepassxc.executable"
		}
	}
	if keepass.Executable != "" && !filepath.IsAbs(keepass.Executable) {
		return RuntimeConfig{}, fmt.Errorf("%s must be an absolute path", executableField)
	}
	if keepass.ShouldStart() && keepass.Executable == "" {
		return RuntimeConfig{}, fmt.Errorf("%s is required when start_on_request is enabled", executableField)
	}
	if cfg.Middleware != nil {
		profile := cfg.middlewareProfile(MiddlewareKeePassXC)
		if keepass.ShouldStart() && profile.UsesDatabase() && (profile.Database == nil || *profile.Database == "") {
			return RuntimeConfig{}, fmt.Errorf("middleware.programs.keepassxc.database is required when use_database is enabled")
		}
		if keepass.Database != "" && !filepath.IsAbs(keepass.Database) {
			return RuntimeConfig{}, fmt.Errorf("middleware.programs.keepassxc.database must be an absolute path")
		}
	}
	return RuntimeConfig{
		ConfigPath:            configPath,
		LogDirectory:          logDirectory,
		BackendType:           cfg.Backend.Type,
		BackendPipePath:       pipe,
		ConnectTimeout:        timeout,
		CygwinPath:            filepath.Clean(cygwinPath),
		PageantEnabled:        cfg.Interfaces.Pageant.Enabled,
		CygwinEnabled:         cfg.Interfaces.Cygwin.Enabled,
		ShowSignNotifications: cfg.Tray.ShowSignNotifications,
		FluentIcon:            cfg.Tray.FluentIcon,
		LogLevel:              level,
		LoggingEnabled:        cfg.Logging.IsEnabled(),
		KeePassXC:             keepass,
		KeyLoadDelay:          delay,
	}, nil
}
