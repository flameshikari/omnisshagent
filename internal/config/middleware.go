package config

import "strings"

type MiddlewareConfig struct {
	Enabled  bool                               `toml:"enabled"`
	Program  string                             `toml:"program"`
	Programs map[string]MiddlewareProgramConfig `toml:"programs"`
}

type MiddlewareProgramConfig struct {
	Database        *string `toml:"database,omitempty"`
	UseExecutable   *bool   `toml:"use_executable,omitempty"`
	UseDatabase     *bool   `toml:"use_database,omitempty"`
	Executable      string  `toml:"executable"`
	UnlockOnRequest bool    `toml:"unlock_on_request"`
	StartOnRequest  bool    `toml:"start_on_request"`
}

func (p MiddlewareProgramConfig) UsesExecutable() bool {
	if p.UseExecutable != nil {
		return *p.UseExecutable
	}
	return p.Executable != ""
}

func (p MiddlewareProgramConfig) UsesDatabase() bool {
	if p.UseDatabase != nil {
		return *p.UseDatabase
	}
	return p.Database != nil && *p.Database != ""
}

func (c Config) MiddlewareProgram() string {
	if c.Middleware != nil && strings.TrimSpace(c.Middleware.Program) != "" {
		return strings.TrimSpace(c.Middleware.Program)
	}
	return MiddlewareKeePassXC
}

func (c Config) MiddlewareEnabled() bool {
	if c.Middleware != nil {
		return c.Middleware.Enabled
	}
	return c.KeePassXC.Enabled || c.KeePassXC.ShouldStart()
}

// middlewareProfile resolves legacy defaults without copying unrelated profiles.
// Callers must treat pointer fields as read-only; MiddlewareProfiles clones them.
func (c Config) middlewareProfile(program string) MiddlewareProgramConfig {
	profile, exists := MiddlewareProgramConfig{}, false
	if c.Middleware != nil {
		profile, exists = c.Middleware.Programs[program]
	}
	if program == MiddlewareKeePassXC {
		if !exists {
			profile = MiddlewareProgramConfig{
				Executable:      c.KeePassXC.Executable,
				UnlockOnRequest: c.KeePassXC.Enabled,
				StartOnRequest:  c.KeePassXC.ShouldStart(),
			}
		}
		if profile.Database == nil {
			database := c.KeePassXC.Database
			profile.Database = &database
		}
	}
	return profile
}

// MiddlewareProfiles returns an independent snapshot, including legacy defaults.
// Inactive profiles survive UI saves.
func (c Config) MiddlewareProfiles() map[string]MiddlewareProgramConfig {
	profiles := make(map[string]MiddlewareProgramConfig)
	if c.Middleware != nil {
		for name := range c.Middleware.Programs {
			profiles[name] = c.middlewareProfile(name).clone()
		}
	}
	if _, exists := profiles[MiddlewareKeePassXC]; !exists {
		profiles[MiddlewareKeePassXC] = c.middlewareProfile(MiddlewareKeePassXC).clone()
	}
	return profiles
}

func (p MiddlewareProgramConfig) clone() MiddlewareProgramConfig {
	if p.Database != nil {
		database := *p.Database
		p.Database = &database
	}
	if p.UseExecutable != nil {
		enabled := *p.UseExecutable
		p.UseExecutable = &enabled
	}
	if p.UseDatabase != nil {
		enabled := *p.UseDatabase
		p.UseDatabase = &enabled
	}
	return p
}

func (c Config) EffectiveKeePassXC() KeePassXCConfig {
	if c.Middleware == nil {
		return c.KeePassXC
	}
	result := c.KeePassXC
	profile := c.middlewareProfile(MiddlewareKeePassXC)
	active := c.MiddlewareEnabled() && c.MiddlewareProgram() == MiddlewareKeePassXC
	result.Enabled = active && profile.UnlockOnRequest
	start := active && profile.StartOnRequest && profile.UsesExecutable()
	result.StartOnRequest = &start
	result.Executable, result.Database = "", ""
	if start {
		result.Executable = profile.Executable
		if profile.UsesDatabase() && profile.Database != nil {
			result.Database = *profile.Database
		}
	}
	return result
}
