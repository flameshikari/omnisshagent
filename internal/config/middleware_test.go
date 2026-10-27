package config

import (
	"path/filepath"
	"testing"
)

func TestMiddlewareLegacyAndProfiles(t *testing.T) {
	cfg := Default()
	cfg.KeePassXC.Enabled = true
	cfg.KeePassXC.Executable = `C:\Legacy\KeePassXC.exe`
	cfg.KeePassXC.Database = `C:\Secrets\vault.kdbx`
	if !cfg.MiddlewareEnabled() || cfg.MiddlewareProgram() != MiddlewareKeePassXC {
		t.Fatal("legacy middleware was not detected")
	}
	legacy := cfg.MiddlewareProfiles()[MiddlewareKeePassXC]
	if legacy.Executable != cfg.KeePassXC.Executable || !legacy.StartOnRequest || !legacy.UnlockOnRequest {
		t.Fatalf("legacy profile=%+v", legacy)
	}
	profiles := cfg.MiddlewareProfiles()
	profiles[MiddlewareKeePassXC] = MiddlewareProgramConfig{Executable: `D:\Apps\KeePassXC.exe`, StartOnRequest: true, UnlockOnRequest: true}
	profiles["future-program"] = MiddlewareProgramConfig{Executable: `E:\Apps\Other.exe`, StartOnRequest: true}
	cfg.Middleware = &MiddlewareConfig{Enabled: true, Program: MiddlewareKeePassXC, Programs: profiles}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Middleware.Programs["future-program"].Executable != `E:\Apps\Other.exe` {
		t.Fatal("inactive program profile was lost")
	}
	runtime, err := Validate(loaded, path, `C:\logs`, `C:\Users\test`)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.KeePassXC.Executable != `D:\Apps\KeePassXC.exe` || !runtime.KeePassXC.Enabled || !runtime.KeePassXC.ShouldStart() || runtime.KeePassXC.Database != cfg.KeePassXC.Database {
		t.Fatalf("effective profile=%+v", runtime.KeePassXC)
	}
	copy := loaded.MiddlewareProfiles()
	copy[MiddlewareKeePassXC] = MiddlewareProgramConfig{}
	if loaded.EffectiveKeePassXC().Executable != `D:\Apps\KeePassXC.exe` {
		t.Fatal("profile snapshot changed the configuration")
	}
	loaded.Middleware.Enabled = false
	runtime, err = Validate(loaded, path, `C:\logs`, `C:\Users\test`)
	if err != nil || runtime.KeePassXC.Enabled || runtime.KeePassXC.ShouldStart() {
		t.Fatal("master switch did not disable middleware")
	}
}

func TestMiddlewareMigrationPreservesStartOnly(t *testing.T) {
	cfg := Default()
	start := true
	cfg.KeePassXC.Executable = `C:\Apps\KeePassXC.exe`
	cfg.KeePassXC.StartOnRequest = &start
	cfg.Middleware = &MiddlewareConfig{Enabled: cfg.MiddlewareEnabled(), Program: cfg.MiddlewareProgram(), Programs: cfg.MiddlewareProfiles()}
	effective := cfg.EffectiveKeePassXC()
	if !cfg.Middleware.Enabled || effective.Enabled || !effective.ShouldStart() {
		t.Fatal("migration changed start-only behavior")
	}
	cfg.Middleware.Program = "unsupported"
	if _, err := Validate(cfg, `C:\config.toml`, `C:\logs`, `C:\Users\test`); err == nil {
		t.Fatal("unsupported active middleware was accepted")
	}
	cfg.Middleware.Program = MiddlewareKeePassXC
	profile := cfg.Middleware.Programs[MiddlewareKeePassXC]
	profile.Executable = "relative.exe"
	cfg.Middleware.Programs[MiddlewareKeePassXC] = profile
	if _, err := Validate(cfg, `C:\config.toml`, `C:\logs`, `C:\Users\test`); err == nil {
		t.Fatal("relative middleware executable was accepted")
	}
}

func TestMiddlewareDatabaseMigrationAndCheckbox(t *testing.T) {
	cfg := Default()
	cfg.KeePassXC.Enabled = true
	cfg.KeePassXC.Database = `C:\Legacy\old.kdbx`
	cfg.Middleware = &MiddlewareConfig{Enabled: true, Program: MiddlewareKeePassXC, Programs: map[string]MiddlewareProgramConfig{MiddlewareKeePassXC: {Executable: `C:\Apps\KeePassXC.exe`, StartOnRequest: true, UnlockOnRequest: true}}}
	if cfg.EffectiveKeePassXC().Database != cfg.KeePassXC.Database {
		t.Fatal("profile without database lost its legacy setting")
	}
	profile := cfg.MiddlewareProfiles()[MiddlewareKeePassXC]
	database, enabled := `D:\Secrets\selected.kdbx`, true
	profile.Database, profile.UseDatabase = &database, &enabled
	cfg.Middleware.Programs[MiddlewareKeePassXC] = profile
	if cfg.EffectiveKeePassXC().Database != database {
		t.Fatal("explicit database was ignored")
	}
	snapshot := cfg.MiddlewareProfiles()
	*snapshot[MiddlewareKeePassXC].Database = "changed"
	*snapshot[MiddlewareKeePassXC].UseDatabase = false
	if cfg.EffectiveKeePassXC().Database != database {
		t.Fatal("snapshot modified the original preferences")
	}
	enabled = false
	if cfg.EffectiveKeePassXC().Database != "" {
		t.Fatal("unchecked Database did not use the previous database")
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	stored := loaded.Middleware.Programs[MiddlewareKeePassXC]
	if stored.Database == nil || *stored.Database != database || stored.UsesDatabase() {
		t.Fatal("unchecked Database lost its remembered path")
	}
	enabled = true
	database = ""
	if _, err := Validate(cfg, path, `C:\logs`, `C:\Users\test`); err == nil {
		t.Fatal("enabled Database without a path was accepted")
	}
	enabled = false
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err = Load(path)
	if err != nil || loaded.EffectiveKeePassXC().Database != "" {
		t.Fatal("cleared Database reverted to its legacy path")
	}
}

func TestMiddlewareValidatesInheritedDatabase(t *testing.T) {
	cfg := Default()
	cfg.KeePassXC.Database = "relative.kdbx"
	cfg.Middleware = &MiddlewareConfig{Enabled: true, Programs: map[string]MiddlewareProgramConfig{
		MiddlewareKeePassXC: {Executable: `C:\Apps\KeePassXC.exe`, StartOnRequest: true},
	}}
	if _, err := Validate(cfg, `C:\config.toml`, `C:\logs`, `C:\Users\test`); err == nil {
		t.Fatal("relative inherited database accepted for startup")
	}
	profile := cfg.Middleware.Programs[MiddlewareKeePassXC]
	profile.StartOnRequest = false
	cfg.Middleware.Programs[MiddlewareKeePassXC] = profile
	if _, err := Validate(cfg, `C:\config.toml`, `C:\logs`, `C:\Users\test`); err != nil {
		t.Fatalf("inactive inherited database blocked configuration: %v", err)
	}
}
