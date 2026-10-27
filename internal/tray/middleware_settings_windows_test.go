//go:build windows

package tray

import (
	"github.com/masahide/OmniSSHAgent/internal/config"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMiddlewareProfilesSwitchIndependently(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	originalOptions := middlewareOptions
	middlewareOptions = append(append([]middlewareOption(nil), middlewareOptions...), middlewareOption{"future-program", "Future Program", "future.exe"})
	defer func() { middlewareOptions = originalOptions }()
	cfg := config.Default()
	cfg.KeePassXC.Enabled = true
	cfg.KeePassXC.Executable = `C:\Apps\KeePassXC.exe`
	cfg.KeePassXC.Database = `C:\Secrets\keepass.kdbx`
	cfg.Middleware = &config.MiddlewareConfig{Enabled: true, Program: config.MiddlewareKeePassXC, Programs: cfg.MiddlewareProfiles()}
	futureDatabase := `D:\Secrets\future.kdbx`
	cfg.Middleware.Programs["future-program"] = config.MiddlewareProgramConfig{Database: &futureDatabase, Executable: `D:\Apps\future.exe`, StartOnRequest: true}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	d := &settingsDialog{tray: New(path, t.TempDir(), func() {}), m: newMetrics()}
	previous := settingsDlg
	settingsDlg = d
	defer func() { settingsDlg = previous }()
	if err := d.create(0); err != nil {
		t.Fatal(err)
	}
	defer d.close()
	setWindowText(d.middlewarePath, `C:\Updated\KeePassXC.exe`)
	setWindowText(d.middlewareDatabase, `C:\Updated\keepass.kdbx`)
	comboSelect(d.middlewareProgram, 1)
	sendMessage.Call(d.hwnd, wmCommand, idMiddlewareProgram|1<<16, d.middlewareProgram)
	if windowText(d.middlewarePath) != `D:\Apps\future.exe` || isChecked(d.middlewareUnlock) || !isChecked(d.middlewareStart) {
		t.Fatal("program switch did not load its own profile")
	}
	if windowText(d.middlewareDatabase) != futureDatabase || !isChecked(d.middlewareDatabaseEnabled) {
		t.Fatal("program switch did not load its database")
	}
	setWindowText(d.middlewarePath, `D:\Updated\future.exe`)
	setWindowText(d.middlewareDatabase, `D:\Updated\future.kdbx`)
	setChecked(d.middlewareDatabaseEnabled, false)
	setChecked(d.middlewareExecutableEnabled, false)
	setChecked(d.middlewareStart, false)
	comboSelect(d.middlewareProgram, 0)
	sendMessage.Call(d.hwnd, wmCommand, idMiddlewareProgram|1<<16, d.middlewareProgram)
	if windowText(d.middlewarePath) != `C:\Updated\KeePassXC.exe` || !isChecked(d.middlewareUnlock) || !isChecked(d.middlewareStart) || !isChecked(d.middlewareExecutableEnabled) {
		t.Fatal("switching back lost KeePassXC preferences")
	}
	if windowText(d.middlewareDatabase) != `C:\Updated\keepass.kdbx` || !isChecked(d.middlewareDatabaseEnabled) {
		t.Fatal("switching back lost Database preferences")
	}
	merged := mergeSettings(cfg, d.values())
	if err := config.Save(path, merged); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p := loaded.Middleware.Programs["future-program"]
	if p.Executable != `D:\Updated\future.exe` || p.StartOnRequest || p.UsesExecutable() || p.Database == nil || *p.Database != `D:\Updated\future.kdbx` || p.UsesDatabase() {
		t.Fatal("inactive preferences were not persisted separately")
	}
	if loaded.EffectiveKeePassXC().Database != `C:\Updated\keepass.kdbx` {
		t.Fatal("selected database profile was ignored")
	}
	setChecked(d.middlewareEnabled, false)
	merged = mergeSettings(loaded, d.values())
	if merged.EffectiveKeePassXC().Enabled || merged.EffectiveKeePassXC().ShouldStart() || !merged.Middleware.Programs[config.MiddlewareKeePassXC].StartOnRequest {
		t.Fatal("master switch did not preserve startup preferences")
	}
	setChecked(d.middlewareEnabled, true)
	setChecked(d.middlewareStart, false)
	merged = mergeSettings(loaded, d.values())
	if p := merged.EffectiveKeePassXC(); p.ShouldStart() || p.Executable != "" || p.Database != "" {
		t.Fatal("disabled startup used remembered path preferences")
	}
	setChecked(d.middlewareStart, true)
	setChecked(d.middlewareExecutableEnabled, false)
	merged = mergeSettings(loaded, d.values())
	if p := merged.EffectiveKeePassXC(); p.ShouldStart() || p.Executable != "" || p.Database != "" {
		t.Fatal("unchecked Executable did not use only the running process")
	}
}
