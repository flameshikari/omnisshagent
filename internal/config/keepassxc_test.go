package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestKeePassXCConfiguration(t *testing.T) {
	cfg := Default()
	rt, err := Validate(cfg, "", "", "user")
	if err != nil || rt.KeePassXC.Enabled || rt.KeyLoadDelay != 2*time.Second {
		t.Fatalf("default=%+v err=%v", rt, err)
	}
	cfg.KeePassXC.Enabled = true
	if _, err := Validate(cfg, "", "", "user"); err != nil {
		t.Fatalf("running-process discovery should not require an executable: %v", err)
	}
	cfg.KeePassXC.Executable = "KeePassXC.exe"
	if _, err := Validate(cfg, "", "", "user"); err == nil {
		t.Fatal("accepted relative executable path")
	}
	cfg.KeePassXC.Executable = filepath.Join(t.TempDir(), "KeePassXC.exe")
	cfg.KeePassXC.KeyLoadDelay = "0s"
	if _, err := Validate(cfg, "", "", "user"); err != nil {
		t.Fatal(err)
	}
	for _, delay := range []string{"-1s", "garbage"} {
		cfg.KeePassXC.KeyLoadDelay = delay
		if _, err := Validate(cfg, "", "", "user"); err == nil {
			t.Fatalf("accepted delay %q", delay)
		}
	}
}

func TestKeePassXCStartupSwitch(t *testing.T) {
	cfg := Default()
	cfg.KeePassXC.Enabled = true
	cfg.KeePassXC.Executable = filepath.Join(t.TempDir(), "KeePassXC.exe")
	if !cfg.KeePassXC.ShouldStart() {
		t.Fatal("legacy executable configuration lost startup behavior")
	}
	disabled := false
	cfg.KeePassXC.StartOnRequest = &disabled
	if cfg.KeePassXC.ShouldStart() {
		t.Fatal("startup switch did not override a saved executable")
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.KeePassXC.StartOnRequest == nil || loaded.KeePassXC.ShouldStart() {
		t.Fatalf("disabled startup did not survive save/load: %v", err)
	}
	enabled := true
	cfg.KeePassXC.StartOnRequest = &enabled
	cfg.KeePassXC.Enabled = false
	if !cfg.KeePassXC.ShouldStart() {
		t.Fatal("startup must also work independently of unlock")
	}
	cfg.KeePassXC.Executable = ""
	if _, err := Validate(cfg, "", "", "user"); err == nil {
		t.Fatal("startup accepted a missing executable")
	}
}
