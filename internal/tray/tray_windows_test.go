//go:build windows

package tray

import (
	"reflect"
	"testing"

	"github.com/masahide/OmniSSHAgent/internal/app"
)

func TestTrayIconsLoadAtSystemSizes(t *testing.T) {
	for _, name := range []string{"assets/tray.ico"} {
		data, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range []int32{16, 20, 24, 32, 40, 48} {
			icon, err := createIcon(data, size, size)
			if err != nil || icon == 0 {
				t.Fatalf("%s at %dpx: %v", name, size, err)
			}
			destroyIcon.Call(icon)
		}
	}
	for _, light := range []bool{false, true} {
		for _, size := range []int32{16, 20, 24, 32, 40, 48} {
			icon, err := createFluentIcon(size, size, light)
			if err != nil || icon == 0 {
				t.Fatalf("Segoe glyph at %dpx: %v", size, err)
			}
			destroyIcon.Call(icon)
		}
	}
}

func TestTrayIconSwitchesWithThemeWithoutReplacingClassicAsset(t *testing.T) {
	previous := taskbarUsesLightTheme
	defer func() { taskbarUsesLightTheme = previous }()
	light := true
	taskbarUsesLightTheme = func() bool { return light }
	tray := New("", "", nil)
	defer tray.close()
	for _, step := range []struct {
		fluent, light bool
		name          string
	}{
		{false, true, "assets/tray.ico"},
		{true, true, "font:E192:light"},
		{true, false, "font:E192:dark"},
		{false, false, "assets/tray.ico"},
	} {
		light = step.light
		tray.SetFluentIcon(step.fluent)
		if err := tray.refreshIcon(); err != nil {
			t.Fatal(err)
		}
		if tray.iconAsset != step.name {
			t.Fatalf("asset=%q want=%q", tray.iconAsset, step.name)
		}
		icon := tray.icon
		if err := tray.refreshIcon(); err != nil {
			t.Fatal(err)
		}
		if tray.icon != icon {
			t.Fatal("unchanged theme recreated icon")
		}
	}
}

func TestRequiredMenu(t *testing.T) {
	var labels []string
	for _, item := range requiredMenuEntries() {
		if item.flags != mfSeparator {
			labels = append(labels, item.text)
		}
	}
	want := []string{
		"Manage Keys",
		"Remove Keys",
		"Settings",
		"Quit",
	}
	if !reflect.DeepEqual(labels, want) {
		t.Fatalf("labels=%v", labels)
	}
}

func TestStateLabels(t *testing.T) {
	for state, want := range map[app.State]string{
		app.StateRunning:            "Running",
		app.StateDegraded:           "Degraded",
		app.StateConfigurationError: "Configuration error",
	} {
		if got := stateLabel(state); got != want {
			t.Fatalf("%s=%q", state, got)
		}
	}
}

func TestTrayLeftClickOpensKeys(t *testing.T) {
	tray := New(`C:\Config\config.toml`, `C:\Logs`, func() {})
	activeMu.Lock()
	previous := active
	active = tray
	activeMu.Unlock()
	previousOpen := openKeysDialog
	defer func() {
		openKeysDialog = previousOpen
		activeMu.Lock()
		active = previous
		activeMu.Unlock()
	}()
	opened := 0
	openKeysDialog = func(t *Tray) {
		if t == tray {
			opened++
		}
	}
	windowProc(0, wmTray, 0, wmLButtonUp)
	if opened != 1 {
		t.Fatal("left click did not open Manage Keys")
	}
	tray.shuttingDown = true
	windowProc(0, wmTray, 0, wmLButtonUp)
	if opened != 1 {
		t.Fatal("tray opened Manage Keys during shutdown")
	}
}

func TestCommandsAndShutdownRejection(t *testing.T) {
	oldOpenPath := openPath
	oldOpenConfiguration := openConfiguration
	oldCreateDefault := createDefaultConfig
	oldOpenSettings := openSettingsDialog
	oldOpenKeys := openKeysDialog
	defer func() {
		openPath = oldOpenPath
		openConfiguration = oldOpenConfiguration
		createDefaultConfig = oldCreateDefault
		openSettingsDialog = oldOpenSettings
		openKeysDialog = oldOpenKeys
	}()
	openSettingsDialog = func(*Tray) {}
	keysOpened := false
	openKeysDialog = func(*Tray) { keysOpened = true }
	var opened []string
	openPath = func(path string) error { opened = append(opened, path); return nil }
	openConfiguration = func(path string) error { opened = append(opened, path); return nil }
	createDefaultConfig = func(path string) (bool, error) {
		opened = append(opened, "create:"+path)
		return true, nil
	}
	quit := make(chan struct{}, 2)
	tray := New(`C:\Config\config.toml`, `C:\Logs`, func() { quit <- struct{}{} })
	tray.command(menuOpenConfig)
	tray.command(menuOpenConfigDir)
	tray.command(menuOpenLogDir)
	tray.command(menuSettings)
	tray.command(menuManageKeys)
	if !keysOpened {
		t.Fatal("key manager was not opened")
	}
	tray.command(menuQuit)
	<-quit
	wantOpened := []string{
		`create:C:\Config\config.toml`,
		`C:\Config\config.toml`,
		`C:\Config`,
		`C:\Logs`,
	}
	if !reflect.DeepEqual(opened, wantOpened) {
		t.Fatalf("opened=%v, want %v", opened, wantOpened)
	}
	tray.shuttingDown = true
	tray.command(menuQuit)
	select {
	case <-quit:
		t.Fatal("command accepted during shutdown")
	default:
	}
}
