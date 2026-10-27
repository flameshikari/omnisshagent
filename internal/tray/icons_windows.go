//go:build windows

package tray

import (
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var taskbarUsesLightTheme = systemUsesLightTheme

func trayIconMetrics() (int32, int32) {
	class, _ := windows.UTF16PtrFromString("Shell_TrayWnd")
	window, _, _ := user32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(class)), 0)
	if window != 0 {
		dpi, _, _ := user32.NewProc("GetDpiForWindow").Call(window)
		if dpi != 0 {
			metrics := user32.NewProc("GetSystemMetricsForDpi")
			width, _, _ := metrics.Call(smCXSmallIcon, dpi)
			height, _, _ := metrics.Call(smCYSmallIcon, dpi)
			if width > 0 && height > 0 {
				return int32(width), int32(height)
			}
		}
	}
	return int32Result(getSystemMetrics, smCXSmallIcon), int32Result(getSystemMetrics, smCYSmallIcon)
}

func systemUsesLightTheme() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return true
	}
	defer key.Close()
	light, _, err := key.GetIntegerValue("SystemUsesLightTheme")
	return err != nil || light != 0
}

func (t *Tray) SetFluentIcon(enabled bool) {
	t.mu.Lock()
	changed := t.fluentIcon != enabled
	t.fluentIcon = enabled
	window := t.window
	t.mu.Unlock()
	if changed && window != 0 {
		postMessage.Call(window, wmApply, 0, 0)
	}
}

// refreshIcon runs only on the tray's locked Windows thread. Replacements are
// installed before the previous HICON is destroyed, including on theme changes.
func (t *Tray) refreshIcon() error {
	t.mu.Lock()
	fluent := t.fluentIcon
	t.mu.Unlock()
	name := "assets/tray.ico"
	light := true
	if fluent {
		light = taskbarUsesLightTheme()
		name = "font:E192:dark"
		if light {
			name = "font:E192:light"
		}
	}
	width, height := trayIconMetrics()
	if t.icon != 0 && t.iconAsset == name && t.iconWidth == width && t.iconHeight == height {
		return nil
	}
	var icon uintptr
	var err error
	if fluent {
		icon, err = createFluentIcon(width, height, light)
	}
	if !fluent || err != nil {
		var data []byte
		data, err = assets.ReadFile("assets/tray.ico")
		if err == nil {
			icon, err = createIcon(data, width, height)
		}
	}
	if err != nil {
		return err
	}
	previous := t.icon
	t.nid.Icon = icon
	if t.added {
		if ok, _, err := shellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&t.nid))); ok == 0 {
			t.nid.Icon = previous
			destroyIcon.Call(icon)
			return winErr(err)
		}
	}
	t.icon, t.iconAsset, t.iconWidth, t.iconHeight = icon, name, width, height
	if previous != 0 {
		destroyIcon.Call(previous)
	}
	return nil
}
