//go:build windows

package tray

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"github.com/masahide/OmniSSHAgent/internal/config"
)

func TestResolveUITheme(t *testing.T) {
	for _, test := range []struct {
		name            string
		light, contrast bool
		window, face    uintptr
		want            uiTheme
	}{
		{"native light", true, false, 0xFFFFFF, 0xF0F0F0, uiTheme{}},
		{"system dark fallback", false, false, 0xFFFFFF, 0xF0F0F0, uiTheme{true, true}},
		{"patched dark", false, false, 0x191919, 0x202020, uiTheme{true, false}},
		{"patched dark with light preference", true, false, 0x191919, 0x202020, uiTheme{true, false}},
		{"high contrast", false, true, 0, 0, uiTheme{}},
	} {
		if got := resolveUITheme(test.light, test.contrast, test.window, test.face); got != test.want {
			t.Errorf("%s: got %+v want %+v", test.name, got, test.want)
		}
	}
}

func TestLiveUITheme(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	originalReader, originalTheme := readUITheme, activeTheme.Load()
	mode := uiTheme{}
	readUITheme = func() uiTheme { return mode }
	initial := mode
	activeTheme.Store(&initial)
	defer func() { readUITheme = originalReader; activeTheme.Store(originalTheme) }()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := config.Save(path, config.Default()); err != nil {
		t.Fatal(err)
	}
	b, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	tray := New(path, t.TempDir(), nil)
	tray.SetBackend(b)
	settings := &settingsDialog{tray: tray, m: newMetrics()}
	settingsDlg = settings
	defer func() { settings.close(); settingsDlg = nil }()
	if err := settings.create(0); err != nil {
		t.Fatal(err)
	}
	tray.openKeys(settings.hwnd)
	keys := keysDlg
	if keys == nil {
		t.Fatal("key manager did not open")
	}
	defer keys.close()
	password := &passwordDialog{}
	passwordDlg = password
	if err := password.create(keys.hwnd, "id_ed25519", "SHA256:AAJF1T/Dly+MNefGtcYuIERftzxkdjyECkOS8UsDg28"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if password.hwnd != 0 {
			destroyWindow.Call(password.hwnd)
		}
		passwordDlg = nil
	}()
	errorWindow := &errorDialog{}
	if err := errorWindow.create(keys.hwnd, "invalid-key is not a valid key."); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errorWindow.hwnd != 0 {
			destroyWindow.Call(errorWindow.hwnd)
		}
	}()
	setWindowText(password.edit, "preserved input")
	button, _, _ := user32.NewProc("GetDlgItem").Call(password.hwnd, idOK)
	pump := func() {
		var msg message
		for i := 0; i < 1000; i++ {
			if pending, _, _ := user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, wmApplyTheme, wmApplyTheme, 1); pending == 0 {
				return
			}
			dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
		}
		t.Fatal("theme notifications did not settle")
	}
	for _, next := range []uiTheme{{true, true}, {true, false}, {}} {
		mode = next
		sendMessage.Call(settings.hwnd, 0x001A, 0, 0)
		pump()
		if windowText(password.edit) != "preserved input" {
			t.Fatal("theme switch lost passphrase input")
		}
		if currentUITheme() != next {
			t.Fatal("open windows did not pick up the system theme")
		}
		background, _, _ := sendMessage.Call(keys.list, 0x1000, 0, 0) // LVM_GETBKCOLOR.
		if background != uiColor(5) {
			t.Fatalf("ListView retained its previous background: %x want %x", background, uiColor(5))
		}
		if !next.fallback {
			for _, index := range []uintptr{4, 5, 7, 8, 13, 14, 15, 16, 17, 18, 23, 24, 29} {
				native, _, _ := getSysColor.Call(index)
				if got := uiColor(index); got != native {
					t.Fatalf("native/patched color %d overridden: %x want %x", index, got, native)
				}
			}
		}
		if next.fallback {
			if target := os.Getenv("OMNI_THEME_PREVIEW"); target != "" {
				showWindow.Call(settings.hwnd, swShow)
				updateWindow.Call(settings.hwnd)
				saveSettingsPreview(t, settings.hwnd, target)
			}
			for _, window := range []uintptr{settings.hwnd, password.hwnd, errorWindow.hwnd} {
				if pixel := renderedControlPixel(t, window, 2, 2); pixel != uiColor(15) {
					t.Fatalf("dialog background=%x want=%x", pixel, uiColor(15))
				}
			}
			if pixel := renderedControlPixel(t, button, 3, 3); pixel != uiColor(22) {
				t.Fatalf("button retained its native light background: %x", pixel)
			}
			// Theme rendering must preserve native automatic checkbox interaction.
			checkbox, _, _ := user32.NewProc("GetDlgItem").Call(settings.hwnd, idLoggingEnabled)
			before, _, _ := sendMessage.Call(checkbox, bmGetCheck, 0, 0)
			sendMessage.Call(checkbox, 0x00F5, 0, 0) // BM_CLICK.
			after, _, _ := sendMessage.Call(checkbox, bmGetCheck, 0, 0)
			if before == after {
				t.Fatal("themed checkbox stopped responding to clicks")
			}
		}
	}
}

func renderedControlPixel(t *testing.T, window uintptr, x, y int32) uintptr {
	t.Helper()
	dc, _, _ := getDC.Call(window)
	if dc == 0 {
		t.Fatal("GetDC failed")
	}
	defer releaseDC.Call(window, dc)
	memory, _, _ := createCompatibleDC.Call(dc)
	if memory == 0 {
		t.Fatal("CreateCompatibleDC failed")
	}
	defer deleteDC.Call(memory)
	var bounds rect
	getClientRect.Call(window, uintptr(unsafe.Pointer(&bounds)))
	bitmap, _, _ := gdi32.NewProc("CreateCompatibleBitmap").Call(dc, uintptr(bounds.Right), uintptr(bounds.Bottom))
	if bitmap == 0 {
		t.Fatal("CreateCompatibleBitmap failed")
	}
	defer deleteObject.Call(bitmap)
	previous, _, _ := selectObject.Call(memory, bitmap)
	defer selectObject.Call(memory, previous)
	sendMessage.Call(window, 0x0318, memory, 0xC) // WM_PRINTCLIENT, erase and paint client.
	color, _, _ := gdi32.NewProc("GetPixel").Call(memory, uintptr(x), uintptr(y))
	return color
}
