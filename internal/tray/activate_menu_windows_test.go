//go:build windows

package tray

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"golang.org/x/sys/windows"
)

func TestActivateExistingAndMenu(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tTray := New("", t.TempDir(), nil)
	activeMu.Lock()
	previous := active
	active = tTray
	activeMu.Unlock()
	defer func() {
		if keysDlg != nil && keysDlg.tray == tTray {
			keysDlg.close()
		}
		tTray.close()
		class, _ := windows.UTF16PtrFromString(windowClass)
		instance, _, _ := getModuleHandle.Call(0)
		user32.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(class)), instance)
		var msg message
		user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0x12, 0x12, 1)
		activeMu.Lock()
		active = previous
		activeMu.Unlock()
	}()
	window, err := createPopup(windowClass, windowTitle, 240, 100, 0, callback)
	if err != nil {
		t.Fatal(err)
	}
	tTray.window = window
	activate := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return ActivateExisting(ctx)
	}
	if !activate() {
		t.Fatal("existing instance was not found")
	}
	pump := func() {
		var msg message
		for {
			if pending, _, _ := user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&msg)), window, wmUser, wmUser+20, 1); pending == 0 {
				break
			}
			dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
		}
	}
	pump()
	if !tTray.wantKeys || keysDlg != nil {
		t.Fatal("startup activation was not deferred until backend availability")
	}
	b, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	tTray.SetBackend(b)
	pump()
	if keysDlg == nil || keysDlg.tray != tTray || tTray.wantKeys {
		t.Fatal("activation did not open Manage Keys after backend startup")
	}
	first := keysDlg.hwnd
	if !activate() {
		t.Fatal("second activation failed")
	}
	pump()
	if keysDlg.hwnd != first {
		t.Fatal("second activation duplicated Manage Keys")
	}
	menu, _, err := createPopupMenu.Call()
	if menu == 0 {
		t.Fatal(err)
	}
	tTray.menu = menu
	for _, entry := range requiredMenuEntries() {
		if err := appendMenuItem(menu, entry.flags, entry.id, entry.text); err != nil {
			t.Fatal(err)
		}
	}
	if err := styleTrayMenu(menu); err != nil {
		t.Fatal(err)
	}
	showWindow.Call(window, swShow)
	setForegroundWindow.Call(window)
	type selection struct {
		item, client, outer, last rect
		pixels                    [4]uintptr
		found                     bool
	}
	result := make(chan selection, 1)
	go func() {
		class, _ := windows.UTF16PtrFromString("#32768")
		var popup uintptr
		limit := time.Now().Add(3 * time.Second)
		var captured selection
		var lastSelection time.Time
		for time.Now().Before(limit) {
			popup, _, _ = user32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(class)), 0)
			if popup != 0 {
				state, _, _ := user32.NewProc("GetMenuState").Call(menu, 0, 0x400)
				if state&0x80 != 0 {
					time.Sleep(60 * time.Millisecond)
					sendMessage.Call(popup, 0x000F, 0, 0)
					user32.NewProc("GetMenuItemRect").Call(window, menu, 0, uintptr(unsafe.Pointer(&captured.item)))
					getClientRect.Call(popup, uintptr(unsafe.Pointer(&captured.client)))
					getWindowRect.Call(popup, uintptr(unsafe.Pointer(&captured.outer)))
					user32.NewProc("GetMenuItemRect").Call(window, menu, 3, uintptr(unsafe.Pointer(&captured.last)))
					user32.NewProc("MapWindowPoints").Call(popup, 0, uintptr(unsafe.Pointer(&captured.client)), 2)
					dc, _, _ := getDC.Call(popup)
					y := (captured.item.Top+captured.item.Bottom)/2 - captured.client.Top
					for i, x := range []int32{captured.item.Left - captured.client.Left, captured.item.Left - captured.client.Left + 2, captured.item.Right - captured.client.Left - 3, captured.item.Right - captured.client.Left - 1} {
						captured.pixels[i], _, _ = gdi32.NewProc("GetPixel").Call(dc, uintptr(x), uintptr(y))
					}
					releaseDC.Call(popup, dc)
					if target := os.Getenv("OMNI_MENU_PREVIEW"); target != "" {
						saveSettingsPreview(t, popup, target)
					}
					captured.found = true
					break
				}
				if visible, _, _ := user32.NewProc("IsWindowVisible").Call(popup); visible != 0 && time.Since(lastSelection) >= 100*time.Millisecond {
					// The popup can exist before it accepts keyboard input. Retry
					// through the native menu loop, checking selection first.
					postMessage.Call(popup, 0x0100, 0x28, 1)
					lastSelection = time.Now()
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		postMessage.Call(window, 0x001F, 0, 0) // WM_CANCELMODE closes the native menu on its owning thread.
		result <- captured
	}()
	if os.Getenv("OMNI_MENU_DARK") == "1" {
		dark := uiTheme{true, true}
		previous := activeTheme.Swap(&dark)
		defer activeTheme.Store(previous)
	}
	trackTrayMenu(menu, 0, 100, 100, window)
	captured := <-result
	if _, open := menuTrackContexts.Load(windows.GetCurrentThreadId()); open {
		t.Fatal("popup creation hook context was not released")
	}
	menuFrames.Range(func(key, value any) bool { t.Error("closed popup retained its frame state"); return true })
	if !captured.found {
		t.Fatalf("native menu did not open or accept keyboard selection: %+v", captured)
	}
	if captured.item.Left-captured.outer.Left > 1 || captured.outer.Right-captured.item.Right > 1 || captured.item.Top-captured.outer.Top > 1 || captured.outer.Bottom-captured.last.Bottom > 1 {
		t.Fatalf("native menu leaves side gaps: item=%+v client=%+v outer=%+v", captured.item, captured.client, captured.outer)
	}
	for _, pixel := range captured.pixels {
		if pixel == 0xFFFFFFFF || pixel != captured.pixels[0] {
			t.Fatalf("selection does not fill the row edges: %x item=%+v client=%+v", captured.pixels, captured.item, captured.client)
		}
	}
}

func TestMenuSelectionColors(t *testing.T) {
	background, text := menuSelectionColors(true, 0x191919, 0xF0F0F0, 0x282828, 0)
	if text != 0xF0F0F0 || !darkColor(background) || background == 0x191919 {
		t.Fatalf("dark selection lost contrast: background=%x text=%x", background, text)
	}
	background, text = menuSelectionColors(false, 0xFFFFFF, 0, 0xD77800, 0xFFFFFF)
	if background != 0xD77800 || text != 0xFFFFFF {
		t.Fatal("light selection colors changed")
	}
}
