//go:build windows

package tray

import (
	"crypto/ed25519"
	"crypto/rand"
	"runtime"
	"testing"
	"unsafe"

	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"golang.org/x/crypto/ssh/agent"
)

func TestManageKeysMultiselection(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	add := func(name string) {
		t.Helper()
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Add(agent.AddedKey{PrivateKey: private, Comment: name}); err != nil {
			t.Fatal(err)
		}
	}
	tray := New("", t.TempDir(), func() {})
	tray.SetBackend(b)
	tray.openKeys(0)
	d := keysDlg
	if d == nil {
		t.Fatal("Manage Keys did not open")
	}
	defer d.close()
	checkButtons := func(remove, all bool) {
		t.Helper()
		for _, button := range []struct {
			id   uintptr
			want bool
		}{{idRemoveKey, remove}, {idRemoveAllKeys, all}} {
			window, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, button.id)
			enabled, _, _ := isWindowEnabled.Call(window)
			if (enabled != 0) != button.want {
				t.Fatalf("button %d enabled=%v want=%v", button.id, enabled != 0, button.want)
			}
		}
	}
	checkButtons(false, false)
	for _, name := range []string{"Omega", "Gamma", "Beta", "Alpha"} {
		add(name)
	}
	if err := d.refresh(); err != nil {
		t.Fatal(err)
	}
	checkButtons(false, true)
	selectAll := func() {
		t.Helper()
		var original [256]byte
		getKeyboard := user32.NewProc("GetKeyboardState")
		setKeyboard := user32.NewProc("SetKeyboardState")
		if ok, _, err := getKeyboard.Call(uintptr(unsafe.Pointer(&original))); ok == 0 {
			t.Fatal(err)
		}
		defer setKeyboard.Call(uintptr(unsafe.Pointer(&original)))
		keyboard := original
		keyboard[0x11], keyboard[0x12] = 0x80, 0
		if ok, _, err := setKeyboard.Call(uintptr(unsafe.Pointer(&keyboard))); ok == 0 {
			t.Fatal(err)
		}
		button, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, idAddKey)
		if !translateKeysMessage(&message{Window: button, Message: 0x0100, WParam: 0x41}) {
			t.Fatal("Ctrl+A was not handled in Manage Keys")
		}
	}
	click := func(row int, modifier int) {
		t.Helper()
		var keyboard [256]byte
		getKeyboard := user32.NewProc("GetKeyboardState")
		setKeyboard := user32.NewProc("SetKeyboardState")
		if ok, _, err := getKeyboard.Call(uintptr(unsafe.Pointer(&keyboard))); ok == 0 {
			t.Fatal(err)
		}
		defer setKeyboard.Call(uintptr(unsafe.Pointer(&keyboard)))
		modified := keyboard
		modified[0x10], modified[0x11] = 0, 0 // Shift and Ctrl: thread-local test input only.
		flags := uintptr(1)
		if modifier != 0 {
			modified[modifier] = 0x80
			if modifier == 0x11 {
				flags |= 8
			} else {
				flags |= 4
			}
		}
		if ok, _, err := setKeyboard.Call(uintptr(unsafe.Pointer(&modified))); ok == 0 {
			t.Fatal(err)
		}
		var bounds rect
		sendMessage.Call(d.list, 0x100E, uintptr(row), uintptr(unsafe.Pointer(&bounds)))
		position := uintptr(uint32(uint16(bounds.Left+20)) | uint32(uint16((bounds.Top+bounds.Bottom)/2))<<16)
		// ListView may enter its own mouse-tracking loop on button down.
		// Queue release first so that loop can receive it on the same thread.
		postMessage.Call(d.list, 0x0202, flags&^1, position)
		sendMessage.Call(d.list, 0x0201, flags, position)
		var release message
		if queued, _, _ := user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&release)), d.list, 0x0202, 0x0202, 1); queued != 0 {
			dispatchMessage.Call(uintptr(unsafe.Pointer(&release)))
		}
	}
	checkSelection := func(names ...string) {
		t.Helper()
		selected := d.selectedKeys()
		checkButtons(len(names) != 0, len(d.keys) != 0)
		if len(selected) != len(names) {
			t.Fatalf("selected %d keys, want %v", len(selected), names)
		}
		for _, name := range names {
			found := false
			for _, key := range selected {
				found = found || key.Comment == name
			}
			if !found {
				t.Fatalf("selection lost %s", name)
			}
		}
	}
	selectAll()
	checkSelection("Alpha", "Beta", "Gamma", "Omega")
	state := keyItem{StateMask: 2}
	sendMessage.Call(d.list, 0x102B, ^uintptr(0), uintptr(unsafe.Pointer(&state)))
	checkSelection()
	click(0, 0)
	click(2, 0x11)
	checkSelection("Alpha", "Gamma")
	header, _, _ := sendMessage.Call(d.list, 0x101F, 0, 0)
	var column rect
	sendMessage.Call(header, 0x1207, 1, uintptr(unsafe.Pointer(&column)))
	position := uintptr(uint32((column.Left+column.Right)/2) | uint32((column.Top+column.Bottom)/2)<<16)
	sendMessage.Call(header, 0x0201, 1, position)
	sendMessage.Call(header, 0x0202, 0, position)
	checkSelection("Alpha", "Gamma")
	add("Delta")
	if err := d.refresh(); err != nil {
		t.Fatal(err)
	}
	checkSelection("Alpha", "Gamma")
	var deletion message
	peekDeletion := func() bool {
		pending, _, _ := user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&deletion)), d.hwnd, wmDeleteKeys, wmDeleteKeys, 1)
		return pending != 0
	}
	sendMessage.Call(d.list, 0x0100, 0x2E, 1|(1<<30)) // Held Delete must not repeat removal.
	if peekDeletion() {
		t.Fatal("held Delete queued another removal")
	}
	sendMessage.Call(d.list, 0x0100, 0x2E, 1)
	if !peekDeletion() {
		t.Fatal("Delete did not queue selected-key removal")
	}
	dispatchMessage.Call(uintptr(unsafe.Pointer(&deletion)))
	remaining, err := b.List()
	if err != nil || len(remaining) != 3 {
		t.Fatalf("multi-remove: keys=%d err=%v", len(remaining), err)
	}
	for _, key := range remaining {
		if key.Comment == "Alpha" || key.Comment == "Gamma" {
			t.Fatalf("selected key remains: %s", key.Comment)
		}
	}
	click(0, 0)
	click(2, 0x10)
	checkSelection("Beta", "Delta", "Omega")
	click(0, 0)
	sendMessage.Call(d.hwnd, wmCommand, idRemoveAllKeys, 0)
	remaining, err = b.List()
	if err != nil || len(remaining) != 0 || len(d.keys) != 0 {
		t.Fatalf("Remove All: backend=%d table=%d err=%v", len(remaining), len(d.keys), err)
	}
	checkButtons(false, false)
	selectAll()
	checkSelection()
	add("Tray key")
	if err := d.refresh(); err != nil {
		t.Fatal(err)
	}
	checkButtons(false, true)
	tray.command(menuRemoveAllKeys)
	remaining, err = b.List()
	if err != nil || len(remaining) != 0 || len(d.keys) != 0 {
		t.Fatalf("tray Remove All Keys: backend=%d table=%d err=%v", len(remaining), len(d.keys), err)
	}
	checkButtons(false, false)
}
