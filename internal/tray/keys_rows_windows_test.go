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

func TestFirstKeyRowSelectionStrip(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"First", "Second"} {
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
	var row, headerBounds, client rect
	sendMessage.Call(d.list, 0x100E, 0, uintptr(unsafe.Pointer(&row)))
	header, _, _ := sendMessage.Call(d.list, 0x101F, 0, 0)
	getClientRect.Call(header, uintptr(unsafe.Pointer(&headerBounds)))
	user32.NewProc("MapWindowPoints").Call(header, d.list, uintptr(unsafe.Pointer(&headerBounds)), 2)
	getClientRect.Call(d.list, uintptr(unsafe.Pointer(&client)))
	if row.Top <= headerBounds.Bottom {
		t.Skip("native ListView has no leading row margin")
	}
	setSelected := func(index uintptr, selected bool) {
		state := keyItem{StateMask: 3}
		if selected {
			state.State = 3
		}
		sendMessage.Call(d.list, 0x102B, index, uintptr(unsafe.Pointer(&state)))
	}
	pixel := func(y int32) uintptr {
		dc, _, _ := getDC.Call(d.list)
		defer releaseDC.Call(d.list, dc)
		color, _, _ := gdi32.NewProc("GetPixel").Call(dc, uintptr(client.Right-10), uintptr(y))
		return color
	}
	setSelected(0, true)
	user32.NewProc("RedrawWindow").Call(d.list, 0, 0, 0x185)
	if got := pixel(row.Top - 1); got != uiColor(13) {
		t.Fatalf("first-row margin is not selected: %x", got)
	}
	setSelected(0, false)
	setSelected(1, true)
	user32.NewProc("UpdateWindow").Call(d.list)
	if got := pixel(row.Top - 1); got != uiColor(5) {
		t.Fatalf("selection strip remained above the first key after moving selection: got=%x want=%x", got, uiColor(5))
	}
	setSelected(0, true)
	user32.NewProc("UpdateWindow").Call(d.list)
	if got := pixel(row.Top - 1); got != uiColor(13) {
		t.Fatalf("reselecting first key did not update its margin: %x", got)
	}
}
