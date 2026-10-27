//go:build windows

package tray

import (
	"crypto/ed25519"
	"crypto/rand"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

func TestTrayKeyCountTooltip(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	tray := New("", "", nil)
	tray.SetBackend(b)
	activeMu.Lock()
	previous := active
	active = tray
	activeMu.Unlock()
	defer func() {
		tray.close()
		var msg message
		user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0x12, 0x12, 1) // Drain WM_QUIT from the test tray.
		activeMu.Lock()
		active = previous
		activeMu.Unlock()
	}()
	if err := tray.initialize(); err != nil {
		t.Fatal(err)
	}
	wait := func(expected string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			var msg message
			for {
				pending, _, _ := user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&msg)), tray.window, wmKeyCount, wmKeyCount, 1)
				if pending == 0 {
					break
				}
				dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
			}
			if windows.UTF16ToString(tray.nid.Tip[:]) == expected {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("tooltip=%q, want %q", windows.UTF16ToString(tray.nid.Tip[:]), expected)
	}
	wait("OmniSSHAgent – 0 keys loaded")
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	wait("OmniSSHAgent – 1 keys loaded")
	if err := b.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	wait("OmniSSHAgent – 0 keys loaded")
	oldToken := tray.countToken
	replacement, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	tray.SetBackend(replacement)
	tray.applyState()
	windowProc(tray.window, wmKeyCount, oldToken, 99)
	wait("OmniSSHAgent – 0 keys loaded")
	if err := replacement.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	wait("OmniSSHAgent – 1 keys loaded")
}
