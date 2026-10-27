//go:build windows

package tray

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

func TestConfirmationClosesOnCancellation(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- ConfirmSignature(ctx, key, "test key") }()
	select {
	case approved := <-done:
		if approved {
			t.Fatal("cancelled dialog approved signature")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("confirmation dialog did not close")
	}
}

func TestSignatureWindowTitleAndIcons(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan bool, 1)
	const comment = "production deployment signing key"
	go func() { done <- ConfirmSignature(ctx, key, comment) }()
	window := waitSignatureWindow(t)
	small, large, err := dialogIcons()
	if err != nil {
		t.Fatal(err)
	}
	actualSmall, _, _ := sendMessage.Call(window, 0x007F, 0, 0) // WM_GETICON
	actualLarge, _, _ := sendMessage.Call(window, 0x007F, 1, 0)
	if actualSmall != small || actualLarge != large {
		t.Fatal("confirmation window does not use application icons")
	}
	style, _, _ := getWindowLongPtr.Call(window, ^uintptr(19))
	if style&0x40000 == 0 {
		t.Fatal("confirmation window is missing its taskbar identity")
	}
	body, _, _ := user32.NewProc("GetDlgItem").Call(window, 0xFFFF)
	var bounds rect
	getWindowRect.Call(body, uintptr(unsafe.Pointer(&bounds)))
	keyLabel := comment + " " + ssh.FingerprintSHA256(key)
	var text [256]uint16
	user32.NewProc("GetWindowTextW").Call(body, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)))
	if windows.UTF16ToString(text[:]) != keyLabel {
		t.Fatal("comment and fingerprint are not in the same control")
	}
	if body == 0 || bounds.Right-bounds.Left < controlTextSize(body, keyLabel).CX {
		t.Fatal("comment and fingerprint do not fit on one line")
	}
	if icon, _, _ := user32.NewProc("GetDlgItem").Call(window, 20); icon != 0 {
		if visible, _, _ := user32.NewProc("IsWindowVisible").Call(icon); visible != 0 {
			t.Fatal("message icon is still visible")
		}
	}
	if target := os.Getenv("OMNI_CONFIRM_PREVIEW"); target != "" {
		saveSettingsPreview(t, window, target)
	}
	postMessage.Call(window, 0x0100, 0x0D, 1) // Enter must keep the native default-Cancel behavior.
	select {
	case approved := <-done:
		if approved {
			t.Fatal("default Enter approved a signature")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("confirmation did not close")
	}
}

func waitSignatureWindow(t *testing.T) uintptr {
	t.Helper()
	title, _ := windows.UTF16PtrFromString("OpenSSHAgent – Confirm Signature")
	var window uintptr
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		window, _, _ = user32.NewProc("FindWindowW").Call(0, uintptr(unsafe.Pointer(title)))
		if visible, _, _ := user32.NewProc("IsWindowVisible").Call(window); window != 0 && visible != 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if window == 0 {
		t.Fatal("confirmation window did not appear with the requested title")
	}
	return window
}

func TestSignatureCountdownDeclinesOnTimeout(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan bool, 1)
	started := time.Now()
	go func() { done <- ConfirmSignature(ctx, key, "countdown test") }()
	window := waitSignatureWindow(t)
	button, _, _ := user32.NewProc("GetDlgItem").Call(window, idOK)
	if label := windowText(button); label != "OK (10)" {
		t.Fatalf("initial button label=%q", label)
	}
	deadline := time.Now().Add(2 * time.Second)
	for windowText(button) == "OK (10)" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if label := windowText(button); label != "OK (9)" {
		t.Fatalf("button countdown did not update: %q", label)
	}
	sendMessage.Call(button, 0, 0, 0) // Finish the UI thread's text update before inspecting its border.
	var bounds rect
	getClientRect.Call(button, uintptr(unsafe.Pointer(&bounds)))
	dc, _, _ := getDC.Call(button)
	border := uiColor(16)
	for _, p := range []point{{0, bounds.Bottom / 2}, {bounds.Right - 1, bounds.Bottom / 2}, {bounds.Right / 2, 0}, {bounds.Right / 2, bounds.Bottom - 1}} {
		pixel, _, _ := gdi32.NewProc("GetPixel").Call(dc, uintptr(p.X), uintptr(p.Y))
		if pixel != border {
			t.Errorf("button border disappeared after countdown update at %v: color=%x want=%x", p, pixel, border)
		}
	}
	releaseDC.Call(button, dc)
	select {
	case approved := <-done:
		if approved {
			t.Fatal("timeout approved signature")
		}
		if time.Since(started) < signatureTimeout {
			t.Fatal("confirmation expired too early")
		}
	case <-time.After(11 * time.Second):
		t.Fatal("confirmation did not close after its deadline")
	}
	if alive, _, _ := user32.NewProc("IsWindow").Call(window); alive != 0 {
		t.Fatal("expired window still exists")
	}
}
