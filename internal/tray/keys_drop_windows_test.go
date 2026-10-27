//go:build windows

package tray

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

func TestManageKeysFileDrop(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	tray := New("", t.TempDir(), func() {})
	tray.SetBackend(b)
	tray.openKeys(0)
	d := keysDlg
	if d == nil {
		t.Fatal("Manage Keys did not open")
	}
	defer d.close()
	assertTaskbarIcon(t, d.hwnd)
	dir := t.TempDir()
	for batch, target := range []uintptr{d.hwnd, d.list} {
		ex, _, _ := getWindowLongPtr.Call(target, ^uintptr(19))
		if ex&0x10 == 0 {
			t.Fatal("drop target does not accept shell files")
		}
		var paths []string
		for index := range 2 {
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, fmt.Sprintf("ключ %d-%d", batch, index))
			if err := writePrivateKey(path, private, nil); err != nil {
				t.Fatal(err)
			}
			paths = append(paths, path)
		}
		sendMessage.Call(target, wmDropFiles, testFileDrop(t, paths), 0)
		keys, err := b.List()
		if err != nil || len(keys) != (batch+1)*2 || len(d.keys) != len(keys) {
			t.Fatalf("drop did not import and refresh keys: backend=%d table=%d err=%v", len(keys), len(d.keys), err)
		}
		for _, key := range keys {
			source := d.keySources[string(key.Blob)]
			if source.File != filepath.Join(dir, key.Comment) || source.Executable != "" {
				t.Fatal("file import did not retain its original path")
			}
			if source.Name != "Manual" {
				t.Fatal("file import did not record its source")
			}
			signature, err := b.Sign(key, []byte("drop import test"))
			if err != nil {
				t.Fatal(err)
			}
			public, err := ssh.ParsePublicKey(key.Blob)
			if err != nil {
				t.Fatal(err)
			}
			if err := public.Verify([]byte("drop import test"), signature); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func testFileDrop(t *testing.T, paths []string) uintptr {
	t.Helper()
	var names []uint16
	for _, path := range paths {
		value, err := windows.UTF16FromString(path)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, value...)
	}
	names = append(names, 0)
	data := make([]byte, 20+len(names)*2)
	binary.LittleEndian.PutUint32(data, 20)
	binary.LittleEndian.PutUint32(data[16:], 1)
	for index, value := range names {
		binary.LittleEndian.PutUint16(data[20+index*2:], value)
	}
	handle, _, err := kernel32.NewProc("GlobalAlloc").Call(2, uintptr(len(data)))
	if handle == 0 {
		t.Fatal(err)
	}
	pointer, _, err := kernel32.NewProc("GlobalLock").Call(handle)
	if pointer == 0 {
		kernel32.NewProc("GlobalFree").Call(handle)
		t.Fatal(err)
	}
	var written uintptr
	err = windows.WriteProcessMemory(windows.CurrentProcess(), pointer, &data[0], uintptr(len(data)), &written)
	kernel32.NewProc("GlobalUnlock").Call(handle)
	if err != nil {
		kernel32.NewProc("GlobalFree").Call(handle)
		t.Fatal(err)
	}
	return handle // The recipient owns it and releases it with DragFinish.
}

func TestPassphraseDialogLayout(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	const fingerprint = "SHA256:AAJF1T/Dly+MNefGtcYuIERftzxkdjyECkOS8UsDg28"
	for _, value := range []string{fingerprint, ""} {
		d := &passwordDialog{}
		passwordDlg = d
		name := "private_key_" + strings.Repeat("long_filename_", 8)
		if err := d.create(0, name, value); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if d.hwnd != 0 {
					destroyWindow.Call(d.hwnd)
				}
			}()
			assertTaskbarIcon(t, d.hwnd)
			if windowText(d.hwnd) != "OmniSSHAgent – Passphrase" {
				t.Fatal("incorrect passphrase title")
			}
			fp, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, idPassFingerprint)
			expected := value
			if expected == "" {
				expected = "Fingerprint unavailable for this key format"
			}
			if windowText(fp) != expected {
				t.Fatalf("incorrect fingerprint label: %q", windowText(fp))
			}
			ok, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, idOK)
			cancel, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, idCancel)
			for _, child := range []uintptr{d.edit, ok, cancel} {
				font, _, _ := sendMessage.Call(child, 0x0031, 0, 0)
				if font != newMetrics().font {
					t.Fatal("passphrase controls do not use Settings font")
				}
			}
			font, _, _ := sendMessage.Call(fp, 0x0031, 0, 0)
			var info [92]byte
			if size, _, _ := gdi32.NewProc("GetObjectW").Call(font, uintptr(len(info)), uintptr(unsafe.Pointer(&info[0]))); size == 0 || binary.LittleEndian.Uint32(info[16:20]) != 700 {
				t.Fatal("fingerprint is not bold")
			}
			filename, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, idPassFilename)
			if windowText(filename) != name {
				t.Fatal("filename is missing from the footer")
			}
			filenameStyle, _, _ := getWindowLongPtr.Call(filename, ^uintptr(15))
			if filenameStyle&0x1F != 2 {
				t.Fatal("filename is not right aligned toward OK")
			}
			var filenameBounds, okBounds rect
			getWindowRect.Call(filename, uintptr(unsafe.Pointer(&filenameBounds)))
			getWindowRect.Call(ok, uintptr(unsafe.Pointer(&okBounds)))
			if filenameBounds.Top != okBounds.Top || okBounds.Left-filenameBounds.Right != newMetrics().s(8) {
				t.Fatal("filename is not immediately before OK")
			}
			var fpBounds, editBounds, cancelBounds, client rect
			getWindowRect.Call(fp, uintptr(unsafe.Pointer(&fpBounds)))
			getWindowRect.Call(d.edit, uintptr(unsafe.Pointer(&editBounds)))
			if fpBounds.Bottom >= editBounds.Top || fpBounds.Right-fpBounds.Left < controlTextSize(fp, expected).CX {
				t.Fatal("fingerprint is clipped or not above the input")
			}
			getWindowRect.Call(cancel, uintptr(unsafe.Pointer(&cancelBounds)))
			user32.NewProc("MapWindowPoints").Call(0, d.hwnd, uintptr(unsafe.Pointer(&cancelBounds)), 2)
			getClientRect.Call(d.hwnd, uintptr(unsafe.Pointer(&client)))
			pad := newMetrics().s(12)
			if client.Right != measureTextWidth(0, font, expected)+2*pad {
				t.Fatal("filename or fixed minimum controls the dialog width instead of the fingerprint")
			}
			if client.Right-cancelBounds.Right != pad || client.Bottom-cancelBounds.Bottom != pad {
				t.Fatal("passphrase footer has excess whitespace")
			}
			setWindowText(d.edit, "test passphrase")
			sendMessage.Call(d.hwnd, wmCommand, idCancel, 0)
			if d.ok || len(d.secret) != 0 || d.hwnd != 0 {
				t.Fatal("cancelled passphrase retained a secret")
			}
		}()
	}
}

func assertTaskbarIcon(t *testing.T, window uintptr) {
	t.Helper()
	ex, _, _ := getWindowLongPtr.Call(window, ^uintptr(19))
	if ex&wsExAppWindow == 0 {
		t.Fatal("window does not opt into taskbar visibility")
	}
	small, large, err := dialogIcons()
	if err != nil {
		t.Fatal(err)
	}
	actualSmall, _, _ := sendMessage.Call(window, 0x007F, 0, 0)
	actualLarge, _, _ := sendMessage.Call(window, 0x007F, 1, 0)
	if actualSmall != small || actualLarge != large {
		t.Fatal("window does not use application icons")
	}
}

func TestAddKeyErrorDialog(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(t.TempDir(), "invalid-key")
	if err := os.WriteFile(invalid, []byte("invalid private key"), 0600); err != nil {
		t.Fatal(err)
	}
	err = addKeyFromFile(b, invalid, nil)
	if err == nil || err.Error() != "invalid-key is not a valid key." {
		t.Fatalf("invalid-key message: %v", err)
	}
	d := &errorDialog{}
	if err := d.create(0, err.Error()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if d.hwnd != 0 {
			destroyWindow.Call(d.hwnd)
		}
	}()
	assertTaskbarIcon(t, d.hwnd)
	showWindow.Call(d.hwnd, 5)
	var flash message
	if pending, _, _ := user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&flash)), d.hwnd, wmFlashError, wmFlashError, 1); pending == 0 {
		t.Fatal("error window did not request taskbar flashing")
	}
	dispatchMessage.Call(uintptr(unsafe.Pointer(&flash)))
	if !d.flashed {
		t.Fatal("error window did not flash after being shown")
	}
	if windowText(d.hwnd) != "OmniSSHAgent – Error" {
		t.Fatal("incorrect Add Key title")
	}
	label, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, 0xFFFF)
	style, _, _ := getWindowLongPtr.Call(label, ^uintptr(15))
	if style&0x1F != 1 {
		t.Fatal("error text is not centered")
	}
	if windowText(label) != "invalid-key is not a valid key." {
		t.Fatal("incorrect Add Key text")
	}
	button, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, idOK)
	var bounds, client rect
	getWindowRect.Call(button, uintptr(unsafe.Pointer(&bounds)))
	user32.NewProc("MapWindowPoints").Call(0, d.hwnd, uintptr(unsafe.Pointer(&bounds)), 2)
	getClientRect.Call(d.hwnd, uintptr(unsafe.Pointer(&client)))
	pad := newMetrics().s(12)
	if client.Bottom-bounds.Bottom != pad || abs(int64(bounds.Left+bounds.Right-client.Right)) > 1 || client.Bottom > newMetrics().s(90) {
		t.Fatal("Add Key error has excess whitespace")
	}
	if icon, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, 20); icon != 0 {
		t.Fatal("Add Key error still has a message pictogram")
	}
	sendMessage.Call(d.hwnd, wmCommand, idOK, 0)
	if d.hwnd != 0 {
		t.Fatal("Add Key error did not close")
	}
}

func TestKeyPasswordErrors(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_encrypted")
	if err := writePrivateKey(path, private, []byte("correct")); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ password, want string }{{"", "Empty password for id_encrypted."}, {"incorrect", "Password decryption failed for id_encrypted."}} {
		b, err := embedded.New()
		if err != nil {
			t.Fatal(err)
		}
		secret := []byte(test.password)
		err = addKeyFromFile(b, path, func(string) ([]byte, bool) { return secret, true })
		if err == nil || err.Error() != test.want {
			t.Fatalf("password error=%v want=%q", err, test.want)
		}
		for _, value := range secret {
			if value != 0 {
				t.Fatal("failed decryption retained the password buffer")
			}
		}
		keys, err := b.List()
		if err != nil || len(keys) != 0 {
			t.Fatal("failed decryption added a key")
		}
	}
}
