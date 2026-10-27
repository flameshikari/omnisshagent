//go:build windows

package keepassxc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sys/windows"
)

func TestStatusPreservesUnlockBroadcastBeforeReply(t *testing.T) {
	client, err := newCryptoSession()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := box.GenerateKey(rand.Reader)
	if err := client.accept(message{Success: "true", PublicKey: base64.StdEncoding.EncodeToString(pub[:])}); err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	p := &proxyProcess{input: writer, messages: make(chan received, 4)}
	defer reader.Close()
	defer writer.Close()
	go func() {
		m, err := readMessage(reader)
		if err != nil {
			p.messages <- received{err: err}
			return
		}
		decoded, _ := base64.StdEncoding.DecodeString(m.Nonce)
		var n [24]byte
		copy(n[:], decoded)
		ciphertext, _ := base64.StdEncoding.DecodeString(m.Message)
		if _, ok := box.Open(nil, ciphertext, &n, client.public, priv); !ok {
			p.messages <- received{err: io.ErrUnexpectedEOF}
			return
		}
		p.messages <- received{message: message{Action: "database-unlocked"}}
		for i := range n {
			n[i]++
			if n[i] != 0 {
				break
			}
		}
		response := box.Seal(nil, []byte(`{"success":"true","hash":"test"}`), &n, client.public, priv)
		p.messages <- received{message: message{Action: "get-databasehash", Nonce: base64.StdEncoding.EncodeToString(n[:]), Message: base64.StdEncoding.EncodeToString(response)}}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	opened, err := p.status(ctx, client, true)
	if err != nil || !opened || !p.unlocked {
		t.Fatalf("opened=%v broadcast=%v err=%v", opened, p.unlocked, err)
	}
}

func TestPauseStopsOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pause(ctx, time.Hour); err != context.Canceled {
		t.Fatalf("pause=%v", err)
	}
}

// This opt-in smoke test only reads status from an already-running KeePassXC.
// It never requests unlock or starts the GUI.
func TestInstalledKeePassXCStatus(t *testing.T) {
	executable := os.Getenv("OMNI_TEST_KEEPASSXC")
	if executable == "" {
		t.Skip("set OMNI_TEST_KEEPASSXC for read-only protocol smoke test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pid, discovered, err := resolveExecutable("", findProcess)
	if err != nil || pid == 0 {
		t.Fatalf("running-process discovery: pid=%d err=%v", pid, err)
	}
	if !strings.EqualFold(filepath.Clean(discovered), filepath.Clean(executable)) {
		t.Fatalf("discovered unexpected executable: %q", discovered)
	}
	p, s, err := connect(ctx, filepath.Join(filepath.Dir(discovered), "keepassxc-proxy.exe"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	_, err = p.status(ctx, s, false)
	if err != nil {
		t.Fatal(err)
	}
}

func TestResolveExecutable(t *testing.T) {
	actual := `C:\Running\KeePassXC.exe`
	findRunning := func(name string) (uint32, string, error) {
		if name != "KeePassXC.exe" {
			t.Fatalf("process name=%q", name)
		}
		return 42, actual, nil
	}
	for _, configured := range []string{"", `D:\Old\KeePassXC.exe`} {
		pid, path, err := resolveExecutable(configured, findRunning)
		if err != nil || pid != 42 || path != actual {
			t.Fatalf("pid=%d path=%q err=%v", pid, path, err)
		}
	}
	findMissing := func(string) (uint32, string, error) { return 0, "", nil }
	if _, _, err := resolveExecutable("", findMissing); err == nil {
		t.Fatal("missing executable must not launch an arbitrary PATH command")
	}
	configured := `C:\Programs\KeePassXC.exe`
	pid, path, err := resolveExecutable(configured, findMissing)
	if err != nil || pid != 0 || path != configured {
		t.Fatalf("cold-start resolution: pid=%d path=%q err=%v", pid, path, err)
	}
}

func TestRequestExecutableStartupPolicy(t *testing.T) {
	path := `C:\Programs\KeePassXC.exe`
	missing := func(string) (uint32, string, error) { return 0, "", nil }
	if _, _, err := resolveRequestExecutable(path, false, missing); err == nil {
		t.Fatal("startup disabled but a launch path was returned")
	}
	if pid, executable, err := resolveRequestExecutable(path, true, missing); err != nil || pid != 0 || executable != path {
		t.Fatalf("allowed startup: pid=%d path=%q err=%v", pid, executable, err)
	}
	running := func(string) (uint32, string, error) { return 42, path, nil }
	if pid, executable, err := resolveRequestExecutable(path, false, running); err != nil || pid != 42 || executable != path {
		t.Fatalf("running process unavailable with startup disabled: pid=%d path=%q err=%v", pid, executable, err)
	}
}

func TestProcessExecutable(t *testing.T) {
	path, err := processExecutable(windows.GetCurrentProcessId())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Base(path), filepath.Base(want)) {
		t.Fatalf("path=%q executable=%q", path, want)
	}
}

func TestRestoreMinimizedUnlockDialog(t *testing.T) {
	testRestoreUnlockDialog(t, 6)
}

func TestRestoreHiddenUnlockDialog(t *testing.T) {
	testRestoreUnlockDialog(t, 0)
}

func TestActivateUnlockDialogFromWorkerThread(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	class, _ := windows.UTF16PtrFromString("STATIC")
	create := user32.NewProc("CreateWindowExW")
	newWindow := func(title string) uintptr {
		text, _ := windows.UTF16PtrFromString(title)
		hwnd, _, err := create.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(text)), 0x00CF0000, 123, 145, 700, 400, 0, 0, 0, 0)
		if hwnd == 0 {
			t.Fatal(err)
		}
		user32.NewProc("ShowWindow").Call(hwnd, 5)
		return hwnd
	}
	dialog := newWindow("Unlock Database - KeePassXC")
	defer user32.NewProc("DestroyWindow").Call(dialog)
	blocker := newWindow("Terminal")
	defer user32.NewProc("DestroyWindow").Call(blocker)
	setForegroundWindow.Call(blocker)
	foreground, _, _ := getForegroundWindow.Call()
	canActivate := foreground != 0
	var before, after [4]int32
	getRect := user32.NewProc("GetWindowRect")
	getRect.Call(dialog, uintptr(unsafe.Pointer(&before[0])))
	finished := make(chan bool, 1)
	go func() { finished <- activateUnlockWindow(dialog) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// The target windows belong to this thread, so keep processing activation
		// messages while the agent worker performs its cross-thread request.
		var msg [8]uintptr
		for {
			pending, _, _ := peekMessage.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0, 1)
			if pending == 0 {
				break
			}
			user32.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&msg[0])))
			user32.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&msg[0])))
		}
		select {
		case activated := <-finished:
			getRect.Call(dialog, uintptr(unsafe.Pointer(&after[0])))
			if before != after {
				t.Fatalf("activation changed geometry: before=%v after=%v", before, after)
			}
			if canActivate && !activated {
				t.Fatal("unlock dialog was not activated")
			}
			if !canActivate {
				t.Log("desktop does not permit foreground activation; geometry check passed")
			}
			return
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("activation worker did not return")
}

func testRestoreUnlockDialog(t *testing.T, showCommand uintptr) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	class, _ := windows.UTF16PtrFromString("STATIC")
	title, _ := windows.UTF16PtrFromString("Unlock Database - KeePassXC")
	create := user32.NewProc("CreateWindowExW")
	hwnd, _, err := create.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)), 0x00CF0000, 100, 100, 700, 400, 0, 0, 0, 0)
	if hwnd == 0 {
		t.Fatal(err)
	}
	defer user32.NewProc("DestroyWindow").Call(hwnd)
	user32.NewProc("ShowWindow").Call(hwnd, showCommand)
	if iconic, _, _ := isIconic.Call(hwnd); showCommand == 6 && iconic == 0 {
		t.Fatal("test window was not minimized")
	}
	if found := unlockWindow(windows.GetCurrentProcessId()); showCommand == 6 && found != hwnd {
		t.Fatalf("unlock window=%d want=%d", found, hwnd)
	}
	restoreUnlockWindow(hwnd)
	peek := user32.NewProc("PeekMessageW")
	translate := user32.NewProc("TranslateMessage")
	dispatch := user32.NewProc("DispatchMessageW")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var msg [8]uintptr
		for {
			r, _, _ := peek.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0, 1)
			if r == 0 {
				break
			}
			translate.Call(uintptr(unsafe.Pointer(&msg[0])))
			dispatch.Call(uintptr(unsafe.Pointer(&msg[0])))
		}
		if iconic, _, _ := isIconic.Call(hwnd); iconic == 0 && visible(hwnd) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("unlock dialog remained minimized")
}
