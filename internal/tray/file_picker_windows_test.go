//go:build windows

package tray

import (
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestFilePickerTaskbar(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	owner, err := createPopup("OmniSSHAgentFilePickerTestOwner", "File picker owner", 240, 100, 0, settingsCallback)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyWindow.Call(owner)
	const title = "OmniSSHAgent file picker test"
	name, _ := windows.UTF16PtrFromString(title)
	class, _ := windows.UTF16PtrFromString("#32770")
	type snapshot struct{ window, style uintptr }
	done := make(chan snapshot, 1)
	go func() {
		var result snapshot
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			result.window, _, _ = user32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(name)))
			if result.window != 0 {
				if visible, _, _ := user32.NewProc("IsWindowVisible").Call(result.window); visible != 0 {
					result.style, _, _ = getWindowLongPtr.Call(result.window, ^uintptr(19))
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		if result.window != 0 {
			postMessage.Call(result.window, wmCommand, idCancel, 0)
		}
		done <- result
	}()
	if _, selected := pickOpenFile(owner, title, t.TempDir(), "", []string{"All files", "*.*"}, true); selected {
		t.Fatal("cancelled file picker selected a file")
	}
	result := <-done
	if result.window == 0 {
		t.Fatal("file picker did not appear")
	}
	if result.style&wsExAppWindow == 0 {
		t.Fatal("owned file picker does not opt into taskbar visibility")
	}
}
