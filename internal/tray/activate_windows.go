//go:build windows

package tray

import (
	"context"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ActivateExisting hands foreground permission to the first instance and queues
// its key manager, including when that instance is still starting its backend.
func ActivateExisting(ctx context.Context) bool {
	class, _ := windows.UTF16PtrFromString(windowClass)
	title, _ := windows.UTF16PtrFromString(windowTitle)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return false
		}
		window, _, _ := user32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)))
		if window != 0 {
			var pid uint32
			user32.NewProc("GetWindowThreadProcessId").Call(window, uintptr(unsafe.Pointer(&pid)))
			if pid != 0 {
				user32.NewProc("AllowSetForegroundWindow").Call(uintptr(pid))
			}
			if sent, _, _ := postMessage.Call(window, wmShowKeys, 0, 0); sent != 0 {
				return true
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}
