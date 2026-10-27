//go:build windows

package tray

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const wmDropFiles = 0x0233

var (
	dragAcceptFiles  = shell32.NewProc("DragAcceptFiles")
	dragQueryFile    = shell32.NewProc("DragQueryFileW")
	dragFinish       = shell32.NewProc("DragFinish")
	keysDropCallback uintptr
)

func init() { keysDropCallback = windows.NewCallback(keysDropWindowProc) }

func (d *keysDialog) acceptFileDrops() error {
	if ok, _, err := setWindowSubclass.Call(d.list, keysDropCallback, 2, d.hwnd); ok == 0 {
		return winErr(err)
	}
	dragAcceptFiles.Call(d.hwnd, 1)
	dragAcceptFiles.Call(d.list, 1)
	return nil
}

func keysDropWindowProc(window uintptr, msg uint32, wParam, lParam, id, owner uintptr) uintptr {
	if msg == 0x000F { // WM_PAINT
		if keysDlg != nil && keysDlg.hwnd == owner && (keysDlg.fittingColumns || keysDlg.updatingKeys) {
			return 0
		}
		paintKeyTable(window)
		return 0
	}
	if msg == 0x0014 {
		return 1
	} // Background is filled in the same offscreen frame as rows.
	if msg == 0x0100 && wParam == 0x2E && keysDlg != nil && keysDlg.hwnd == owner {
		if enabled, _, _ := isWindowEnabled.Call(window); enabled != 0 {
			if lParam&(1<<30) == 0 {
				postMessage.Call(owner, wmDeleteKeys, 0, 0)
			}
			return 0
		}
	}
	if msg == wmDropFiles {
		if keysDlg != nil && keysDlg.hwnd == owner {
			sendMessage.Call(owner, wmDropFiles, wParam, 0)
		} else {
			dragFinish.Call(wParam)
		}
		return 0
	}
	if msg == 0x0082 { // WM_NCDESTROY
		removeWindowSubclass.Call(window, keysDropCallback, id)
	}
	result, _, _ := defSubclassProc.Call(window, uintptr(msg), wParam, lParam)
	return result
}

func droppedFiles(drop uintptr) []string {
	defer dragFinish.Call(drop)
	count, _, _ := dragQueryFile.Call(drop, 0xFFFFFFFF, 0, 0)
	var paths []string
	for index := uintptr(0); index < count; index++ {
		length, _, _ := dragQueryFile.Call(drop, index, 0, 0)
		if length == 0 || length > 32767 {
			continue
		}
		buffer := make([]uint16, int(length)+1)
		if copied, _, _ := dragQueryFile.Call(drop, index, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer))); copied == length {
			paths = append(paths, windows.UTF16ToString(buffer))
		}
	}
	return paths
}
