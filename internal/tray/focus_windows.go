//go:build windows

package tray

import "golang.org/x/sys/windows"

var focusCueCallback uintptr

func init() { focusCueCallback = windows.NewCallback(focusCueWindowProc) }

func installFocusCues(hwnd uintptr) error {
	if ok, _, err := setWindowSubclass.Call(hwnd, focusCueCallback, 2, 0); ok == 0 {
		return winErr(err)
	}
	sendMessage.Call(hwnd, 0x0127, 1|1<<16, 0) // WM_CHANGEUISTATE / UIS_SET / UISF_HIDEFOCUS
	return nil
}

func focusCueWindowProc(hwnd uintptr, msg uint32, wParam, lParam, id, data uintptr) uintptr {
	if msg == 0x0201 || (msg == 0x0210 && uint16(wParam) == 0x0201) { // Direct or child mouse click.
		sendMessage.Call(hwnd, 0x0127, 1|1<<16, 0)
	}
	if msg == 0x0082 {
		removeWindowSubclass.Call(hwnd, focusCueCallback, id)
	}
	result, _, _ := defSubclassProc.Call(hwnd, uintptr(msg), wParam, lParam)
	return result
}

func updateFocusCues(msg *message) {
	if msg.Message == 0x0100 && msg.WParam == 0x09 { // WM_KEYDOWN / Tab (including Shift+Tab).
		root, _, _ := user32.NewProc("GetAncestor").Call(msg.Window, 2) // GA_ROOT
		if root != 0 {
			sendMessage.Call(root, 0x0127, 2|1<<16, 0)
		} // UIS_CLEAR / UISF_HIDEFOCUS
	}
}
