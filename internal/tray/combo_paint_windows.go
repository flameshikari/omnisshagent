//go:build windows

package tray

import "unsafe"

func comboPaintMessage(hwnd uintptr, msg uint32, wParam uintptr) (bool, uintptr) {
	paint := func(dc uintptr) {
		paintBufferedControl(hwnd, dc, func(window, memory uintptr, _ rect) { drawThinBorder(window, memory, borderCombo) })
	}
	switch msg {
	case 0x0014: // WM_ERASEBKGND: the buffered renderer fills the whole field.
		return true, 1
	case 0x000F: // WM_PAINT
		var state struct {
			DC                 uintptr
			Erase              int32
			Bounds             rect
			Restore, IncUpdate int32
			Reserved           [32]byte
		}
		dc, _, _ := user32.NewProc("BeginPaint").Call(hwnd, uintptr(unsafe.Pointer(&state)))
		if dc != 0 {
			paint(dc)
		}
		user32.NewProc("EndPaint").Call(hwnd, uintptr(unsafe.Pointer(&state)))
		return true, 0
	case 0x0317, 0x0318: // WM_PRINT / WM_PRINTCLIENT
		if wParam != 0 {
			paint(wParam)
		}
		return true, 0
	}
	return false, 0
}
