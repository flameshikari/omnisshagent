//go:build windows

package tray

import "unsafe"

type controlPaintState struct {
	DC                 uintptr
	Erase              int32
	Bounds             rect
	Restore, IncUpdate int32
	Reserved           [32]byte
}

func paintBufferedControl(hwnd, dc uintptr, draw func(uintptr, uintptr, rect)) {
	var bounds rect
	getClientRect.Call(hwnd, uintptr(unsafe.Pointer(&bounds)))
	if bounds.Right <= 0 || bounds.Bottom <= 0 {
		return
	}
	memory, _, _ := createCompatibleDC.Call(dc)
	bitmap, _, _ := gdi32.NewProc("CreateCompatibleBitmap").Call(dc, uintptr(bounds.Right), uintptr(bounds.Bottom))
	if memory == 0 || bitmap == 0 {
		if memory != 0 {
			deleteDC.Call(memory)
		}
		if bitmap != 0 {
			deleteObject.Call(bitmap)
		}
		state, _, _ := saveDC.Call(dc)
		draw(hwnd, dc, bounds)
		restoreDC.Call(dc, state)
		return
	}
	previous, _, _ := selectObject.Call(memory, bitmap)
	draw(hwnd, memory, bounds)
	gdi32.NewProc("BitBlt").Call(dc, 0, 0, uintptr(bounds.Right), uintptr(bounds.Bottom), memory, 0, 0, 0x00CC0020)
	selectObject.Call(memory, previous)
	deleteObject.Call(bitmap)
	deleteDC.Call(memory)
}
