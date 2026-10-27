//go:build windows

package tray

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func measureControlItem(address uintptr, height int32, kind uint32) bool {
	var item struct {
		Type, ID, Item, Width, Height uint32
		Data                          uintptr
	}
	var copied uintptr
	if address == 0 || windows.ReadProcessMemory(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&item)), unsafe.Sizeof(item), &copied) != nil || item.Type != kind {
		return false
	}
	item.Height = uint32(height)
	return windows.WriteProcessMemory(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&item)), unsafe.Sizeof(item), &copied) == nil
}

func drawComboItem(address uintptr) bool {
	var item struct {
		Type, ID, Item, Action, State uint32
		Window, DC                    uintptr
		Bounds                        rect
		Data                          uintptr
	}
	var copied uintptr
	if address == 0 || windows.ReadProcessMemory(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&item)), unsafe.Sizeof(item), &copied) != nil || item.Type != 3 {
		return false
	}
	state, _, _ := saveDC.Call(item.DC)
	defer restoreDC.Call(item.DC, state)
	gdi32.NewProc("IntersectClipRect").Call(item.DC, uintptr(item.Bounds.Left), uintptr(item.Bounds.Top), uintptr(item.Bounds.Right), uintptr(item.Bounds.Bottom))
	background, foreground := uintptr(5), uintptr(8)
	if item.State&1 != 0 && item.State&0x1000 == 0 {
		background, foreground = 13, 14
	} // Highlight only in the open list.
	if item.State&4 != 0 {
		foreground = 17
	} // ODS_DISABLED
	brush := uiBrush(background)
	fillRect.Call(item.DC, uintptr(unsafe.Pointer(&item.Bounds)), brush)
	if int32(item.Item) < 0 {
		return true
	}
	length, _, _ := sendMessage.Call(item.Window, 0x0149, uintptr(item.Item), 0) // CB_GETLBTEXTLEN
	if int32(length) < 0 || length > 65536 {
		return true
	}
	text := make([]uint16, int(length)+1)
	sendMessage.Call(item.Window, 0x0148, uintptr(item.Item), uintptr(unsafe.Pointer(&text[0]))) // CB_GETLBTEXT
	font, _, _ := sendMessage.Call(item.Window, 0x0031, 0, 0)
	if font != 0 {
		selectObject.Call(item.DC, font)
	}
	color := uiColor(foreground)
	setTextColor.Call(item.DC, color)
	setBkMode.Call(item.DC, 1)
	padding := newMetrics().s(6)
	if item.State&0x1000 == 0 {
		padding--
	} // The popup adds its own physical 1px frame.
	label := item.Bounds
	label.Left += padding
	label.Right -= padding
	drawText.Call(item.DC, uintptr(unsafe.Pointer(&text[0])), uintptr(length), uintptr(unsafe.Pointer(&label)), 0x8824)
	return true
}
