//go:build windows

package tray

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ListView invalidates only the native item bounds on selection changes. Our
// first row also fills its leading margin, so include that band in the same
// double-buffered paint before ListView begins drawing.
func invalidateFirstKeyRow(window uintptr) {
	var row, headerBounds, client rect
	if ok, _, _ := sendMessage.Call(window, 0x100E, 0, uintptr(unsafe.Pointer(&row))); ok == 0 {
		return
	}
	header, _, _ := sendMessage.Call(window, 0x101F, 0, 0)
	getClientRect.Call(header, uintptr(unsafe.Pointer(&headerBounds)))
	user32.NewProc("MapWindowPoints").Call(header, window, uintptr(unsafe.Pointer(&headerBounds)), 2)
	if row.Top <= headerBounds.Bottom {
		return
	}
	getClientRect.Call(window, uintptr(unsafe.Pointer(&client)))
	bounds := rect{Top: headerBounds.Bottom, Right: client.Right, Bottom: row.Bottom}
	user32.NewProc("InvalidateRect").Call(window, uintptr(unsafe.Pointer(&bounds)), 0)
}

func paintKeyTable(window uintptr) {
	invalidateFirstKeyRow(window)
	var paint controlPaintState
	dc, _, _ := user32.NewProc("BeginPaint").Call(window, uintptr(unsafe.Pointer(&paint)))
	if dc != 0 {
		paintBufferedControl(window, dc, func(window, memory uintptr, bounds rect) {
			fillRect.Call(memory, uintptr(unsafe.Pointer(&bounds)), uiBrush(5))
			defSubclassProc.Call(window, 0x0318, memory, 0xC) // WM_PRINTCLIENT; PRF_CLIENT | PRF_ERASEBKGND.
		})
	}
	user32.NewProc("EndPaint").Call(window, uintptr(unsafe.Pointer(&paint)))
}

func (d *keysDialog) drawKeyRow(address uintptr) bool {
	var item struct {
		Type, ID, Item, Action, State uint32
		Window, DC                    uintptr
		Bounds                        rect
		Data                          uintptr
	}
	var copied uintptr
	if address == 0 || windows.ReadProcessMemory(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&item)), unsafe.Sizeof(item), &copied) != nil || item.Type != 102 {
		return false
	}
	if int(item.Item) >= len(d.keys) {
		return true
	}
	state, _, _ := saveDC.Call(item.DC)
	defer restoreDC.Call(item.DC, state)
	var client rect
	getClientRect.Call(item.Window, uintptr(unsafe.Pointer(&client)))
	row := item.Bounds
	row.Left, row.Right = 0, client.Right
	if item.Item == 0 {
		header, _, _ := sendMessage.Call(item.Window, 0x101F, 0, 0)
		var bounds rect
		getClientRect.Call(header, uintptr(unsafe.Pointer(&bounds)))
		user32.NewProc("MapWindowPoints").Call(header, item.Window, uintptr(unsafe.Pointer(&bounds)), 2)
		row.Top = min(row.Top, bounds.Bottom)
	}
	background, foreground := uintptr(5), uintptr(8)
	if item.State&1 != 0 {
		background, foreground = 13, 14
	}
	brush := uiBrush(background)
	fillRect.Call(item.DC, uintptr(unsafe.Pointer(&row)), brush)
	font, _, _ := sendMessage.Call(item.Window, 0x0031, 0, 0)
	if font != 0 {
		selectObject.Call(item.DC, font)
	}
	color := uiColor(foreground)
	setTextColor.Call(item.DC, color)
	setBkMode.Call(item.DC, 1)
	left, padding := int32(0), d.m.s(6)
	for column := 0; column < len(keyColumnNames); column++ {
		width, _, _ := sendMessage.Call(item.Window, 0x101D, uintptr(column), 0)
		cell := rect{Left: left + padding, Top: item.Bounds.Top, Right: left + int32(width) - padding, Bottom: item.Bounds.Bottom}
		if column == 2 {
			source := d.keySources[string(d.keys[item.Item].Blob)]
			app := d.sourceApps[sourceAppID(source)]
			size := d.m.s(16)
			if app.icon != 0 && cell.Right-cell.Left >= size {
				y := cell.Top + (cell.Bottom-cell.Top-size)/2
				user32.NewProc("DrawIconEx").Call(item.DC, uintptr(cell.Left), uintptr(y), app.icon, uintptr(size), uintptr(size), 0, 0, 3)
				cell.Left += size + d.m.s(4)
			}
		}
		text, _ := windows.UTF16PtrFromString(strings.ReplaceAll(d.keyCell(d.keys[item.Item], column), "\x00", "\uFFFD"))
		drawText.Call(item.DC, uintptr(unsafe.Pointer(text)), ^uintptr(0), uintptr(unsafe.Pointer(&cell)), 0x8824)
		left += int32(width)
	}
	if item.State&0x10 != 0 && item.State&0x200 == 0 {
		if flags, _, _ := sendMessage.Call(item.Window, 0x0129, 0, 0); flags&1 == 0 {
			user32.NewProc("DrawFocusRect").Call(item.DC, uintptr(unsafe.Pointer(&row)))
		}
	}
	return true
}
