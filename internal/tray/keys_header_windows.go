//go:build windows

package tray

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Own divider dragging so the system's "show window contents while dragging"
// preference cannot turn column resizing into an outline-only preview.
func keyHeaderMessage(hwnd uintptr, msg uint32, wParam, lParam uintptr) (bool, uintptr) {
	switch msg {
	case 0x0014: // WM_ERASEBKGND: the buffered paint fills the entire header.
		return true, 1
	case 0x000F: // WM_PAINT
		if keysDlg != nil && (keysDlg.fittingColumns || keysDlg.updatingKeys) {
			return true, 0
		}
		var paint controlPaintState
		dc, _, _ := user32.NewProc("BeginPaint").Call(hwnd, uintptr(unsafe.Pointer(&paint)))
		if dc != 0 {
			paintKeyHeader(hwnd, dc)
		}
		user32.NewProc("EndPaint").Call(hwnd, uintptr(unsafe.Pointer(&paint)))
		return true, 0
	case 0x0317, 0x0318: // WM_PRINT / WM_PRINTCLIENT
		if wParam != 0 {
			paintKeyHeader(hwnd, wParam)
		}
		return true, 0
	}
	d := keysDlg
	if d == nil {
		return false, 0
	}
	x, y := int32(int16(lParam)), int32(int16(lParam>>16))
	switch msg {
	case 0x0201: // WM_LBUTTONDOWN
		var hit struct {
			Point point
			Flags uint32
			Item  int32
		}
		hit.Point = point{x, y}
		sendMessage.Call(hwnd, 0x1206, 0, uintptr(unsafe.Pointer(&hit))) // HDM_HITTEST
		if hit.Flags&0xC == 0 || hit.Item < 0 || hit.Item >= int32(keyFingerprintColumn) {
			return false, 0
		}
		width, _, _ := sendMessage.Call(d.list, 0x101D, uintptr(hit.Item), 0)
		d.headerDrag.active, d.headerDrag.column = true, int(hit.Item)
		d.headerDrag.startX, d.headerDrag.width = x, int32(width)
		user32.NewProc("SetCapture").Call(hwnd)
		return true, 0
	case 0x0200: // WM_MOUSEMOVE
		if !d.headerDrag.active {
			return false, 0
		}
		d.dragColumn(d.headerDrag.width + x - d.headerDrag.startX)
		return true, 0
	case 0x0202: // WM_LBUTTONUP
		if !d.headerDrag.active {
			return false, 0
		}
		d.dragColumn(d.headerDrag.width + x - d.headerDrag.startX)
		d.headerDrag.active = false
		user32.NewProc("ReleaseCapture").Call()
		return true, 0
	case 0x001F, 0x0215: // WM_CANCELMODE / WM_CAPTURECHANGED
		if d.headerDrag.active {
			d.headerDrag.active = false
			if msg == 0x001F {
				user32.NewProc("ReleaseCapture").Call()
			}
			return true, 0
		}
	}
	return false, 0
}

func (d *keysDialog) dragColumn(width int32) {
	column := d.headerDrag.column
	var other int32
	for i := 0; i < keyFingerprintColumn; i++ {
		if i != column {
			current, _, _ := sendMessage.Call(d.list, 0x101D, uintptr(i), 0)
			other += int32(current)
		}
	}
	var area rect
	getClientRect.Call(d.list, uintptr(unsafe.Pointer(&area)))
	width = max(d.m.s(32), min(width, area.Right-other-d.m.s(80)))
	current, _, _ := sendMessage.Call(d.list, 0x101D, uintptr(column), 0)
	if int32(current) == width {
		return
	}
	// Keep the total width within the viewport throughout the update. Resizing
	// with WM_SETREDRAW disabled makes WM_PRINTCLIENT return empty frames.
	// Defer paint while both widths change, then present one completed frame.
	lastWidth := area.Right - other - width
	d.fittingColumns = true
	if width > int32(current) {
		sendMessage.Call(d.list, 0x101E, uintptr(keyFingerprintColumn), uintptr(lastWidth))
		sendMessage.Call(d.list, 0x101E, uintptr(column), uintptr(width))
	} else {
		sendMessage.Call(d.list, 0x101E, uintptr(column), uintptr(width))
		sendMessage.Call(d.list, 0x101E, uintptr(keyFingerprintColumn), uintptr(lastWidth))
	}
	d.fittingColumns = false
	user32.NewProc("RedrawWindow").Call(d.list, 0, 0, 0x1A1)
}

// Render once into a bitmap rather than drawing over the native themed header.
func paintKeyHeader(hwnd, dc uintptr) {
	paintBufferedControl(hwnd, dc, drawKeyHeader)
}

func drawKeyHeader(hwnd, dc uintptr, bounds rect) {
	background := uiBrush(15)
	fillRect.Call(dc, uintptr(unsafe.Pointer(&bounds)), background)
	font, _, _ := sendMessage.Call(hwnd, 0x0031, 0, 0)
	if font != 0 {
		selectObject.Call(dc, font)
	}
	textColor := uiColor(18) // COLOR_BTNTEXT
	setTextColor.Call(dc, textColor)
	setBkMode.Call(dc, 1)
	border := uiBrush(16)
	m := newMetrics()
	padding := m.s(6)
	for column, name := range keyColumnNames {
		var cell rect
		if ok, _, _ := sendMessage.Call(hwnd, 0x1207, uintptr(column), uintptr(unsafe.Pointer(&cell))); ok == 0 {
			continue
		}
		label := cell
		label.Left += padding
		label.Right -= padding
		label.Top += padding
		label.Bottom -= padding + 1
		item := keyHeaderItem{Mask: 4}
		sendMessage.Call(hwnd, 0x120B, uintptr(column), uintptr(unsafe.Pointer(&item)))
		if item.Format&0x600 != 0 {
			label.Right -= m.s(12)
		}
		text, _ := windows.UTF16PtrFromString(name)
		drawText.Call(dc, uintptr(unsafe.Pointer(text)), ^uintptr(0), uintptr(unsafe.Pointer(&label)), 0x8824)
		if item.Format&0x600 != 0 {
			x, y := cell.Right-m.s(9), (cell.Top+cell.Bottom)/2
			w, h := m.s(3), m.s(2)
			if item.Format&0x400 != 0 {
				h = -h
			}
			points := [3]point{{x - w, y - h}, {x + w, y - h}, {x, y + h}}
			pen, _, _ := getStockObject.Call(8)
			selectObject.Call(dc, pen)
			brush := uiBrush(18)
			selectObject.Call(dc, brush)
			polygon.Call(dc, uintptr(unsafe.Pointer(&points[0])), 3)
		}
		if column < keyFingerprintColumn {
			line := rect{Left: cell.Right - 1, Top: cell.Top, Right: cell.Right, Bottom: cell.Bottom}
			fillRect.Call(dc, uintptr(unsafe.Pointer(&line)), border)
		}
	}
	line := rect{Left: bounds.Left, Top: bounds.Bottom - 1, Right: bounds.Right, Bottom: bounds.Bottom}
	fillRect.Call(dc, uintptr(unsafe.Pointer(&line)), border)
}

func sizeKeyHeader(hwnd, address uintptr) {
	var layout struct{ Bounds, Position uintptr }
	var copied uintptr
	if address == 0 || windows.ReadProcessMemory(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&layout)), unsafe.Sizeof(layout), &copied) != nil {
		return
	}
	var bounds rect
	var position struct {
		Window, After       uintptr
		X, Y, Width, Height int32
		Flags               uint32
	}
	if windows.ReadProcessMemory(windows.CurrentProcess(), layout.Bounds, (*byte)(unsafe.Pointer(&bounds)), unsafe.Sizeof(bounds), &copied) != nil {
		return
	}
	if windows.ReadProcessMemory(windows.CurrentProcess(), layout.Position, (*byte)(unsafe.Pointer(&position)), unsafe.Sizeof(position), &copied) != nil {
		return
	}
	height := controlTextSize(hwnd, "Mg").CY + 2*newMetrics().s(6) + 1
	bounds.Top += height - position.Height
	position.Height = height
	_ = windows.WriteProcessMemory(windows.CurrentProcess(), layout.Bounds, (*byte)(unsafe.Pointer(&bounds)), unsafe.Sizeof(bounds), &copied)
	_ = windows.WriteProcessMemory(windows.CurrentProcess(), layout.Position, (*byte)(unsafe.Pointer(&position)), unsafe.Sizeof(position), &copied)
}
