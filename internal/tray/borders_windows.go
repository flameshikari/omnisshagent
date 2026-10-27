//go:build windows

package tray

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	borderButton    = 1
	borderGroup     = 2
	borderEdit      = 3
	borderList      = 4
	borderCombo     = 5
	borderComboList = 6
	borderKeyHeader = 7
)

var (
	comctl32             = windows.NewLazySystemDLL("comctl32.dll")
	setWindowSubclass    = comctl32.NewProc("SetWindowSubclass")
	removeWindowSubclass = comctl32.NewProc("RemoveWindowSubclass")
	defSubclassProc      = comctl32.NewProc("DefSubclassProc")
	getClientRect        = user32.NewProc("GetClientRect")
	frameRect            = user32.NewProc("FrameRect")
	getSysColorBrush     = user32.NewProc("GetSysColorBrush")
	getSysColor          = user32.NewProc("GetSysColor")
	getWindowDC          = user32.NewProc("GetWindowDC")
	fillRect             = user32.NewProc("FillRect")
	drawText             = user32.NewProc("DrawTextW")
	getComboBoxInfo      = user32.NewProc("GetComboBoxInfo")
	isWindowEnabled      = user32.NewProc("IsWindowEnabled")
	getWindowLongPtr     = user32.NewProc("GetWindowLongPtrW")
	setWindowLongPtr     = user32.NewProc("SetWindowLongPtrW")
	setBkMode            = gdi32.NewProc("SetBkMode")
	setTextColor         = gdi32.NewProc("SetTextColor")
	polygon              = gdi32.NewProc("Polygon")
	saveDC               = gdi32.NewProc("SaveDC")
	restoreDC            = gdi32.NewProc("RestoreDC")
	excludeClipRect      = gdi32.NewProc("ExcludeClipRect")
	borderCallback       uintptr
)

func init() { borderCallback = windows.NewCallback(borderWindowProc) }

func setThinBorder(hwnd uintptr, kind uintptr) error {
	if ok, _, err := setWindowSubclass.Call(hwnd, borderCallback, 1, kind); ok == 0 {
		return winErr(err)
	}
	if kind == borderEdit || kind == borderList || kind == borderComboList {
		setWindowPos.Call(hwnd, 0, 0, 0, 0, 0, 0x37) // Recalculate frame, no move/resize/activation.
	}
	if kind == borderCombo {
		empty, _ := windows.UTF16PtrFromString("")
		windows.NewLazySystemDLL("uxtheme.dll").NewProc("SetWindowTheme").Call(hwnd, uintptr(unsafe.Pointer(empty)), uintptr(unsafe.Pointer(empty)))
		styleComboPopup(hwnd)
	}
	return nil
}

func borderWindowProc(hwnd uintptr, msg uint32, wParam, lParam, id, kind uintptr) uintptr {
	if kind == borderCombo {
		if handled, result := comboPaintMessage(hwnd, msg, wParam); handled {
			return result
		}
	}
	if kind == borderKeyHeader {
		if handled, result := keyHeaderMessage(hwnd, msg, wParam, lParam); handled {
			return result
		}
	}
	if kind == borderComboList {
		if msg == 0x0046 && lParam != 0 { // WM_WINDOWPOSCHANGING
			var position struct {
				Window, After       uintptr
				X, Y, Width, Height int32
				Flags               uint32
			}
			var copied uintptr
			if err := windows.ReadProcessMemory(windows.CurrentProcess(), lParam, (*byte)(unsafe.Pointer(&position)), unsafe.Sizeof(position), &copied); err == nil && position.Flags&0x0002 == 0 { // SWP_NOMOVE
				position.Y--
				_ = windows.WriteProcessMemory(windows.CurrentProcess(), lParam, (*byte)(unsafe.Pointer(&position)), unsafe.Sizeof(position), &copied)
			}
		}
		kind = borderList
	}
	var editFrame rect
	if kind == borderEdit && msg == 0x0083 && lParam != 0 {
		var copied uintptr
		if err := windows.ReadProcessMemory(windows.CurrentProcess(), lParam, (*byte)(unsafe.Pointer(&editFrame)), unsafe.Sizeof(editFrame), &copied); err != nil {
			result, _, _ := defSubclassProc.Call(hwnd, uintptr(msg), wParam, lParam)
			return result
		}
	}
	if msg == 0x0082 { // WM_NCDESTROY
		removeWindowSubclass.Call(hwnd, borderCallback, id)
	}
	result, _, _ := defSubclassProc.Call(hwnd, uintptr(msg), wParam, lParam)
	if keysDlg != nil && !keysDlg.fittingColumns && ((kind == borderKeyHeader && (msg == 0x0005 || msg == 0x120C || msg == 0x1204)) || (hwnd == keysDlg.list && msg == 0x0005)) {
		postMessage.Call(keysDlg.hwnd, wmFitKeyColumns, 0, 0)
	}
	if kind == borderKeyHeader {
		if msg == 0x1205 {
			sizeKeyHeader(hwnd, lParam)
		} // HDM_LAYOUT
		switch msg {
		case 0x0005, wmSetFont, 0x120C, 0x1204, 0x0201, 0x0202, 0x031A:
			user32.NewProc("InvalidateRect").Call(hwnd, 0, 0)
		}
		return result
	}
	if kind == borderEdit && msg == 0x0083 && lParam != 0 { // WM_NCCALCSIZE: first RECT is shared by both forms.
		var bounds rect
		var copied uintptr
		if err := windows.ReadProcessMemory(windows.CurrentProcess(), lParam, (*byte)(unsafe.Pointer(&bounds)), unsafe.Sizeof(bounds), &copied); err != nil {
			return result
		}
		// Keep both side borders outside the edit's client painting region.
		bounds.Left, bounds.Right = editFrame.Left+1, editFrame.Right-1
		height := controlTextSize(hwnd, "Mg").CY
		if extra := bounds.Bottom - bounds.Top - height; height > 0 && extra > 0 {
			bounds.Top += extra / 2
			bounds.Bottom = bounds.Top + height
		}
		if err := windows.WriteProcessMemory(windows.CurrentProcess(), lParam, (*byte)(unsafe.Pointer(&bounds)), unsafe.Sizeof(bounds), &copied); err != nil {
			return result
		}
		return 0
	}
	if kind == borderEdit && msg == 0x0084 {
		return 1
	} // Padding clicks are client-area clicks.
	if msg == wmSetFont {
		if kind == borderEdit {
			setWindowPos.Call(hwnd, 0, 0, 0, 0, 0, 0x37)
			margin := uint32(newMetrics().s(5))
			sendMessage.Call(hwnd, 0x00D3, 3, uintptr(margin|margin<<16)) // EM_SETMARGINS after frame recalculation.
		}
		if kind == borderCombo {
			sizeComboField(hwnd)
			styleComboPopup(hwnd)
		}
	}
	if kind == borderCombo {
		switch msg {
		case wmSetFont, wmSetText, 0x014E, 0x0005, 0x0007, 0x0008, 0x000A, 0x0201, 0x0202, 0x031A:
			user32.NewProc("InvalidateRect").Call(hwnd, 0, 0)
		}
		return result
	}
	var dc uintptr
	release := false
	switch msg {
	case wmSetText:
		// Buttons repaint synchronously when their label changes, bypassing WM_PAINT.
		if kind == borderButton {
			dc, _, _ = getDC.Call(hwnd)
			release = true
		}
	case 0x000F: // WM_PAINT
		if kind == borderEdit || kind == borderList {
			break
		}
		if kind == borderCombo {
			dc, _, _ = getWindowDC.Call(hwnd)
		} else {
			dc, _, _ = getDC.Call(hwnd)
		}
		release = true
	case 0x0085: // WM_NCPAINT
		if kind == borderEdit || kind == borderList || kind == borderCombo {
			dc, _, _ = getWindowDC.Call(hwnd)
			release = true
		}
	case 0x0007, 0x0008, 0x000A, 0x00F3, 0x00F4, 0x0200, 0x0201, 0x0202, 0x02A3, 0x031A: // Focus, enable, button state, hover, theme.
		if kind == borderGroup {
			break
		}
		if alive, _, _ := isWindow.Call(hwnd); alive == 0 {
			break
		}
		if kind == borderEdit || kind == borderList || kind == borderCombo {
			dc, _, _ = getWindowDC.Call(hwnd)
		} else {
			dc, _, _ = getDC.Call(hwnd)
		}
		release = true
	case 0x0317: // WM_PRINT
		dc = wParam
	case 0x0318: // WM_PRINTCLIENT
		if kind != borderEdit && kind != borderList && kind != borderCombo {
			dc = wParam
		}
	}
	if dc != 0 {
		drawThinBorder(hwnd, dc, kind)
		if release {
			releaseDC.Call(hwnd, dc)
		}
	}
	return result
}

func drawThinBorder(hwnd, dc, kind uintptr) {
	state, _, _ := saveDC.Call(dc)
	if state == 0 {
		return
	}
	defer restoreDC.Call(dc, state)
	var bounds rect
	getClientRect.Call(hwnd, uintptr(unsafe.Pointer(&bounds)))
	if kind == borderEdit || kind == borderList || kind == borderCombo {
		var window rect
		getWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&window)))
		bounds = rect{Right: window.Right - window.Left, Bottom: window.Bottom - window.Top}
		if kind == borderEdit {
			var client rect
			getClientRect.Call(hwnd, uintptr(unsafe.Pointer(&client)))
			user32.NewProc("MapWindowPoints").Call(hwnd, 0, uintptr(unsafe.Pointer(&client)), 2)
			client.Left -= window.Left
			client.Right -= window.Left
			client.Top -= window.Top
			client.Bottom -= window.Top
			excludeClipRect.Call(dc, uintptr(client.Left), uintptr(client.Top), uintptr(client.Right), uintptr(client.Bottom))
			background := uintptr(5)
			if enabled, _, _ := isWindowEnabled.Call(hwnd); enabled == 0 {
				background = 15
			}
			brush := uiBrush(background)
			fillRect.Call(dc, uintptr(unsafe.Pointer(&bounds)), brush)
		}
		if kind == borderCombo {
			drawComboField(hwnd, dc, bounds)
		}
	}
	if kind == borderGroup {
		drawGroupFrame(hwnd, dc, bounds)
		return
	}
	brush := uiBrush(16) // COLOR_3DSHADOW: same color as the original borders.
	frameRect.Call(dc, uintptr(unsafe.Pointer(&bounds)), brush)
}

func controlTextSize(hwnd uintptr, value string) size {
	dc, _, _ := getDC.Call(hwnd)
	if dc == 0 {
		return size{}
	}
	defer releaseDC.Call(hwnd, dc)
	font, _, _ := sendMessage.Call(hwnd, 0x0031, 0, 0)
	previous, _, _ := selectObject.Call(dc, font)
	defer selectObject.Call(dc, previous)
	text, _ := windows.UTF16FromString(value)
	var extent size
	getTextExtentPoint32.Call(dc, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)-1), uintptr(unsafe.Pointer(&extent)))
	return extent
}

type comboInfo struct {
	Size              uint32
	Item, Button      rect
	State             uint32
	Combo, Edit, List uintptr
}

func sizeComboField(hwnd uintptr) {
	info := comboInfo{Size: uint32(unsafe.Sizeof(comboInfo{}))}
	if ok, _, _ := getComboBoxInfo.Call(hwnd, uintptr(unsafe.Pointer(&info))); ok == 0 {
		return
	}
	var bounds rect
	getWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&bounds)))
	extra := bounds.Bottom - bounds.Top - (info.Item.Bottom - info.Item.Top)
	if height := newMetrics().s(24) - extra; height > 0 {
		sendMessage.Call(hwnd, 0x0153, ^uintptr(0), uintptr(height))
	}
	getWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&bounds)))
	sendMessage.Call(hwnd, 0x0153, 0, uintptr(bounds.Bottom-bounds.Top)) // Match dropdown rows to the closed field.
}

func styleComboPopup(hwnd uintptr) {
	info := comboInfo{Size: uint32(unsafe.Sizeof(comboInfo{}))}
	if ok, _, _ := getComboBoxInfo.Call(hwnd, uintptr(unsafe.Pointer(&info))); ok == 0 || info.List == 0 {
		return
	}
	style, _, _ := getWindowLongPtr.Call(info.List, ^uintptr(15)) // GWL_STYLE = -16
	ex, _, _ := getWindowLongPtr.Call(info.List, ^uintptr(19))    // GWL_EXSTYLE = -20
	setWindowLongPtr.Call(info.List, ^uintptr(15), style|wsBorder)
	setWindowLongPtr.Call(info.List, ^uintptr(19), ex&^(wsExClientEdge|wsExWindowEdge))
	_ = setThinBorder(info.List, borderComboList)
}

func drawComboField(hwnd, dc uintptr, bounds rect) {
	enabled, _, _ := isWindowEnabled.Call(hwnd)
	background := uintptr(5)
	if enabled == 0 {
		background = 15
	}
	brush := uiBrush(background)
	fillRect.Call(dc, uintptr(unsafe.Pointer(&bounds)), brush)
	font, _, _ := sendMessage.Call(hwnd, 0x0031, 0, 0)
	if font != 0 {
		selectObject.Call(dc, font)
	}
	colorIndex := uintptr(8)
	if enabled == 0 {
		colorIndex = 17
	}
	color := uiColor(colorIndex)
	setTextColor.Call(dc, color)
	setBkMode.Call(dc, 1)
	padding := newMetrics().s(6)
	textBounds := bounds
	textBounds.Left += padding
	textBounds.Right -= newMetrics().s(20)
	text, err := windows.UTF16FromString(windowText(hwnd))
	if err != nil {
		return
	}
	drawText.Call(dc, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)-1), uintptr(unsafe.Pointer(&textBounds)), 0x8824) // Single line, vertical center, no prefix, ellipsis.
	x, y := bounds.Right-newMetrics().s(10), bounds.Bottom/2
	w, h := newMetrics().s(3), newMetrics().s(2)
	points := [3]point{{x - w, y - h}, {x + w, y - h}, {x, y + h}}
	pen, _, _ := getStockObject.Call(8) // NULL_PEN
	selectObject.Call(dc, pen)
	brush = uiBrush(colorIndex)
	selectObject.Call(dc, brush)
	polygon.Call(dc, uintptr(unsafe.Pointer(&points[0])), 3)
}
