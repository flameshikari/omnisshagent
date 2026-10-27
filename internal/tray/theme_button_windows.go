//go:build windows

package tray

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func buttonVisualMessage(msg uint32) bool {
	switch msg {
	case wmSetText, wmSetFont, 0x0007, 0x0008, 0x000A, 0x00F1, 0x00F3, 0x00F4, 0x0128, 0x0200, 0x0201, 0x0202, 0x02A3:
		return true
	}
	return false
}

func themeButtonMessage(window uintptr, msg uint32, wParam uintptr) (bool, uintptr) {
	paint := func(dc uintptr) { paintBufferedControl(window, dc, drawThemeButton) }
	switch msg {
	case 0x0014:
		return true, 1
	case 0x000F:
		var state controlPaintState
		dc, _, _ := user32.NewProc("BeginPaint").Call(window, uintptr(unsafe.Pointer(&state)))
		if dc != 0 {
			paint(dc)
		}
		user32.NewProc("EndPaint").Call(window, uintptr(unsafe.Pointer(&state)))
		return true, 0
	case 0x0317, 0x0318:
		if wParam != 0 {
			paint(wParam)
		}
		return true, 0
	}
	return false, 0
}

func drawThemeButton(window, dc uintptr, bounds rect) {
	style, _, _ := getWindowLongPtr.Call(window, ^uintptr(15))
	kind := style & 15
	fillRect.Call(dc, uintptr(unsafe.Pointer(&bounds)), uiBrush(15))
	if kind == bsGroupBox {
		drawGroupFrame(window, dc, bounds)
		return
	}
	enabled, _, _ := isWindowEnabled.Call(window)
	state, _, _ := sendMessage.Call(window, 0x00F2, 0, 0)
	color := uintptr(18)
	if enabled == 0 {
		color = 17
	}
	font, _, _ := sendMessage.Call(window, 0x0031, 0, 0)
	if font != 0 {
		selectObject.Call(dc, font)
	}
	setTextColor.Call(dc, uiColor(color))
	setBkMode.Call(dc, 1)
	m := newMetrics()
	textBounds := bounds
	flags := uintptr(0x825)
	if kind == bsAutoCheckBox {
		box := rect{Left: 0, Right: m.s(13), Top: (bounds.Bottom - m.s(13)) / 2}
		box.Bottom = box.Top + m.s(13)
		fillRect.Call(dc, uintptr(unsafe.Pointer(&box)), uiBrush(5))
		checked, _, _ := sendMessage.Call(window, bmGetCheck, 0, 0)
		if checked != 0 {
			fillRect.Call(dc, uintptr(unsafe.Pointer(&box)), uiBrush(13))
			pen, _, _ := gdi32.NewProc("CreatePen").Call(0, uintptr(max(1, m.s(2))), uiColor(14))
			if pen != 0 {
				previous, _, _ := selectObject.Call(dc, pen)
				pts := [3]point{{box.Left + m.s(3), box.Top + m.s(6)}, {box.Left + m.s(5), box.Top + m.s(9)}, {box.Left + m.s(10), box.Top + m.s(3)}}
				gdi32.NewProc("Polyline").Call(dc, uintptr(unsafe.Pointer(&pts[0])), 3)
				selectObject.Call(dc, previous)
				deleteObject.Call(pen)
			}
		} else {
			frameRect.Call(dc, uintptr(unsafe.Pointer(&box)), uiBrush(16))
		}
		textBounds.Left = box.Right + m.s(4)
		flags = 0x824
	} else {
		brush := uiBrush(22)
		if enabled != 0 && state&4 != 0 {
			brush = uiBrush(16)
		} else if enabled != 0 && state&0x200 != 0 {
			brush = uiBrush(29)
		}
		fillRect.Call(dc, uintptr(unsafe.Pointer(&bounds)), brush)
		frameRect.Call(dc, uintptr(unsafe.Pointer(&bounds)), uiBrush(16))
	}
	text, _ := windows.UTF16FromString(windowText(window))
	drawText.Call(dc, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)-1), uintptr(unsafe.Pointer(&textBounds)), flags)
	if state&8 != 0 {
		if cues, _, _ := sendMessage.Call(window, 0x0129, 0, 0); cues&1 == 0 {
			textBounds.Left += m.s(3)
			textBounds.Right -= m.s(3)
			textBounds.Top += m.s(3)
			textBounds.Bottom -= m.s(3)
			user32.NewProc("DrawFocusRect").Call(dc, uintptr(unsafe.Pointer(&textBounds)))
		}
	}
}
