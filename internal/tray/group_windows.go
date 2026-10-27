//go:build windows

package tray

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func drawGroupFrame(hwnd, dc uintptr, bounds rect) {
	font, _, _ := sendMessage.Call(hwnd, 0x0031, 0, 0)
	if font != 0 {
		selectObject.Call(dc, font)
	}
	text, _ := windows.UTF16FromString(strings.TrimSpace(windowText(hwnd)))
	var extent size
	getTextExtentPoint32.Call(dc, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)-1), uintptr(unsafe.Pointer(&extent)))
	band := rect{Right: bounds.Right, Bottom: extent.CY}
	background := uiBrush(15)
	fillRect.Call(dc, uintptr(unsafe.Pointer(&band)), background)
	padding := newMetrics().s(4)
	caption := rect{Left: newMetrics().s(12), Bottom: extent.CY}
	caption.Right = caption.Left + extent.CX
	bounds.Top = extent.CY / 2
	state, _, _ := saveDC.Call(dc)
	excludeClipRect.Call(dc, uintptr(caption.Left-padding), 0, uintptr(caption.Right+padding), uintptr(extent.CY))
	border := uiBrush(16)
	frameRect.Call(dc, uintptr(unsafe.Pointer(&bounds)), border)
	restoreDC.Call(dc, state)
	color := uiColor(18)
	setTextColor.Call(dc, color)
	setBkMode.Call(dc, 1)
	drawText.Call(dc, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)-1), uintptr(unsafe.Pointer(&caption)), 0x0820) // Single line, no mnemonic prefix.
}
