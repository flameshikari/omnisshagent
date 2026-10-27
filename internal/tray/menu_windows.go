//go:build windows

package tray

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func menuEntryFor(id uint32) (menuEntry, bool) {
	for _, entry := range requiredMenuEntries() {
		if uint32(entry.id) == id {
			return entry, true
		}
	}
	return menuEntry{}, false
}

func styleTrayMenu(menu uintptr) error {
	info := struct {
		Size, Mask, Style, MaxHeight uint32
		Background                   uintptr
		Help                         uint32
		Data                         uintptr
	}{Mask: 0x10, Style: 0x84000000} // MIM_STYLE; MNS_NOCHECK | MNS_CHECKORBMP.
	info.Size = uint32(unsafe.Sizeof(info))
	if ok, _, err := user32.NewProc("SetMenuInfo").Call(menu, uintptr(unsafe.Pointer(&info))); ok == 0 {
		return winErr(err)
	}
	for _, entry := range requiredMenuEntries() {
		item := struct {
			Size, Mask, Type, State, ID             uint32
			Submenu, Checked, Unchecked, Data, Text uintptr
			TextLength                              uint32
			Bitmap                                  uintptr
		}{Mask: 0x100, Type: 0x100} // MIIM_FTYPE; MFT_OWNERDRAW. Retain the stored label.
		item.Size = uint32(unsafe.Sizeof(item))
		if ok, _, err := user32.NewProc("SetMenuItemInfoW").Call(menu, entry.id, 0, uintptr(unsafe.Pointer(&item))); ok == 0 {
			return winErr(err)
		}
	}
	return nil
}

func measureTrayMenuItem(address uintptr) bool {
	var item struct {
		Type, ID, Item, Width, Height uint32
		Data                          uintptr
	}
	var copied uintptr
	if address == 0 || windows.ReadProcessMemory(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&item)), unsafe.Sizeof(item), &copied) != nil || item.Type != 1 {
		return false
	}
	entry, ok := menuEntryFor(item.Item)
	if !ok {
		return false
	}
	m := newMetrics()
	item.Width = uint32(measureTextWidth(0, m.font, entry.text) + m.s(40))
	item.Height = uint32(m.s(24))
	return windows.WriteProcessMemory(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&item)), unsafe.Sizeof(item), &copied) == nil
}

func drawTrayMenuItem(address uintptr) bool {
	var item struct {
		Type, ID, Item, Action, State uint32
		Window, DC                    uintptr
		Bounds                        rect
		Data                          uintptr
	}
	var copied uintptr
	if address == 0 || windows.ReadProcessMemory(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&item)), unsafe.Sizeof(item), &copied) != nil || item.Type != 1 {
		return false
	}
	entry, ok := menuEntryFor(item.Item)
	if !ok {
		return false
	}
	saved, _, _ := saveDC.Call(item.DC)
	defer restoreDC.Call(item.DC, saved)
	brush := uiBrush(4) // COLOR_MENU.
	fillRect.Call(item.DC, uintptr(unsafe.Pointer(&item.Bounds)), brush)
	foreground := uintptr(7) // COLOR_MENUTEXT.
	color := uiColor(foreground)
	if item.State&1 != 0 {
		background, selectedText := menuSelectionColors(currentUITheme().dark, uiColor(4), uiColor(7), uiColor(29), uiColor(14))
		solid, _, _ := gdi32.NewProc("CreateSolidBrush").Call(background)
		if solid != 0 {
			fillRect.Call(item.DC, uintptr(unsafe.Pointer(&item.Bounds)), solid)
			deleteObject.Call(solid)
		}
		color = selectedText
	}

	setTextColor.Call(item.DC, color)
	setBkMode.Call(item.DC, 1)
	m := newMetrics()
	family, _ := windows.UTF16PtrFromString("Segoe MDL2 Assets")
	iconSize := int32(16)
	if entry.id == menuQuit {
		iconSize = 12
	}
	font, _, _ := createFont.Call(uintptr(-int64(m.s(iconSize))), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, uintptr(unsafe.Pointer(family)))
	if font != 0 {
		selectObject.Call(item.DC, font)
		glyph := map[uintptr]uint16{menuManageKeys: 0xE192, menuSettings: 0xE713, menuRemoveAllKeys: 0xE74D, menuQuit: 0xE8BB}[entry.id]
		iconBounds := item.Bounds
		iconBounds.Left += m.s(6)
		iconBounds.Right = iconBounds.Left + m.s(16)
		drawText.Call(item.DC, uintptr(unsafe.Pointer(&glyph)), 1, uintptr(unsafe.Pointer(&iconBounds)), 0x825)
		selectObject.Call(item.DC, m.font)
		deleteObject.Call(font)
	} else {
		selectObject.Call(item.DC, m.font)
	}
	label, _ := windows.UTF16FromString(entry.text)
	bounds := item.Bounds
	bounds.Left += m.s(30)
	bounds.Right -= m.s(6)
	drawText.Call(item.DC, uintptr(unsafe.Pointer(&label[0])), uintptr(len(label)-1), uintptr(unsafe.Pointer(&bounds)), 0x824)
	return true
}

func menuSelectionColors(dark bool, background, text, highlight, highlightText uintptr) (uintptr, uintptr) {
	if !dark {
		return highlight, highlightText
	}
	// Patched themes can provide light-menu highlight text. Blend a dark hot row
	// from the actual menu palette and retain its readable foreground instead.
	blend := func(shift uint) uintptr { return (((background>>shift)&255)*88 + ((text>>shift)&255)*12) / 100 }
	return blend(0) | blend(8)<<8 | blend(16)<<16, text
}
