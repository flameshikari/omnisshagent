//go:build windows

package tray

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

type hoverTip struct {
	window uintptr
	text   *uint16 // Keep the text alive while the native tooltip references it.
}

type tooltipInfo struct {
	Size, Flags uint32
	Window, ID  uintptr
	Bounds      rect
	Instance    uintptr
	Text        *uint16
	Param       uintptr
}

func newHoverTip(owner, target uintptr, text string, width int32) (*hoverTip, error) {
	init := struct{ Size, Classes uint32 }{8, 0xFF} // ICC_WIN95_CLASSES includes tooltips.
	if ok, _, err := comctl32.NewProc("InitCommonControlsEx").Call(uintptr(unsafe.Pointer(&init))); ok == 0 {
		return nil, winErr(err)
	}
	value, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return nil, err
	}
	class, _ := windows.UTF16PtrFromString("tooltips_class32")
	window, _, err := createWindow.Call(8, uintptr(unsafe.Pointer(class)), 0, wsPopup|3, 0, 0, 0, 0, owner, 0, 0, 0) // Topmost, always-tip, no prefix.
	if window == 0 {
		return nil, winErr(err)
	}
	if err := installUITheme(window, themeTooltip); err != nil {
		destroyWindow.Call(window)
		return nil, err
	}
	tip := &hoverTip{window: window, text: value}
	info := tooltipInfo{Size: uint32(unsafe.Sizeof(tooltipInfo{})), Flags: 0x11, Window: owner, ID: target, Text: value} // V2 TOOLINFO; TTF_IDISHWND | TTF_SUBCLASS.
	if ok, _, _ := sendMessage.Call(window, 0x0432, 0, uintptr(unsafe.Pointer(&info))); ok == 0 {                        // TTM_ADDTOOLW
		destroyWindow.Call(window)
		return nil, errors.New("could not register tooltip")
	}
	sendMessage.Call(window, 0x0418, 0, uintptr(width)) // TTM_SETMAXTIPWIDTH enables multiline text.
	tip.setEnabled(false)
	return tip, nil
}

func (tip *hoverTip) setEnabled(enabled bool) {
	if tip == nil {
		return
	}
	var active uintptr
	if enabled {
		active = 1
	}
	sendMessage.Call(tip.window, 0x0401, active, 0) // TTM_ACTIVATE
}
