//go:build windows

package tray

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const errorWindowTitle = "OmniSSHAgent – Error"
const wmFlashError = wmUser + 10

type errorDialog struct {
	hwnd    uintptr
	flashed bool
}

func flashError(window uintptr, start bool) {
	info := struct {
		Size                  uint32
		Window                uintptr
		Flags, Count, Timeout uint32
	}{Window: window}
	info.Size = uint32(unsafe.Sizeof(info))
	if start {
		info.Flags = 2
		info.Count = 3
	} // FLASHW_TRAY; three pulses, without changing activation.
	user32.NewProc("FlashWindowEx").Call(uintptr(unsafe.Pointer(&info)))
}

var errorDialogs sync.Map
var errorCallback = windows.NewCallback(errorWindowProc)

func (d *errorDialog) create(owner uintptr, text string) (err error) {
	m := newMetrics()
	pad, gap, buttonW, buttonH := m.s(12), m.s(12), m.s(88), m.s(24)
	width := min(m.s(600), max(m.s(260), measureTextWidth(0, m.font, text)+2*pad))
	bounds := rect{Right: width - 2*pad}
	dc, _, _ := getDC.Call(0)
	if dc != 0 {
		previous, _, _ := selectObject.Call(dc, m.font)
		encoded, _ := windows.UTF16FromString(text)
		drawText.Call(dc, uintptr(unsafe.Pointer(&encoded[0])), uintptr(len(encoded)-1), uintptr(unsafe.Pointer(&bounds)), 0xC10) // Calculate wrapped text, no accelerator prefixes.
		selectObject.Call(dc, previous)
		releaseDC.Call(0, dc)
	}
	measuredH := max(m.s(16), bounds.Bottom)
	textH := max(m.s(20), measuredH)
	buttonY := pad + textH + gap
	hwnd, err := createPopup("OmniSSHAgentErrorWindow", errorWindowTitle, width, buttonY+buttonH+pad, owner, errorCallback)
	if err != nil {
		return err
	}
	d.hwnd = hwnd
	errorDialogs.Store(hwnd, d)
	defer func() {
		if err != nil {
			destroyWindow.Call(hwnd)
		}
	}()
	label, err := createChild("Static", text, 0x81, 0, pad, pad+(textH-measuredH)/2, width-2*pad, measuredH, hwnd, 0xFFFF)
	if err != nil {
		return err
	}
	setChildFont(label, m.font)
	button, err := createChild("Button", "OK", bsDefPushButton|wsTabStop, 0, (width-buttonW)/2, buttonY, buttonW, buttonH, hwnd, idOK)
	if err != nil {
		return err
	}
	setChildFont(button, m.font)
	return nil
}

func errorWindowProc(window uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	if value, ok := errorDialogs.Load(window); ok {
		d := value.(*errorDialog)
		switch msg {
		case 0x0018: // WM_SHOWWINDOW
			if wParam != 0 {
				postMessage.Call(window, wmFlashError, 0, 0)
			}
		case wmFlashError:
			if !d.flashed {
				d.flashed = true
				flashError(window, true)
			}
			return 0
		case wmCommand:
			if id := commandID(wParam); id == idOK || id == idCancel {
				destroyWindow.Call(window)
				return 0
			}
		case wmClose:
			destroyWindow.Call(window)
			return 0
		case wmDestroy:
			flashError(window, false)
			errorDialogs.Delete(window)
			d.hwnd = 0
			return 0
		case 0x0400: // DM_GETDEFID
			return 0x534B0000 | idOK
		}
	}
	result, _, _ := defWindowProc.Call(window, uintptr(msg), wParam, lParam)
	return result
}
