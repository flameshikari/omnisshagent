//go:build windows

package tray

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const signatureClass = "OmniSSHAgentSignatureWindow"
const wmCancelSignature = wmUser + 7
const signatureTimeout = 10 * time.Second

type signatureDialog struct {
	window   uintptr
	token    uintptr
	approved bool
	deadline time.Time
	okButton uintptr
	seconds  int
}

var signatureDialogs sync.Map
var signatureSequence atomic.Uint64
var signatureCallback = windows.NewCallback(signatureWindowProc)

func showSignatureDialog(ctx context.Context, fingerprint, comment string) bool {
	m := newMetrics()
	bold := signatureBoldFont(m.font)
	if bold != 0 {
		defer deleteObject.Call(bold)
	} else {
		bold = m.font
	}
	pad, gap, buttonW, buttonH := m.s(12), m.s(8), m.s(88), m.s(24)
	keyLabel := fingerprint
	if comment != "" {
		keyLabel = comment + " " + fingerprint
	}
	width := measureTextWidth(0, bold, keyLabel) + 2*pad
	window, err := createPopup(signatureClass, "OpenSSHAgent – Confirm Signature", width, m.s(160), 0, signatureCallback)
	if err != nil {
		return false
	}
	d := &signatureDialog{window: window, token: uintptr(signatureSequence.Add(1))}
	signatureDialogs.Store(window, d)
	defer signatureDialogs.Delete(window)
	defer destroyWindow.Call(window)
	text, err := createChild("Static", keyLabel, 0x8C, 0, pad, pad, width-2*pad, m.s(24), window, 0xFFFF)
	if err != nil {
		return false
	}
	setChildFont(text, bold)
	lineH := controlTextSize(text, "Mg").CY
	y := pad
	label := func(value string, id uintptr) bool {
		child, err := createChild("Static", value, 0x408C, 0, pad, y, width-2*pad, lineH, window, id)
		if err != nil {
			return false
		}
		setChildFont(child, m.font)
		y += lineH
		return true
	}
	if !label("Allow one SSH signature with this key?", 2401) {
		return false
	}
	y += gap
	setWindowPos.Call(text, 0, uintptr(pad), uintptr(y), uintptr(width-2*pad), uintptr(lineH), 0x14)
	y += lineH + gap
	if !label("The requesting host cannot be verified by the SSH agent protocol.", 2403) {
		return false
	}
	y += pad
	for index, button := range []struct {
		text  string
		id    uintptr
		style uint32
	}{{"OK (10)", idOK, bsPushButton}, {"Cancel", idCancel, bsDefPushButton}} {
		x := width - pad - buttonW - int32(1-index)*(buttonW+gap)
		child, err := createChild("Button", button.text, button.style|wsTabStop, 0, x, y, buttonW, buttonH, window, button.id)
		if err != nil {
			return false
		}
		setChildFont(child, m.font)
		if button.id == idOK {
			d.okButton = child
		}
	}
	var outer, client rect
	getWindowRect.Call(window, uintptr(unsafe.Pointer(&outer)))
	getClientRect.Call(window, uintptr(unsafe.Pointer(&client)))
	height := y + buttonH + pad
	setWindowPos.Call(window, 0, 0, 0, uintptr(width+outer.Right-outer.Left-client.Right), uintptr(height+outer.Bottom-outer.Top-client.Bottom), 0x16)
	if ctx.Err() != nil {
		return false
	}
	done, stopped := make(chan struct{}), make(chan struct{})
	token := d.token
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			postMessage.Call(window, wmCancelSignature, token, 0)
		case <-done:
		}
	}()
	defer func() { close(done); <-stopped }()
	centerWindow(window)
	setWindowPos.Call(window, ^uintptr(0), 0, 0, 0, 0, 0x13) // Topmost; keep native position and size.
	d.deadline = time.Now().Add(signatureTimeout)
	d.seconds = 10
	if timer, _, _ := user32.NewProc("SetTimer").Call(window, 1, 100, 0); timer == 0 {
		return false
	}
	showWindow.Call(window, swShow)
	cancel, _, _ := user32.NewProc("GetDlgItem").Call(window, idCancel)
	user32.NewProc("SetFocus").Call(cancel)
	foregroundSignatureWindow(window)
	updateWindow.Call(window)
	var msg message
	for d.window != 0 {
		result, _, _ := getMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(result) <= 0 {
			if result == 0 {
				postQuitMessage.Call(0)
			}
			break
		}
		updateFocusCues(&msg)
		if handled, _, _ := isDialogMessage.Call(window, uintptr(unsafe.Pointer(&msg))); handled != 0 {
			continue
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
	return d.approved && ctx.Err() == nil
}

func signatureWindowProc(window uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	value, ok := signatureDialogs.Load(window)
	if ok {
		d := value.(*signatureDialog)
		switch msg {
		case 0x0113: // WM_TIMER
			if wParam == 1 {
				remaining := time.Until(d.deadline)
				if remaining <= 0 {
					destroyWindow.Call(window)
					return 0
				}
				seconds := int((remaining + time.Second - 1) / time.Second)
				if seconds != d.seconds {
					d.seconds = seconds
					setWindowText(d.okButton, fmt.Sprintf("OK (%d)", seconds))
				}
			}
			return 0
		case wmCancelSignature:
			if wParam == d.token {
				destroyWindow.Call(window)
			}
			return 0
		case wmCommand:
			if id := commandID(wParam); id == idOK || id == idCancel {
				d.approved = id == idOK && time.Now().Before(d.deadline)
				destroyWindow.Call(window)
				return 0
			}
		case wmClose:
			destroyWindow.Call(window)
			return 0
		case wmDestroy:
			user32.NewProc("KillTimer").Call(window, 1)
			d.window = 0
			return 0
		case 0x0400: // DM_GETDEFID: Enter defaults to Cancel.
			return 0x534B0000 | idCancel
		}
	}
	result, _, _ := defWindowProc.Call(window, uintptr(msg), wParam, lParam)
	return result
}

func signatureBoldFont(base uintptr) uintptr {
	var font struct {
		Height, Width, Escapement, Orientation, Weight                                              int32
		Italic, Underline, Strikeout, Charset, OutPrecision, ClipPrecision, Quality, PitchAndFamily byte
		Face                                                                                        [32]uint16
	}
	if count, _, _ := gdi32.NewProc("GetObjectW").Call(base, unsafe.Sizeof(font), uintptr(unsafe.Pointer(&font))); count == 0 {
		return 0
	}
	font.Weight = 700
	derived, _, _ := gdi32.NewProc("CreateFontIndirectW").Call(uintptr(unsafe.Pointer(&font)))
	return derived
}

func foregroundSignatureWindow(window uintptr) {
	foreground, _, _ := user32.NewProc("GetForegroundWindow").Call()
	if foreground == window {
		return
	}
	thread, _, _ := user32.NewProc("GetWindowThreadProcessId").Call(foreground, 0)
	current := uintptr(windows.GetCurrentThreadId())
	attach := user32.NewProc("AttachThreadInput")
	if thread != 0 && thread != current {
		if ok, _, _ := attach.Call(current, thread, 1); ok != 0 {
			defer attach.Call(current, thread, 0)
		}
	}
	user32.NewProc("BringWindowToTop").Call(window)
	setForegroundWindow.Call(window)
}
