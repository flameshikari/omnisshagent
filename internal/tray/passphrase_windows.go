//go:build windows

package tray

type passwordDialog struct {
	boldFont, hwnd, edit uintptr
	ok                   bool
	secret               []byte
}

var passwordDlg *passwordDialog

func promptPassphrase(owner uintptr, name, fingerprint string) ([]byte, bool) {
	d := &passwordDialog{}
	passwordDlg = d
	defer func() {
		if passwordDlg == d {
			passwordDlg = nil
		}
	}()
	if err := d.create(owner, name, fingerprint); err != nil {
		showError(owner, err)
		return nil, false
	}
	runModal(owner, d.hwnd)
	if !d.ok {
		clearBytes(d.secret)
		return nil, false
	}
	return d.secret, true
}

func (d *passwordDialog) create(owner uintptr, name, fingerprint string) (err error) {
	m := newMetrics()
	pad, gap, lineH, controlH, buttonW := m.s(12), m.s(8), m.s(20), m.s(24), m.s(88)
	if fingerprint == "" {
		fingerprint = "Fingerprint unavailable for this key format"
	}
	d.boldFont = signatureBoldFont(m.font)
	defer func() {
		if err != nil {
			d.freeFont()
		}
	}()
	bold := d.boldFont
	if bold == 0 {
		bold = m.font
	}
	width := max(measureTextWidth(0, bold, fingerprint)+2*pad, 2*buttonW+2*gap+2*pad+m.s(32))
	editY := pad + lineH + gap
	buttonY := editY + controlH + gap
	hwnd, err := createPopup(passwordClass, "OmniSSHAgent – Passphrase", width, buttonY+controlH+pad, owner, passwordCallback)
	if err != nil {
		d.freeFont()
		return err
	}
	d.hwnd = hwnd
	defer func() {
		if err != nil {
			destroyWindow.Call(hwnd)
		}
	}()
	for _, c := range []struct {
		class, text string
		style, ex   uint32
		x, y, w, h  int32
		id          uintptr
	}{
		{"Static", fingerprint, 0x8C, 0, pad, pad, width - 2*pad, lineH, idPassFingerprint},
		{"Static", name, 0x4282, 0, pad, buttonY, width - 2*pad - 2*buttonW - 2*gap, controlH, idPassFilename},
		{"Edit", "", esAutoHScroll | esPassword | wsTabStop, wsExClientEdge, pad, editY, width - 2*pad, controlH, idPassEdit},
		{"Button", "OK", bsDefPushButton | wsTabStop, 0, width - pad - 2*buttonW - gap, buttonY, buttonW, controlH, idOK},
		{"Button", "Cancel", bsPushButton | wsTabStop, 0, width - pad - buttonW, buttonY, buttonW, controlH, idCancel},
	} {
		child, createErr := createChild(c.class, c.text, c.style, c.ex, c.x, c.y, c.w, c.h, hwnd, c.id)
		if createErr != nil {
			return createErr
		}
		if c.id == idPassFingerprint {
			setChildFont(child, bold)
		} else {
			setChildFont(child, m.font)
		}
		if c.id == idPassEdit {
			d.edit = child
		}
	}
	return nil
}

func (d *passwordDialog) freeFont() {
	if d.boldFont != 0 {
		deleteObject.Call(d.boldFont)
		d.boldFont = 0
	}
}

func (d *passwordDialog) accept() {
	text := windowText(d.edit)
	d.secret = []byte(text)
	d.ok = true
	setWindowText(d.edit, "")
	destroyWindow.Call(d.hwnd)
}

func (d *passwordDialog) cancel() {
	d.ok = false
	setWindowText(d.edit, "")
	destroyWindow.Call(d.hwnd)
}

func passwordWindowProc(window uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	d := passwordDlg
	if d == nil || (d.hwnd != 0 && d.hwnd != window) {
		result, _, _ := defWindowProc.Call(window, uintptr(msg), wParam, lParam)
		return result
	}
	switch msg {
	case 0x0007: // WM_SETFOCUS
		if d.edit != 0 {
			user32.NewProc("SetFocus").Call(d.edit)
		}
		return 0
	case wmCommand:
		switch commandID(wParam) {
		case idOK:
			d.accept()
			return 0
		case idCancel:
			d.cancel()
			return 0
		}
	case wmClose:
		d.cancel()
		return 0
	case wmDestroy:
		d.freeFont()
		d.hwnd = 0
		if passwordDlg == d {
			passwordDlg = nil
		}
		return 0
	}
	result, _, _ := defWindowProc.Call(window, uintptr(msg), wParam, lParam)
	return result
}
