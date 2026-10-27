//go:build windows

package tray

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/masahide/OmniSSHAgent/internal/backend"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	keysClass         = "OmniSSHAgentKeysWindow"
	passwordClass     = "OmniSSHAgentPasswordWindow"
	idKeyList         = 2201
	idAddKey          = 2202
	idRemoveKey       = 2203
	idPassEdit        = 2204
	idRemoveAllKeys   = 2205
	idPassFingerprint = 2206
	idPassFilename    = 2208
	idKeySettings     = 2207
	wmFitKeyColumns   = wmUser + 3
	wmDeleteKeys      = wmUser + 9
)

type keysDialog struct {
	tray           *Tray
	owner          uintptr
	m              metrics
	hwnd           uintptr
	list           uintptr
	backend        backend.Backend
	keys           []*agent.Key
	keySources     map[string]backend.KeySource
	sourceApps     map[string]sourceApp
	sortColumn     int
	descending     bool
	fittingColumns bool
	updatingKeys   bool
	pollResults    chan keySnapshot
	pollPending    bool
	keysRevision   uint64
	changeToken    uintptr
	changePending  atomic.Bool
	stopChanges    func()
	importing      bool
	headerDrag     struct {
		active        bool
		column        int
		startX, width int32
	}
}

var keysDlg *keysDialog

func formatListedKey(k *agent.Key) string {
	if k == nil {
		return ""
	}
	text := k.Type() + " " + ssh.FingerprintSHA256(k)
	if comment := strings.TrimSpace(k.Comment); comment != "" {
		text += " " + comment
	}
	return text
}

func (t *Tray) openKeys(owner uintptr) {
	if keysDlg != nil && keysDlg.hwnd != 0 {
		showWindow.Call(keysDlg.hwnd, 9) // SW_RESTORE
		setForegroundWindow.Call(keysDlg.hwnd)
		return
	}
	b := t.backend()
	if b == nil {
		showError(owner, errors.New("the SSH agent backend is unavailable until the configuration is valid"))
		return
	}
	d := &keysDialog{tray: t, owner: t.window, m: newMetrics(), backend: b}
	keysDlg = d
	if err := d.create(); err != nil {
		keysDlg = nil
		showError(owner, err)
		return
	}
	centerWindow(d.hwnd)
	showWindow.Call(d.hwnd, swShow)
	updateWindow.Call(d.hwnd)
	setForegroundWindow.Call(d.hwnd)
}

func (t *Tray) backend() backend.Backend {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.agent
}

func (t *Tray) SetBackend(b backend.Backend) {
	t.mu.Lock()
	t.agent = b
	window := t.window
	t.mu.Unlock()
	if window != 0 {
		postMessage.Call(window, wmApply, 0, 0)
	}
}

func (d *keysDialog) create() (err error) {
	m := d.m
	pad := m.s(12)
	listH := m.s(240)
	buttonY := pad + listH + m.s(8)
	hwnd, err := createPopup(keysClass, "OpenSSHAgent – Manage Keys", m.s(780), buttonY+m.s(24)+pad, d.owner, keysCallback, wsThickFrame|wsMinimizeBox|wsMaximizeBox|wsClipChildren)
	if err != nil {
		return err
	}
	d.hwnd = hwnd
	defer func() {
		if err != nil {
			d.close()
		}
	}()
	if err = d.createTable(); err != nil {
		return err
	}
	for _, button := range []struct {
		text  string
		id    uintptr
		style uint32
	}{
		{"Add", idAddKey, bsPushButton},
		{"Remove", idRemoveKey, bsPushButton},
		{"Remove All", idRemoveAllKeys, bsPushButton},
		{"Settings", idKeySettings, bsPushButton},
		{"Close", idCancel, bsDefPushButton},
	} {
		if _, err = d.child("Button", button.text, button.style|wsTabStop, 0, 0, 0, m.s(88), m.s(24), button.id); err != nil {
			return err
		}
	}
	d.updateRemoveButtons()
	d.layout()
	if err := d.startLiveUpdates(); err != nil {
		return err
	}
	if err := d.refresh(); err != nil {
		showError(d.hwnd, err)
	}
	if err := d.acceptFileDrops(); err != nil {
		return err
	}
	return nil
}

func (d *keysDialog) child(class, title string, style, ex uint32, x, y, w, h int32, id uintptr) (uintptr, error) {
	hwnd, err := createChild(class, title, style, ex, x, y, w, h, d.hwnd, id)
	if err != nil {
		return 0, err
	}
	setChildFont(hwnd, d.m.font)
	return hwnd, nil
}

func (d *keysDialog) refresh() error {
	d.keysRevision++ // Discard any background result predating a manual change.
	keys, err := d.backend.List()
	if err != nil {
		return err
	}
	return d.replaceKeys(keys)
}

func (d *keysDialog) add() {
	initialDir := os.Getenv("USERPROFILE")
	if initialDir != "" {
		initialDir = filepath.Join(initialDir, ".ssh")
	}
	path, ok := pickOpenFile(
		d.hwnd,
		"Add private key",
		initialDir,
		"",
		[]string{"Private key files", "*.*", "All files", "*.*"},
		true,
	)
	if !ok {
		return
	}
	d.addPaths([]string{path})
}

func (d *keysDialog) addPaths(paths []string) {
	if d.importing {
		return
	}
	d.importing = true
	defer func() { d.importing = false }()
	var failures []error
	for _, path := range paths {
		if d.hwnd == 0 {
			return
		}
		err := addKeyFromFile(d.backend, path, func(fingerprint string) ([]byte, bool) {
			return promptPassphrase(d.hwnd, filepath.Base(path), fingerprint)
		})
		if err != nil && !errors.Is(err, errDialogCanceled) {
			failures = append(failures, err)
		}
	}
	if d.hwnd == 0 {
		return
	}
	if err := errors.Join(errors.Join(failures...), d.refresh()); err != nil {
		showError(d.hwnd, err)
	}
}

func (d *keysDialog) remove() {
	keys := d.selectedKeys()
	if len(keys) == 0 {
		showError(d.hwnd, errors.New("select one or more keys to remove"))
		return
	}
	var failures []error
	for _, key := range keys {
		if err := d.backend.Remove(key); err != nil {
			failures = append(failures, err)
		}
	}
	if err := d.refresh(); err != nil {
		failures = append(failures, err)
	}
	if err := errors.Join(failures...); err != nil {
		showError(d.hwnd, err)
	}
}

func (d *keysDialog) removeAll() {
	err := d.backend.RemoveAll()
	if err := errors.Join(err, d.refresh()); err != nil {
		showError(d.hwnd, err)
	}
}

func (d *keysDialog) close() {
	if d.hwnd != 0 {
		destroyWindow.Call(d.hwnd)
	}
}

func keysWindowProc(window uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	d := keysDlg
	if d == nil || (d.hwnd != 0 && d.hwnd != window) {
		result, _, _ := defWindowProc.Call(window, uintptr(msg), wParam, lParam)
		return result
	}
	switch msg {
	case wmDeleteKeys:
		if len(d.selectedKeys()) != 0 {
			d.remove()
		}
		return 0
	case wmDropFiles:
		d.addPaths(droppedFiles(wParam))
		return 0
	case wmKeysChanged:
		if wParam == d.changeToken {
			d.changePending.Store(false)
			_ = d.refresh()
		}
		return 0
	case 0x002C: // WM_MEASUREITEM
		if measureControlItem(lParam, d.m.s(18), 102) {
			return 1
		}
	case 0x002B: // WM_DRAWITEM
		if d.drawKeyRow(lParam) {
			return 1
		}
	case 0x0113: // WM_TIMER
		if wParam == 1 && d.pollResults != nil {
			d.pollKeys()
		}
		return 0
	case wmFitKeyColumns:
		d.fitColumns()
		return 0
	case 0x0005: // WM_SIZE
		if wParam != 1 { // SIZE_MINIMIZED
			d.layout()
		}
		return 0
	case 0x0024: // WM_GETMINMAXINFO
		d.setMinimumSize(lParam)
		return 0
	case 0x004E: // WM_NOTIFY
		d.tableNotification(lParam)
		return 0
	case wmCommand:
		switch commandID(wParam) {
		case idAddKey:
			d.add()
			return 0
		case idRemoveKey:
			d.remove()
			return 0
		case idKeySettings:
			d.tray.openSettings()
			return 0
		case idRemoveAllKeys:
			d.removeAll()
			return 0
		case idCancel, idOK:
			d.close()
			return 0
		}
	case wmClose:
		d.close()
		return 0
	case wmDestroy:
		d.clearSourceApps()
		if d.stopChanges != nil {
			d.stopChanges()
			d.stopChanges = nil
		}
		user32.NewProc("KillTimer").Call(window, 1)
		d.hwnd = 0
		if keysDlg == d {
			keysDlg = nil
		}
		return 0
	}
	result, _, _ := defWindowProc.Call(window, uintptr(msg), wParam, lParam)
	return result
}
