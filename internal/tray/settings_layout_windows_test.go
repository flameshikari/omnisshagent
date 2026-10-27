//go:build windows

package tray

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"github.com/masahide/OmniSSHAgent/internal/config"
	"golang.org/x/sys/windows"
)

func TestSettingsLayout(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := config.Default()
	cfg.Backend.Type = config.BackendEmbedded
	cfg.KeePassXC.Enabled = true
	cfg.KeePassXC.Database = `C:\Secrets\layout.kdbx`
	cfg.KeePassXC.Executable = `B:\Programs\KeePassXC\KeePassXC.exe`
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	d := &settingsDialog{tray: New(path, t.TempDir(), func() {}), m: newMetrics()}
	previous := settingsDlg
	settingsDlg = d
	defer func() { settingsDlg = previous }()
	if err := d.create(0); err != nil {
		t.Fatal(err)
	}
	defer d.close()
	assertTaskbarIcon(t, d.hwnd)
	previousConfig := openConfiguration
	var openedConfig string
	openConfiguration = func(path string) error { openedConfig = path; return nil }
	defer func() { openConfiguration = previousConfig }()
	sendMessage.Call(d.hwnd, wmCommand, idOpenConfig, 0)
	if openedConfig != path {
		t.Fatalf("Open Config opened %q instead of %q", openedConfig, path)
	}
	openConfig, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, idOpenConfig)
	if windowText(openConfig) != "Open Config" {
		t.Fatal("Settings footer still exposes Manage Keys")
	}
	previousOpen := openPath
	var opened []string
	openPath = func(path string) error { opened = append(opened, path); return nil }
	defer func() { openPath = previousOpen }()
	sendMessage.Call(d.hwnd, wmCommand, idConfigDirectory, 0)
	sendMessage.Call(d.hwnd, wmCommand, idLogsDirectory, 0)
	if len(opened) != 2 || opened[0] != filepath.Dir(path) || opened[1] != d.tray.logDirectory {
		t.Fatalf("directory buttons opened %v", opened)
	}
	getChild := user32.NewProc("GetDlgItem")
	bounds := func(id uintptr) rect {
		t.Helper()
		hwnd, _, _ := getChild.Call(d.hwnd, id)
		if hwnd == 0 {
			t.Fatalf("missing settings control %d", id)
		}
		var r rect
		if ok, _, err := getWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r))); ok == 0 {
			t.Fatal(err)
		}
		return r
	}
	compat, backend, keepass, app := bounds(idGroupCompat), bounds(idGroupBackend), bounds(idGroupMiddleware), bounds(idGroupApp)
	for _, r := range []rect{backend, keepass, app} {
		if r.Left != compat.Left || r.Right != compat.Right {
			t.Fatal("section frames are not aligned")
		}
	}
	if backend.Bottom >= compat.Top || compat.Bottom >= keepass.Top || keepass.Bottom >= app.Top {
		t.Fatal("sections overlap")
	}
	manage, ok, cancel, apply := bounds(idOpenConfig), bounds(idOK), bounds(idCancel), bounds(idApply)
	if apply.Top <= app.Bottom {
		t.Fatal("footer crosses section frame")
	}
	if manage.Left != compat.Left || apply.Right != compat.Right {
		t.Fatal("footer buttons are not aligned with sections")
	}
	if ok.Top != apply.Top || cancel.Top != apply.Top || manage.Top != apply.Top || ok.Bottom != apply.Bottom || cancel.Bottom != apply.Bottom {
		t.Fatal("footer buttons are not on the same row")
	}
	if abs(int64(cancel.Left-ok.Right)-int64(apply.Left-cancel.Right)) > 1 || abs(int64(ok.Right-ok.Left)-int64(apply.Right-apply.Left)) > 1 {
		t.Fatal("footer button spacing or widths differ")
	}
	configButton := bounds(idConfigDirectory)
	if abs(int64(configButton.Right-manage.Left)-int64(apply.Right-ok.Left)) > 1 || abs(int64(manage.Right-manage.Left)-int64(configButton.Right-configButton.Left)) > 1 {
		t.Fatal("footer is not split evenly between the two button groups")
	}
	socket, pathBox, socketBrowse, pathBrowse := bounds(idSocket), bounds(idMiddlewarePath), bounds(idBrowse), bounds(idMiddlewareBrowse)
	if socket.Right != pathBox.Right || socketBrowse.Left != pathBrowse.Left || socketBrowse.Right != pathBrowse.Right {
		t.Fatal("path fields and Browse buttons are not aligned")
	}
	if label := bounds(idSocketLabel); socket.Left-label.Right != socketBrowse.Left-socket.Right {
		t.Fatal("socket field does not use the space after its label with equal gaps")
	}
	if pageant, cygwin := bounds(idPageant), bounds(idCygwin); pageant.Top != cygwin.Top || pageant.Right >= cygwin.Left {
		t.Fatal("interface checkboxes do not share a row")
	}
	if pathBrowse.Top != pathBox.Top || pathBrowse.Bottom != pathBox.Bottom {
		t.Fatal("KeePassXC Browse is not aligned with its field")
	}
	group, _, _ := getChild.Call(d.hwnd, idGroupMiddleware)
	if windowText(group) != " Middleware " || windowText(d.middlewareEnabled) != "Enabled" {
		t.Fatal("middleware group or master checkbox label is wrong")
	}
	master, program := bounds(idMiddlewareEnabled), bounds(idMiddlewareProgram)
	if master.Top != program.Top || program.Left-master.Right != d.m.s(8) || program.Right != socketBrowse.Right {
		t.Fatal("middleware master and program selector are not aligned")
	}
	if comboIndex(d.middlewareProgram) != 0 || d.middlewareCurrent != config.MiddlewareKeePassXC {
		t.Fatal("KeePassXC is not selected")
	}
	databaseBox, databaseBrowse := bounds(idMiddlewareDatabase), bounds(idMiddlewareDatabaseBrowse)
	if databaseBox.Left != pathBox.Left || databaseBox.Right != pathBox.Right || databaseBrowse.Left != pathBrowse.Left || databaseBrowse.Right != pathBrowse.Right {
		t.Fatal("Executable and Database fields are not aligned")
	}
	start := bounds(idMiddlewareStart)
	if start.Bottom >= pathBox.Top || pathBox.Bottom >= databaseBox.Top {
		t.Fatal("path rows are not under Start program in order")
	}
	if bounds(idMiddlewareExecutableEnabled).Top != pathBox.Top || bounds(idMiddlewareDatabaseEnabled).Top != databaseBox.Top {
		t.Fatal("path checkboxes are not aligned with their inputs")
	}
	executablePath := windowText(d.middlewarePath)
	databasePath := windowText(d.middlewareDatabase)
	sendMessage.Call(d.middlewareEnabled, 0x00F5, 0, 0)
	for _, window := range []uintptr{d.middlewareProgram, d.middlewareUnlock, d.middlewareStart, d.middlewarePath, d.middlewareBrowse, d.middlewareExecutableEnabled, d.middlewareDatabaseEnabled, d.middlewareDatabase, d.middlewareDatabaseBrowse} {
		if enabled, _, _ := isWindowEnabled.Call(window); enabled != 0 {
			t.Fatal("master switch left a middleware control enabled")
		}
	}
	if enabled, _, _ := isWindowEnabled.Call(d.middlewareEnabled); enabled == 0 {
		t.Fatal("master checkbox disabled itself")
	}
	sendMessage.Call(d.middlewareEnabled, 0x00F5, 0, 0)
	if windowText(d.middlewarePath) != executablePath {
		t.Fatal("disabling middleware erased the executable path")
	}
	sendMessage.Call(d.middlewareStart, 0x00F5, 0, 0) // Disable startup and both path rows.
	for _, window := range []uintptr{d.middlewareExecutableEnabled, d.middlewareDatabaseEnabled, d.middlewarePath, d.middlewareBrowse, d.middlewareDatabase, d.middlewareDatabaseBrowse} {
		if enabled, _, _ := isWindowEnabled.Call(window); enabled != 0 {
			t.Fatal("startup switch left a path checkbox/input/Browse enabled")
		}
	}
	sendMessage.Call(d.middlewareStart, 0x00F5, 0, 0)
	if windowText(d.middlewarePath) != executablePath || windowText(d.middlewareDatabase) != databasePath {
		t.Fatal("startup switch lost a remembered path")
	}
	sendMessage.Call(d.middlewareExecutableEnabled, 0x00F5, 0, 0)
	if enabled, _, _ := isWindowEnabled.Call(d.middlewarePath); enabled != 0 {
		t.Fatal("unchecked Executable left its input active")
	}
	if enabled, _, _ := isWindowEnabled.Call(d.middlewareDatabase); enabled == 0 {
		t.Fatal("Executable checkbox changed Database state")
	}
	sendMessage.Call(d.middlewareExecutableEnabled, 0x00F5, 0, 0)
	sendMessage.Call(d.middlewareDatabaseEnabled, 0x00F5, 0, 0)
	for _, window := range []uintptr{d.middlewareDatabase, d.middlewareDatabaseBrowse} {
		if enabled, _, _ := isWindowEnabled.Call(window); enabled != 0 {
			t.Fatal("unchecked Database left a control active")
		}
	}
	if windowText(d.middlewareDatabase) != databasePath {
		t.Fatal("Database checkbox erased its path")
	}
	sendMessage.Call(d.middlewareDatabaseEnabled, 0x00F5, 0, 0)
	if enabled, _, _ := isWindowEnabled.Call(d.middlewareDatabase); enabled == 0 {
		t.Fatal("Database toggle did not restore its path")
	}
	var client rect
	user32.NewProc("GetClientRect").Call(d.hwnd, uintptr(unsafe.Pointer(&client)))
	user32.NewProc("MapWindowPoints").Call(d.hwnd, 0, uintptr(unsafe.Pointer(&client)), 2)
	if client.Bottom-apply.Bottom != d.m.s(12) {
		t.Fatal("excess bottom space or clipped footer")
	}
	// Styling must preserve native editing and dropdown interaction.
	showWindow.Call(d.hwnd, swShow)
	var editWindow, editClient rect
	getWindowRect.Call(d.socket, uintptr(unsafe.Pointer(&editWindow)))
	getClientRect.Call(d.socket, uintptr(unsafe.Pointer(&editClient)))
	user32.NewProc("MapWindowPoints").Call(d.socket, 0, uintptr(unsafe.Pointer(&editClient)), 2)
	if editClient.Left-editWindow.Left != 1 || editWindow.Right-editClient.Right != 1 {
		t.Fatalf("edit client painting overlaps side borders: window=%+v client=%+v", editWindow, editClient)
	}
	original := windowText(d.socket)
	setWindowText(d.socket, "test")
	sendMessage.Call(d.socket, 0x00B1, 4, 4)   // EM_SETSEL: append.
	sendMessage.Call(d.socket, 0x0102, 'x', 1) // WM_CHAR
	if windowText(d.socket) != "testx" {
		t.Fatalf("styled edit rejected native text input: %q", windowText(d.socket))
	}
	setWindowText(d.socket, original)
	comboSelect(d.backendType, 0)
	d.updateBackendControls()
	originalTimeout := windowText(d.timeout)
	setWindowText(d.timeout, "12s3")
	if windowText(d.timeout) != "123" || d.values().ConnectTimeout != "123s" {
		t.Fatal("timeout did not restrict input to seconds")
	}
	sendMessage.Call(d.timeout, 0x00B1, 0, ^uintptr(0)) // Select all.
	pasted, _ := windows.UTF16PtrFromString("45678s")
	sendMessage.Call(d.timeout, 0x00C2, 1, uintptr(unsafe.Pointer(pasted))) // EM_REPLACESEL: paste-like insertion.
	if windowText(d.timeout) != "4567" {
		t.Fatalf("timeout accepted invalid or oversized input: %q", windowText(d.timeout))
	}
	setWindowText(d.timeout, originalTimeout)
	if d.values().ConnectTimeout != cfg.Backend.ConnectTimeout {
		t.Fatal("unchanged timeout modified the config duration")
	}
	if windowText(d.logLevel) != "Info" {
		t.Fatal("log level label was not capitalized")
	}
	user32.NewProc("SetFocus").Call(d.logLevel)
	sendMessage.Call(d.hwnd, wmCommand, idLogLevel|9<<16, d.logLevel) // CBN_SELENDOK
	var focusMessage message
	if queued, _, _ := user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&focusMessage)), d.hwnd, wmReleaseComboFocus, wmReleaseComboFocus, 1); queued == 0 {
		t.Fatal("confirmed combo selection did not schedule focus release")
	} else {
		dispatchMessage.Call(uintptr(unsafe.Pointer(&focusMessage)))
	}
	if focus, _, _ := user32.NewProc("GetFocus").Call(); focus == d.logLevel {
		t.Fatal("combo retained focus after selection")
	}
	showWindow.Call(d.hwnd, swShow)
	sendMessage.Call(d.backendType, 0x014F, 1, 0) // CB_SHOWDROPDOWN
	info := comboInfo{Size: uint32(unsafe.Sizeof(comboInfo{}))}
	getComboBoxInfo.Call(d.backendType, uintptr(unsafe.Pointer(&info)))
	if visible, _, _ := user32.NewProc("IsWindowVisible").Call(info.List); visible == 0 {
		t.Fatal("styled combo did not open its dropdown")
	}
	var comboBounds, popupBounds rect
	getWindowRect.Call(d.backendType, uintptr(unsafe.Pointer(&comboBounds)))
	getWindowRect.Call(info.List, uintptr(unsafe.Pointer(&popupBounds)))
	if popupBounds.Top != comboBounds.Bottom-1 {
		t.Fatalf("dropdown should overlap the field border by one pixel: field=%+v popup=%+v", comboBounds, popupBounds)
	}
	if target := os.Getenv("OMNI_COMBO_PREVIEW"); target != "" {
		saveSettingsPreview(t, info.List, target)
	}
	comboSelect(d.backendType, 0)
	if windowText(d.backendType) != backendOptions[0].label {
		t.Fatal("styled combo did not change selection")
	}
	sendMessage.Call(d.backendType, 0x014F, 0, 0)
	sendMessage.Call(d.backendType, 0x014F, 1, 0)
	var reopened rect
	getWindowRect.Call(info.List, uintptr(unsafe.Pointer(&reopened)))
	if reopened.Top != popupBounds.Top {
		t.Fatalf("dropdown moves on reopening: first=%+v reopened=%+v", popupBounds, reopened)
	}
	sendMessage.Call(d.backendType, 0x014F, 0, 0)
	comboSelect(d.backendType, 1)
	d.updateBackendControls()
	if target := os.Getenv("OMNI_SETTINGS_PREVIEW"); target != "" {
		showWindow.Call(d.hwnd, swShow)
		updateWindow.Call(d.hwnd)
		saveSettingsPreview(t, d.hwnd, target)
	}
	if target := os.Getenv("OMNI_KEYS_PREVIEW"); target != "" {
		b, err := embedded.New()
		if err != nil {
			t.Fatal(err)
		}
		keys := &keysDialog{tray: d.tray, m: d.m, backend: b}
		previousKeys := keysDlg
		keysDlg = keys
		defer func() { keysDlg = previousKeys }()
		if err := keys.create(); err != nil {
			t.Fatal(err)
		}
		defer keys.close()
		showWindow.Call(keys.hwnd, swShow)
		updateWindow.Call(keys.hwnd)
		user32.NewProc("RedrawWindow").Call(keys.hwnd, 0, 0, 0x181)
		saveSettingsPreview(t, keys.hwnd, target)
	}
}

func saveSettingsPreview(t *testing.T, hwnd uintptr, path string) {
	t.Helper()
	// Let native child controls finish their initial paint before PrintWindow.
	time.Sleep(30 * time.Millisecond)
	var msg message
	for {
		pending, _, _ := user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1)
		if pending == 0 {
			break
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
	user32.NewProc("RedrawWindow").Call(hwnd, 0, 0, 0x585)
	var r rect
	getWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	w, h := r.Right-r.Left, r.Bottom-r.Top
	dc, _, _ := getDC.Call(hwnd)
	defer releaseDC.Call(hwnd, dc)
	memory, _, _ := gdi32.NewProc("CreateCompatibleDC").Call(dc)
	defer gdi32.NewProc("DeleteDC").Call(memory)
	bitmap, _, _ := gdi32.NewProc("CreateCompatibleBitmap").Call(dc, uintptr(w), uintptr(h))
	defer gdi32.NewProc("DeleteObject").Call(bitmap)
	previous, _, _ := selectObject.Call(memory, bitmap)
	if result, _, err := user32.NewProc("PrintWindow").Call(hwnd, memory, 2); result == 0 {
		t.Fatal(err)
	}
	selectObject.Call(memory, previous)
	info := make([]byte, 40)
	binary.LittleEndian.PutUint32(info, 40)
	binary.LittleEndian.PutUint32(info[4:], uint32(w))
	binary.LittleEndian.PutUint32(info[8:], uint32(-h))
	binary.LittleEndian.PutUint16(info[12:], 1)
	binary.LittleEndian.PutUint16(info[14:], 32)
	pixels := make([]byte, int(w*h*4))
	if result, _, err := gdi32.NewProc("GetDIBits").Call(memory, bitmap, 0, uintptr(h), uintptr(unsafe.Pointer(&pixels[0])), uintptr(unsafe.Pointer(&info[0])), 0); result == 0 {
		t.Fatal(err)
	}
	header := make([]byte, 14)
	copy(header, "BM")
	binary.LittleEndian.PutUint32(header[2:], uint32(len(header)+len(info)+len(pixels)))
	binary.LittleEndian.PutUint32(header[10:], 54)
	data := append(append(header, info...), pixels...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
