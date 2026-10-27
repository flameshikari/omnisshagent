//go:build windows

package tray

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/masahide/OmniSSHAgent/internal/backend"
	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"github.com/masahide/OmniSSHAgent/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

func TestManageKeysTable(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Zebra", "alpha", "Beta"} {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Add(agent.AddedKey{PrivateKey: key, Comment: name}); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := config.Save(path, config.Default()); err != nil {
		t.Fatal(err)
	}
	tray := New(path, t.TempDir(), func() {})
	tray.SetBackend(b)
	settings := &settingsDialog{tray: tray, m: newMetrics()}
	previous := settingsDlg
	settingsDlg = settings
	defer func() { settingsDlg = previous }()
	if err := settings.create(0); err != nil {
		t.Fatal(err)
	}
	defer settings.close()
	showWindow.Call(settings.hwnd, swShow)
	tray.openKeys(settings.hwnd)
	d := keysDlg
	if d == nil || d.hwnd == 0 {
		t.Fatal("Manage Keys did not open")
	}
	defer d.close()
	settingsButton, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, idKeySettings)
	closeButton, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, idCancel)
	var settingsBounds, closeBounds rect
	getWindowRect.Call(settingsButton, uintptr(unsafe.Pointer(&settingsBounds)))
	getWindowRect.Call(closeButton, uintptr(unsafe.Pointer(&closeBounds)))
	if settingsButton == 0 || windowText(settingsButton) != "Settings" || closeBounds.Left-settingsBounds.Right != d.m.s(8) || settingsBounds.Top != closeBounds.Top {
		t.Fatal("Settings is not aligned immediately before Close")
	}
	showWindow.Call(settings.hwnd, 6)
	sendMessage.Call(d.hwnd, wmCommand, idKeySettings, 0)
	if minimized, _, _ := user32.NewProc("IsIconic").Call(settings.hwnd); minimized != 0 {
		t.Fatal("Settings button did not restore the Settings window")
	}
	if d.pollResults != nil || d.changeToken == 0 {
		t.Fatal("embedded key list still uses polling")
	}
	if enabled, _, _ := isWindowEnabled.Call(settings.hwnd); enabled == 0 {
		t.Fatal("Manage Keys disabled Settings")
	}
	cell := func(row, column int) string {
		buffer := make([]uint16, 256)
		item := keyItem{SubItem: int32(column), Text: &buffer[0], TextMax: int32(len(buffer))}
		sendMessage.Call(d.list, 0x1073, uintptr(row), uintptr(unsafe.Pointer(&item))) // LVM_GETITEMTEXTW
		return windows.UTF16ToString(buffer)
	}
	if cell(0, 1) != "alpha" || cell(1, 1) != "Beta" || cell(2, 1) != "Zebra" {
		t.Fatalf("default name order: %q, %q, %q", cell(0, 1), cell(1, 1), cell(2, 1))
	}
	if cell(0, 0) != "ED25519" || cell(0, 3) != ssh.FingerprintSHA256(d.keys[0]) || cell(0, 2) != "Unknown" {
		t.Fatal("key table columns do not match the key")
	}
	// Width must change on mouse movement, before the mouse button is released.
	header, _, _ := sendMessage.Call(d.list, 0x101F, 0, 0)
	var firstColumn rect
	sendMessage.Call(header, 0x1207, 0, uintptr(unsafe.Pointer(&firstColumn)))
	pointParam := func(x, y int32) uintptr { return uintptr(uint32(uint16(x)) | uint32(uint16(y))<<16) }
	x, y := firstColumn.Right-1, (firstColumn.Top+firstColumn.Bottom)/2
	sendMessage.Call(header, 0x0201, 1, pointParam(x, y))
	if !d.headerDrag.active {
		t.Fatal("divider mouse down did not begin resizing")
	}
	sendMessage.Call(header, 0x0200, 1, pointParam(x+24, y))
	width, _, _ := sendMessage.Call(d.list, 0x101D, 0, 0)
	if int32(width) != firstColumn.Right-firstColumn.Left+24 {
		t.Fatalf("column did not resize before mouse up: width=%d", width)
	}
	var viewport rect
	getClientRect.Call(d.list, uintptr(unsafe.Pointer(&viewport)))
	var total int32
	for column := 0; column < len(keyColumnNames); column++ {
		width, _, _ := sendMessage.Call(d.list, 0x101D, uintptr(column), 0)
		total += int32(width)
	}
	if total != viewport.Right {
		t.Fatal("fingerprint did not resize during divider dragging")
	}
	sendMessage.Call(header, 0x0202, 0, pointParam(x+24, y))
	if d.headerDrag.active {
		t.Fatal("mouse up did not finish resizing")
	}
	item := keyItem{State: 3, StateMask: 3}
	sendMessage.Call(d.list, 0x102B, 0, uintptr(unsafe.Pointer(&item))) // Select alpha.
	if target := os.Getenv("OMNI_KEYS_PREVIEW"); target != "" {
		saveSettingsPreview(t, d.hwnd, target)
	}
	// Exercise a real native header click and its LVN_COLUMNCLICK notification.
	var column rect
	sendMessage.Call(header, 0x1207, 1, uintptr(unsafe.Pointer(&column))) // HDM_GETITEMRECT
	position := uintptr(uint32((column.Left+column.Right)/2)&0xFFFF | uint32((column.Top+column.Bottom)/2)<<16)
	sendMessage.Call(header, 0x0201, 1, position)
	sendMessage.Call(header, 0x0202, 0, position)
	if cell(0, 1) != "Zebra" || cell(2, 1) != "alpha" {
		t.Fatal("header click did not reverse name sorting")
	}
	if selected := d.selectedKey(); selected == nil || selected.Comment != "alpha" {
		t.Fatal("sorting changed the selected key")
	}
	// Changes made through another client must appear without reopening the window.
	_, external, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.ForClient(b, backend.Client{Source: "Pageant", Executable: `C:\Tools\ssh-add.exe`}).Add(agent.AddedKey{PrivateKey: external, Comment: "external"}); err != nil {
		t.Fatal(err)
	}
	waitForCount := func(count int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for len(d.keys) != count && time.Now().Before(deadline) {
			var update message
			if pending, _, _ := user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&update)), d.hwnd, wmKeysChanged, wmKeysChanged, 1); pending != 0 {
				dispatchMessage.Call(uintptr(unsafe.Pointer(&update)))
			}
			time.Sleep(5 * time.Millisecond)
		}
		if len(d.keys) != count {
			t.Fatalf("live key count=%d, want %d", len(d.keys), count)
		}
	}
	waitForCount(4)
	if cell(1, 2) != "Pageant" {
		t.Fatal("live update did not display key source")
	}
	previousOpen := openPath
	var opened []string
	openPath = func(path string) error { opened = append(opened, path); return nil }
	defer func() { openPath = previousOpen }()
	var activation struct {
		Header struct {
			Window, ID uintptr
			Code       int32
		}
		Item, SubItem               int32
		NewState, OldState, Changed uint32
		Action                      point
		Param                       uintptr
		KeyFlags                    uint32
	}
	activation.Header.Window, activation.Header.Code = d.list, -2 // Single-click only selects.
	activation.Item, activation.SubItem = 1, 2
	sendMessage.Call(d.hwnd, 0x004E, idKeyList, uintptr(unsafe.Pointer(&activation)))
	if len(opened) != 0 {
		t.Fatal("single-click opened a folder")
	}
	activation.Header.Code = -3 // NM_DBLCLK opens from any column.
	for column := range keyColumnNames {
		activation.SubItem = int32(column)
		sendMessage.Call(d.hwnd, 0x004E, idKeyList, uintptr(unsafe.Pointer(&activation)))
		if len(opened) != column+1 || opened[column] != `C:\Tools` {
			t.Fatalf("row double-click opened %v", opened)
		}
	}
	activation.Item, activation.SubItem = 0, 2 // Unknown source has no path.
	sendMessage.Call(d.hwnd, 0x004E, idKeyList, uintptr(unsafe.Pointer(&activation)))
	activation.Item = -1 // Empty table area.
	sendMessage.Call(d.hwnd, 0x004E, idKeyList, uintptr(unsafe.Pointer(&activation)))
	if len(opened) != len(keyColumnNames) {
		t.Fatal("double-click without a known path opened a folder")
	}
	if err := backend.AddFromSource(b, agent.AddedKey{PrivateKey: external, Comment: "external"}, backend.KeySource{Name: "Manual"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for cell(1, 2) != "Manually Added" && time.Now().Before(deadline) {
		var update message
		if pending, _, _ := user32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&update)), d.hwnd, wmKeysChanged, wmKeysChanged, 1); pending != 0 {
			dispatchMessage.Call(uintptr(unsafe.Pointer(&update)))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if cell(1, 2) != "Manually Added" {
		t.Fatal("source-only replacement did not refresh the table")
	}
	activation.Item = 1
	sendMessage.Call(d.hwnd, 0x004E, idKeyList, uintptr(unsafe.Pointer(&activation)))
	if len(opened) != len(keyColumnNames) {
		t.Fatal("manual source retained the previous executable folder")
	}

	if cell(0, 1) != "Zebra" || cell(1, 1) != "external" {
		t.Fatal("live update lost descending name order")
	}
	clickColumn := func(index uintptr) {
		var bounds rect
		sendMessage.Call(header, 0x1207, index, uintptr(unsafe.Pointer(&bounds)))
		position := pointParam((bounds.Left+bounds.Right)/2, (bounds.Top+bounds.Bottom)/2)
		sendMessage.Call(header, 0x0201, 1, position)
		sendMessage.Call(header, 0x0202, 0, position)
	}
	clickColumn(2)
	if d.sortColumn != 2 || cell(0, 1) != "external" || cell(0, 2) != "Manually Added" {
		t.Fatal("Source header did not sort by source")
	}
	clickColumn(1)
	clickColumn(1) // Restore descending comment order.

	if selected := d.selectedKey(); selected == nil || selected.Comment != "alpha" {
		t.Fatal("live update lost the selected key")
	}
	var externalKey *agent.Key
	for _, key := range d.keys {
		if key.Comment == "external" {
			externalKey = key
		}
	}
	if err := b.Remove(externalKey); err != nil {
		t.Fatal(err)
	}
	waitForCount(3)
	d.remove()
	remaining, err := b.List()
	if err != nil || len(remaining) != 2 {
		t.Fatalf("remove failed: keys=%d err=%v", len(remaining), err)
	}
	for _, key := range remaining {
		if key.Comment == "alpha" {
			t.Fatal("removed the wrong key after sorting")
		}
	}
	// Resizing must grow the table while preserving the same 8px gap as Settings.
	setWindowPos.Call(d.hwnd, 0, 0, 0, uintptr(d.m.s(960)), uintptr(d.m.s(460)), 0x16)
	var table, button, client rect
	getWindowRect.Call(d.list, uintptr(unsafe.Pointer(&table)))
	add, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, idAddKey)
	getWindowRect.Call(add, uintptr(unsafe.Pointer(&button)))
	getClientRect.Call(d.hwnd, uintptr(unsafe.Pointer(&client)))
	user32.NewProc("MapWindowPoints").Call(d.hwnd, 0, uintptr(unsafe.Pointer(&client)), 2)
	if button.Top-table.Bottom != d.m.s(8) || table.Left-client.Left != d.m.s(12) || client.Right-table.Right != d.m.s(12) || client.Bottom-button.Bottom != d.m.s(12) {
		t.Fatalf("resized layout lost spacing: table=%+v button=%+v client=%+v", table, button, client)
	}
	checkColumns := func() {
		t.Helper()
		var client rect
		getClientRect.Call(d.list, uintptr(unsafe.Pointer(&client)))
		total := int32(0)
		for column := 0; column < len(keyColumnNames); column++ {
			width, _, _ := sendMessage.Call(d.list, 0x101D, uintptr(column), 0)
			total += int32(width)
		}
		if total != client.Right {
			t.Fatalf("columns do not fill the viewport: total=%d viewport=%d", total, client.Right)
		}
	}
	checkColumns()
	// Over-wide leading columns must not push the fingerprint past the viewport.
	sendMessage.Call(d.list, 0x101E, 1, 2000)
	d.fitColumns()
	checkColumns()
	last := keyHeaderItem{Mask: 4}
	sendMessage.Call(header, 0x120B, uintptr(keyFingerprintColumn), uintptr(unsafe.Pointer(&last)))
	if last.Format&0x100 == 0 {
		t.Fatal("fingerprint divider is still resizable")
	}
	settings.close()
	if alive, _, _ := isWindow.Call(d.hwnd); alive == 0 {
		t.Fatal("closing Settings destroyed Manage Keys")
	}
	// Modeless dialogs must still handle Escape through the shared message loop.
	if !translateKeysMessage(&message{Window: d.list, Message: 0x0100, WParam: 0x1B}) {
		t.Fatal("Escape was not processed")
	}
	if keysDlg != nil {
		t.Fatal("Escape did not close Manage Keys")
	}
}
