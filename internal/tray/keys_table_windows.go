//go:build windows

package tray

import (
	"bytes"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

var keyColumnNames = [...]string{"Type", "Comment", "Source", "Fingerprint"}

const keyFingerprintColumn = len(keyColumnNames) - 1

type keyColumn struct {
	Mask                                                               uint32
	Format, Width                                                      int32
	Text                                                               *uint16
	TextMax, SubItem, Image, Order, MinWidth, DefaultWidth, IdealWidth int32
}

type keyItem struct {
	Mask             uint32
	Item, SubItem    int32
	State, StateMask uint32
	Text             *uint16
	TextMax, Image   int32
	Param            uintptr
	Indent, GroupID  int32
	Columns          uint32
	ColumnIndices    *uint32
	ColumnFormats    *int32
	Group            int32
}

type keyHeaderItem struct {
	Mask            uint32
	Width           int32
	Text            *uint16
	Bitmap          uintptr
	TextMax, Format int32
	Param           uintptr
	Image, Order    int32
	Type            uint32
	Filter          unsafe.Pointer
	State           uint32
}

func (d *keysDialog) createTable() error {
	init := struct{ Size, Classes uint32 }{8, 1} // ICC_LISTVIEW_CLASSES
	if ok, _, err := comctl32.NewProc("InitCommonControlsEx").Call(uintptr(unsafe.Pointer(&init))); ok == 0 {
		return winErr(err)
	}
	var err error
	d.list, err = d.child("SysListView32", "", 1|8|0x400|wsTabStop|wsClipChildren, wsExClientEdge, 0, 0, 0, 0, idKeyList) // Report, owner-drawn fixed rows, native multiselection.
	if err != nil {
		return err
	}
	sendMessage.Call(d.list, 0x1036, 0x10020, 0x10020) // Full-row selection and double buffering.
	header, _, _ := sendMessage.Call(d.list, 0x101F, 0, 0)
	style, _, _ := getWindowLongPtr.Call(header, ^uintptr(15))
	setWindowLongPtr.Call(header, ^uintptr(15), style|0x200|0x80) // HDS_FLAT | HDS_FULLDRAG: resize columns while dragging.
	if err := setThinBorder(header, borderKeyHeader); err != nil {
		return err
	}
	for i, width := range [...]int32{100, 180, 140, 400} {
		text, _ := windows.UTF16PtrFromString(keyColumnNames[i])
		value := keyColumn{Mask: 2 | 4 | 8, Width: d.m.s(width), Text: text, SubItem: int32(i)}
		if i == keyFingerprintColumn {
			value.Mask |= 1
			value.Format = 0x100
		} // LVCFMT_FIXED_WIDTH: the final divider cannot be dragged.
		if index, _, _ := sendMessage.Call(d.list, 0x1061, uintptr(i), uintptr(unsafe.Pointer(&value))); int32(index) == -1 { // LVM_INSERTCOLUMNW
			return errors.New("could not create key table column")
		}
	}
	d.sortColumn = 1
	d.updateSortIndicator()
	return nil
}

func (d *keysDialog) keyCell(key *agent.Key, column int) string {
	switch column {
	case 0:
		return displayKeyType(key.Type())
	case 1:
		return key.Comment
	case 2:
		source := d.keySources[string(key.Blob)]
		if source.Name == "Manual" {
			return "Manually Added"
		}
		if app := d.sourceApps[sourceAppID(source)]; app.name != "" {
			return app.name
		}
		if source.Name != "" {
			return source.Name
		}
		return "Unknown"
	default:
		return ssh.FingerprintSHA256(key)
	}
}

func (d *keysDialog) selectedKey() *agent.Key {
	index, _, _ := sendMessage.Call(d.list, 0x100C, ^uintptr(0), 2) // LVM_GETNEXTITEM / LVNI_SELECTED
	if int32(index) < 0 || int(index) >= len(d.keys) {
		return nil
	}
	return d.keys[index]
}

func (d *keysDialog) selectedKeys() []*agent.Key {
	var keys []*agent.Key
	index := ^uintptr(0)
	for {
		index, _, _ = sendMessage.Call(d.list, 0x100C, index, 2) // LVM_GETNEXTITEM / LVNI_SELECTED
		if int32(index) < 0 || int(index) >= len(d.keys) {
			return keys
		}
		keys = append(keys, d.keys[index])
	}
}

func (d *keysDialog) updateRemoveButtons() {
	if d.updatingKeys || d.list == 0 {
		return
	}
	selected, _, _ := sendMessage.Call(d.list, 0x1032, 0, 0) // LVM_GETSELECTEDCOUNT
	count, _, _ := sendMessage.Call(d.list, 0x1004, 0, 0)    // LVM_GETITEMCOUNT
	for _, button := range []struct {
		id     uintptr
		active bool
	}{
		{idRemoveKey, selected != 0 && count != 0},
		{idRemoveAllKeys, count != 0},
	} {
		window, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, button.id)
		if window == 0 {
			continue
		}
		enabled, _, _ := isWindowEnabled.Call(window)
		if (enabled != 0) != button.active {
			value := uintptr(0)
			if button.active {
				value = 1
			}
			enableWindow.Call(window, value)
		}
	}
}

func (d *keysDialog) selectAllKeys() {
	d.updatingKeys = true
	item := keyItem{State: 2, StateMask: 2} // LVIS_SELECTED, preserving focus.
	sendMessage.Call(d.list, 0x102B, ^uintptr(0), uintptr(unsafe.Pointer(&item)))
	d.updatingKeys = false
	d.updateRemoveButtons()
	user32.NewProc("SetFocus").Call(d.list)
}

type keySelection struct {
	keys          map[string]bool
	focus, anchor string
}

func (d *keysDialog) selection() keySelection {
	state := keySelection{keys: make(map[string]bool)}
	for _, key := range d.selectedKeys() {
		state.keys[string(key.Blob)] = true
	}
	if index, _, _ := sendMessage.Call(d.list, 0x100C, ^uintptr(0), 1); int32(index) >= 0 && int(index) < len(d.keys) {
		state.focus = string(d.keys[index].Blob)
	} // LVNI_FOCUSED
	if index, _, _ := sendMessage.Call(d.list, 0x1042, 0, 0); int32(index) >= 0 && int(index) < len(d.keys) {
		state.anchor = string(d.keys[index].Blob)
	} // LVM_GETSELECTIONMARK
	return state
}

func (d *keysDialog) sortKeys(keys []*agent.Key) {
	labels := make(map[*agent.Key]string, len(keys))
	for _, key := range keys {
		labels[key] = strings.ToLower(d.keyCell(key, d.sortColumn))
	}
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		order := strings.Compare(labels[a], labels[b])
		if order == 0 {
			order = bytes.Compare(a.Blob, b.Blob)
		}
		if d.descending {
			return order > 0
		}
		return order < 0
	})
}

func (d *keysDialog) renderKeys(selected keySelection) error {
	d.updatingKeys = true
	top, _, _ := sendMessage.Call(d.list, 0x1027, 0, 0) // LVM_GETTOPINDEX
	d.updateSortIndicator()
	sendMessage.Call(d.list, 0x000B, 0, 0) // WM_SETREDRAW
	defer func() {
		sendMessage.Call(d.list, 0x000B, 1, 0)
		d.fitColumns()
		d.updatingKeys = false
		d.updateRemoveButtons()
		user32.NewProc("RedrawWindow").Call(d.list, 0, 0, 0x1A1)
	}()
	sendMessage.Call(d.list, 0x1009, 0, 0) // LVM_DELETEALLITEMS
	for row, key := range d.keys {
		for column := 0; column < len(keyColumnNames); column++ {
			text, _ := windows.UTF16PtrFromString(strings.ReplaceAll(d.keyCell(key, column), "\x00", "\uFFFD"))
			item := keyItem{Mask: 1, Item: int32(row), SubItem: int32(column), Text: text}
			operation := uintptr(0x104C) // LVM_SETITEMW
			if column == 0 {
				operation = 0x104D
			} // LVM_INSERTITEMW
			result, _, _ := sendMessage.Call(d.list, operation, 0, uintptr(unsafe.Pointer(&item)))
			if (column == 0 && int32(result) == -1) || (column != 0 && result == 0) {
				return errors.New("could not populate key table")
			}
		}
		identity := string(key.Blob)
		item := keyItem{StateMask: 3} // LVIS_SELECTED | LVIS_FOCUSED
		if selected.keys[identity] {
			item.State |= 2
		}
		if selected.focus == identity {
			item.State |= 1
		}
		if item.State != 0 {
			sendMessage.Call(d.list, 0x102B, uintptr(row), uintptr(unsafe.Pointer(&item)))
		}
		if selected.anchor == identity {
			sendMessage.Call(d.list, 0x1043, 0, uintptr(row))
		} // LVM_SETSELECTIONMARK
	}
	if top > 0 && len(d.keys) > 0 {
		var row rect
		sendMessage.Call(d.list, 0x100E, 0, uintptr(unsafe.Pointer(&row)))            // LVM_GETITEMRECT / LVIR_BOUNDS
		sendMessage.Call(d.list, 0x1014, 0, uintptr(int32(top)*(row.Bottom-row.Top))) // LVM_SCROLL
	}
	return nil
}

func (d *keysDialog) updateSortIndicator() {
	header, _, _ := sendMessage.Call(d.list, 0x101F, 0, 0) // LVM_GETHEADER
	for column := 0; column < len(keyColumnNames); column++ {
		var item keyHeaderItem
		item.Mask = 4 // HDI_FORMAT
		if ok, _, _ := sendMessage.Call(header, 0x120B, uintptr(column), uintptr(unsafe.Pointer(&item))); ok == 0 {
			continue
		} // HDM_GETITEMW
		item.Format &^= 0x600 // HDF_SORTUP | HDF_SORTDOWN
		if column == d.sortColumn {
			item.Format |= 0x400
			if d.descending {
				item.Format = item.Format&^0x400 | 0x200
			}
		}
		sendMessage.Call(header, 0x120C, uintptr(column), uintptr(unsafe.Pointer(&item))) // HDM_SETITEMW
	}
}

func (d *keysDialog) tableNotification(address uintptr) {
	if address == 0 {
		return
	}
	var notification struct {
		Header struct {
			Window, ID uintptr
			Code       int32
		}
		Item, SubItem               int32
		NewState, OldState, Changed uint32
		Action                      point
		Param                       uintptr
	}
	var copied uintptr
	if err := windows.ReadProcessMemory(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&notification.Header)), unsafe.Sizeof(notification.Header), &copied); err != nil {
		return
	}
	if notification.Header.Window != d.list {
		return
	}
	switch notification.Header.Code {
	case -101, -115: // LVN_ITEMCHANGED / LVN_ODSTATECHANGED
		d.updateRemoveButtons()
		return
	case -108, -3: // LVN_COLUMNCLICK / NM_DBLCLK
	default:
		return
	}
	if err := windows.ReadProcessMemory(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&notification)), unsafe.Sizeof(notification), &copied); err != nil {
		return
	}
	if notification.Header.Code == -3 { // NM_DBLCLK
		if notification.Item >= 0 && int(notification.Item) < len(d.keys) {
			key := d.keys[notification.Item]
			source := d.keySources[string(key.Blob)]
			path := source.Executable
			if source.Name == "Manual" {
				path = source.File
			}
			if path != "" && filepath.IsAbs(path) {
				if err := openPath(filepath.Dir(path)); err != nil {
					showError(d.hwnd, err)
				}
			}
		}
		return
	}
	if notification.SubItem < 0 || notification.SubItem >= int32(len(keyColumnNames)) {
		return
	} // LVN_COLUMNCLICK
	selected := d.selection()
	column := int(notification.SubItem)
	if column == d.sortColumn {
		d.descending = !d.descending
	} else {
		d.sortColumn, d.descending = column, false
	}
	d.sortKeys(d.keys)
	if err := d.renderKeys(selected); err != nil {
		showError(d.hwnd, err)
	}
}

func (d *keysDialog) layout() {
	if d.list == 0 {
		return
	}
	var area rect
	getClientRect.Call(d.hwnd, uintptr(unsafe.Pointer(&area)))
	pad, gap, width, height := d.m.s(12), d.m.s(8), d.m.s(88), d.m.s(24)
	buttonY := area.Bottom - pad - height
	setWindowPos.Call(d.list, 0, uintptr(pad), uintptr(pad), uintptr(max(1, area.Right-2*pad)), uintptr(max(1, buttonY-gap-pad)), 0x14)
	d.fitColumns()
	for _, button := range []struct {
		id uintptr
		x  int32
	}{{idAddKey, pad}, {idRemoveKey, pad + width + gap}, {idRemoveAllKeys, pad + 2*(width+gap)}, {idKeySettings, area.Right - pad - 2*width - gap}, {idCancel, area.Right - pad - width}} {
		window, _, _ := user32.NewProc("GetDlgItem").Call(d.hwnd, button.id)
		if window != 0 {
			setWindowPos.Call(window, 0, uintptr(button.x), uintptr(buttonY), uintptr(width), uintptr(height), 0x14)
		}
	}
}

func (d *keysDialog) fitColumns() {
	if d.fittingColumns || d.list == 0 {
		return
	}
	var area rect
	getClientRect.Call(d.list, uintptr(unsafe.Pointer(&area)))
	if area.Right < d.m.s(144) {
		return
	}
	d.fittingColumns = true
	defer func() { d.fittingColumns = false }()
	remaining := area.Right
	for column := 0; column < len(keyColumnNames); column++ {
		current, _, _ := sendMessage.Call(d.list, 0x101D, uintptr(column), 0) // LVM_GETCOLUMNWIDTH
		width := remaining
		if column < keyFingerprintColumn {
			width = min(int32(current), remaining-d.m.s(int32(80+32*(keyFingerprintColumn-column-1))))
		}
		width = max(d.m.s(32), width)
		if int32(current) != width {
			sendMessage.Call(d.list, 0x101E, uintptr(column), uintptr(width))
		} // LVM_SETCOLUMNWIDTH
		remaining -= width
	}
}

func (d *keysDialog) setMinimumSize(address uintptr) {
	if address == 0 {
		return
	}
	var info struct{ Reserved, MaxSize, MaxPosition, MinTrack, MaxTrack point }
	var copied uintptr
	if err := windows.ReadProcessMemory(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&info)), unsafe.Sizeof(info), &copied); err != nil {
		return
	}
	area := rect{Right: d.m.s(540), Bottom: d.m.s(200)}
	adjustWindowRectEx.Call(uintptr(unsafe.Pointer(&area)), wsPopup|wsCaption|wsSysMenu|wsClipSiblings|wsThickFrame|wsMinimizeBox|wsMaximizeBox, 0, wsExControlParent|wsExWindowEdge)
	info.MinTrack = point{area.Right - area.Left, area.Bottom - area.Top}
	_ = windows.WriteProcessMemory(windows.CurrentProcess(), address, (*byte)(unsafe.Pointer(&info)), unsafe.Sizeof(info), &copied)
}

func translateKeysMessage(msg *message) bool {
	if keysDlg == nil || keysDlg.hwnd == 0 {
		return false
	}
	window := keysDlg.hwnd
	if enabled, _, _ := isWindowEnabled.Call(window); enabled == 0 {
		return false
	}
	if msg.Window != window {
		if child, _, _ := user32.NewProc("IsChild").Call(window, msg.Window); child == 0 {
			return false
		}
	}
	if msg.Message == 0x0100 && msg.WParam == 0x41 {
		control, _, _ := user32.NewProc("GetKeyState").Call(0x11)
		alt, _, _ := user32.NewProc("GetKeyState").Call(0x12)
		if control&0x8000 != 0 && alt&0x8000 == 0 {
			keysDlg.selectAllKeys()
			return true
		}
	}
	handled, _, _ := isDialogMessage.Call(window, uintptr(unsafe.Pointer(msg)))
	return handled != 0
}
