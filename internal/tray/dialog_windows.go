//go:build windows

package tray

import (
	"errors"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wsChild               = 0x40000000
	wsVisible             = 0x10000000
	wsTabStop             = 0x00010000
	wsGroup               = 0x00020000
	wsBorder              = 0x00800000
	wsVScroll             = 0x00200000
	wsHScroll             = 0x00100000
	wsPopup               = 0x80000000
	wsClipSiblings        = 0x04000000
	wsClipChildren        = 0x02000000
	wsExDlgModalFrame     = 0x00000001
	wsExControlParent     = 0x00010000
	wsExClientEdge        = 0x00000200
	wsExWindowEdge        = 0x00000100
	wsExAppWindow         = 0x00040000
	bsPushButton          = 0
	bsDefPushButton       = 1
	bsAutoCheckBox        = 3
	bsGroupBox            = 7
	bsFlat                = 0x8000
	esAutoHScroll         = 0x80
	esPassword            = 0x20
	cbsDropDownList       = 3
	lbsNotify             = 1
	lbsNoIntegralHeight   = 0x100
	idOK                  = 1
	idCancel              = 2
	wmSetFont             = 0x0030
	wmSetText             = 0x000C
	wmGetText             = 0x000D
	wmGetTextLength       = 0x000E
	bmGetCheck            = 0x00F0
	bmSetCheck            = 0x00F1
	bstUnchecked          = 0
	bstChecked            = 1
	cbAddString           = 0x0143
	cbSetCurSel           = 0x014E
	cbGetCurSel           = 0x0147
	lbAddString           = 0x0180
	lbResetContent        = 0x0184
	lbGetCurSel           = 0x0188
	lbSetHorizontalExtent = 0x0194
	swShow                = 5
	swpNoSize             = 0x0001
	swpNoZOrder           = 0x0004
	spiGetWorkArea        = 0x0030
	defaultGUIFont        = 17
	idcArrow              = 32512
	colorBtnFace          = 15
	errorClassExists      = syscall.Errno(1410)
	ofnExplorer           = 0x00080000
	ofnEnableHook         = 0x00000020
	ofnFileMustExist      = 0x00001000
	ofnPathMustExist      = 0x00000800
	ofnHideReadOnly       = 0x00000004
	ofnNoChangeDir        = 0x00000008
	maxPathWide           = 32768
)

type rect struct{ Left, Top, Right, Bottom int32 }
type size struct{ CX, CY int32 }

func controlWidth(hwnd uintptr) int32 {
	var bounds rect
	getWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&bounds)))
	return bounds.Right - bounds.Left
}

type openFileNameW struct {
	StructSize    uint32
	Owner         uintptr
	Instance      uintptr
	Filter        *uint16
	CustomFilter  *uint16
	MaxCustFilter uint32
	FilterIndex   uint32
	File          *uint16
	MaxFile       uint32
	FileTitle     *uint16
	MaxFileTitle  uint32
	InitialDir    *uint16
	Title         *uint16
	Flags         uint32
	FileOffset    uint16
	FileExtension uint16
	DefExt        *uint16
	CustData      uintptr
	Hook          uintptr
	TemplateName  *uint16
	Reserved      uintptr
	ReservedFlags uint32
	FlagsEx       uint32
}

type metrics struct {
	dpi  int32
	font uintptr
}

func (m metrics) s(v int32) int32 { return v * m.dpi / 96 }

var (
	gdi32                = windows.NewLazySystemDLL("gdi32.dll")
	comdlg32             = windows.NewLazySystemDLL("comdlg32.dll")
	enableWindow         = user32.NewProc("EnableWindow")
	isWindow             = user32.NewProc("IsWindow")
	isDialogMessage      = user32.NewProc("IsDialogMessageW")
	sendMessage          = user32.NewProc("SendMessageW")
	setWindowPos         = user32.NewProc("SetWindowPos")
	getWindowRect        = user32.NewProc("GetWindowRect")
	systemParameters     = user32.NewProc("SystemParametersInfoW")
	loadCursor           = user32.NewProc("LoadCursorW")
	getDpiForSystem      = user32.NewProc("GetDpiForSystem")
	adjustWindowRectEx   = user32.NewProc("AdjustWindowRectEx")
	getDC                = user32.NewProc("GetDC")
	releaseDC            = user32.NewProc("ReleaseDC")
	getStockObject       = gdi32.NewProc("GetStockObject")
	selectObject         = gdi32.NewProc("SelectObject")
	getTextExtentPoint32 = gdi32.NewProc("GetTextExtentPoint32W")
	getOpenFileName      = comdlg32.NewProc("GetOpenFileNameW")
	settingsCallback     = windows.NewCallback(settingsWindowProc)
	keysCallback         = windows.NewCallback(keysWindowProc)
	passwordCallback     = windows.NewCallback(passwordWindowProc)
	filePickerCallback   = windows.NewCallback(filePickerWindowProc)
)

func systemDPI() int32 {
	if err := getDpiForSystem.Find(); err == nil {
		if result, _, _ := getDpiForSystem.Call(); result != 0 {
			return int32(result)
		}
	}
	return 96
}

func newMetrics() metrics {
	font, _, _ := getStockObject.Call(defaultGUIFont)
	return metrics{dpi: systemDPI(), font: font}
}

func registerDialogClass(name string, proc uintptr) error {
	small, large, err := dialogIcons()
	if err != nil {
		return err
	}
	instance, _, callErr := getModuleHandle.Call(0)
	if instance == 0 {
		return winErr(callErr)
	}
	class, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	cursor, _, _ := loadCursor.Call(0, idcArrow)
	wc := wndClassEx{
		Size:       uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:    proc,
		Instance:   instance,
		Cursor:     cursor,
		Icon:       large,
		IconSmall:  small,
		Background: colorBtnFace + 1,
		ClassName:  class,
	}
	if result, _, callErr := registerClass.Call(uintptr(unsafe.Pointer(&wc))); result == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == errorClassExists {
			return nil
		}
		return winErr(callErr)
	}
	return nil
}

func createPopup(class, title string, width, height int32, owner, proc uintptr, extraStyle ...uint32) (uintptr, error) {
	if err := registerDialogClass(class, proc); err != nil {
		return 0, err
	}
	instance, _, callErr := getModuleHandle.Call(0)
	if instance == 0 {
		return 0, winErr(callErr)
	}
	classPtr, err := windows.UTF16PtrFromString(class)
	if err != nil {
		return 0, err
	}
	titlePtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return 0, err
	}
	style := uint32(wsPopup | wsCaption | wsSysMenu | wsClipSiblings)
	ex := uint32(wsExDlgModalFrame | wsExControlParent | wsExWindowEdge | wsExAppWindow)
	for _, flags := range extraStyle {
		style |= flags
	}
	if style&wsThickFrame != 0 {
		ex &^= wsExDlgModalFrame
	}
	area := rect{Right: width, Bottom: height}
	adjustWindowRectEx.Call(uintptr(unsafe.Pointer(&area)), uintptr(style), 0, uintptr(ex))
	hwnd, _, callErr := createWindow.Call(
		uintptr(ex),
		uintptr(unsafe.Pointer(classPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(style),
		cwUseDefault, cwUseDefault,
		uintptr(area.Right-area.Left), uintptr(area.Bottom-area.Top),
		owner, 0, instance, 0,
	)
	if hwnd == 0 {
		return 0, winErr(callErr)
	}
	if err := installFocusCues(hwnd); err != nil {
		destroyWindow.Call(hwnd)
		return 0, err
	}
	if err := installUITheme(hwnd, themePopup); err != nil {
		destroyWindow.Call(hwnd)
		return 0, err
	}
	small, large, _ := dialogIcons()
	sendMessage.Call(hwnd, 0x0080, 0, small) // WM_SETICON / ICON_SMALL
	sendMessage.Call(hwnd, 0x0080, 1, large) // WM_SETICON / ICON_BIG
	return hwnd, nil
}

// Icons belong to the registered window classes and live for the process lifetime.
var popupIcons struct {
	sync.Once
	small, large uintptr
	err          error
}

func dialogIcons() (uintptr, uintptr, error) {
	popupIcons.Do(func() {
		data, err := assets.ReadFile("assets/tray.ico")
		if err != nil {
			popupIcons.err = err
			return
		}
		popupIcons.small, popupIcons.err = createIcon(data, int32Result(getSystemMetrics, smCXSmallIcon), int32Result(getSystemMetrics, smCYSmallIcon))
		if popupIcons.err != nil {
			return
		}
		popupIcons.large, popupIcons.err = createIcon(data, int32Result(getSystemMetrics, 11), int32Result(getSystemMetrics, 12))
	})
	return popupIcons.small, popupIcons.large, popupIcons.err
}

func createChild(class, title string, style, ex uint32, x, y, w, h int32, parent, id uintptr) (uintptr, error) {
	var border uintptr
	if ex&wsExClientEdge != 0 {
		ex &^= wsExClientEdge
		style |= wsBorder
		border = borderList
		if class == "Edit" {
			// The subclass owns the entire frame; a native edit border can
			// otherwise leave themed inner edges beside the text area.
			style &^= wsBorder
			border = borderEdit
		}
	}
	if class == "ComboBox" && style&3 == cbsDropDownList {
		style |= 0x10 | 0x200 // CBS_OWNERDRAWFIXED | CBS_HASSTRINGS: padded native dropdown items.
		border = borderCombo
	}
	if class == "Button" {
		switch style & 0xF {
		case bsPushButton, bsDefPushButton, bsGroupBox:
			style |= bsFlat
			border = borderButton
			if style&0xF == bsGroupBox {
				style |= wsClipSiblings
				border = borderGroup
			}
		}
	}
	instance, _, callErr := getModuleHandle.Call(0)
	if instance == 0 {
		return 0, winErr(callErr)
	}
	classPtr, err := windows.UTF16PtrFromString(class)
	if err != nil {
		return 0, err
	}
	var titlePtr *uint16
	if title != "" {
		titlePtr, err = windows.UTF16PtrFromString(title)
		if err != nil {
			return 0, err
		}
	}
	hwnd, _, callErr := createWindow.Call(
		uintptr(ex),
		uintptr(unsafe.Pointer(classPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(style|wsChild|wsVisible),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent, id, instance, 0,
	)
	if hwnd == 0 {
		return 0, winErr(callErr)
	}
	if border != 0 {
		if err := setThinBorder(hwnd, border); err != nil {
			destroyWindow.Call(hwnd)
			return 0, err
		}
	}
	if err := installFocusCues(hwnd); err != nil {
		destroyWindow.Call(hwnd)
		return 0, err
	}
	kind := uintptr(themeControl)
	if class == "Button" {
		kind = themeButton
	}
	if class == "SysListView32" {
		kind = themeList
	}
	if err := installUITheme(hwnd, kind); err != nil {
		destroyWindow.Call(hwnd)
		return 0, err
	}
	return hwnd, nil
}

func setChildFont(hwnd, font uintptr) {
	if hwnd != 0 && font != 0 {
		sendMessage.Call(hwnd, wmSetFont, font, 1)
	}
}

func runModal(owner, hwnd uintptr) {
	if owner != 0 {
		enableWindow.Call(owner, 0)
		defer enableWindow.Call(owner, 1)
	}
	centerWindow(hwnd)
	showWindow.Call(hwnd, swShow)
	updateWindow.Call(hwnd)
	setForegroundWindow.Call(hwnd)
	var msg message
	for {
		alive, _, _ := isWindow.Call(hwnd)
		if alive == 0 {
			return
		}
		result, _, callErr := getMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(result) == -1 {
			_ = callErr
			return
		}
		if result == 0 {
			destroyWindow.Call(hwnd)
			postQuitMessage.Call(0)
			return
		}
		updateFocusCues(&msg)
		if translateKeysMessage(&msg) {
			continue
		}
		if handled, _, _ := isDialogMessage.Call(hwnd, uintptr(unsafe.Pointer(&msg))); handled != 0 {
			continue
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func centerWindow(hwnd uintptr) {
	var wr, ar rect
	if result, _, _ := getWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&wr))); result == 0 {
		return
	}
	if result, _, _ := systemParameters.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&ar)), 0); result == 0 {
		return
	}
	width := wr.Right - wr.Left
	height := wr.Bottom - wr.Top
	x := ar.Left + (ar.Right-ar.Left-width)/2
	y := ar.Top + (ar.Bottom-ar.Top-height)/2
	setWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), 0, 0, swpNoSize|swpNoZOrder)
}

func windowText(hwnd uintptr) string {
	if hwnd == 0 {
		return ""
	}
	n, _, _ := sendMessage.Call(hwnd, wmGetTextLength, 0, 0)
	buf := make([]uint16, n+1)
	sendMessage.Call(hwnd, wmGetText, n+1, uintptr(unsafe.Pointer(&buf[0])))
	return windows.UTF16ToString(buf)
}

func setWindowText(hwnd uintptr, text string) {
	ptr, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	sendMessage.Call(hwnd, wmSetText, 0, uintptr(unsafe.Pointer(ptr)))
}

func isChecked(hwnd uintptr) bool {
	result, _, _ := sendMessage.Call(hwnd, bmGetCheck, 0, 0)
	return result == bstChecked
}

func setChecked(hwnd uintptr, checked bool) {
	value := uintptr(bstUnchecked)
	if checked {
		value = bstChecked
	}
	sendMessage.Call(hwnd, bmSetCheck, value, 0)
}

func comboSelect(hwnd uintptr, index int) {
	sendMessage.Call(hwnd, cbSetCurSel, uintptr(index), 0)
}

func comboIndex(hwnd uintptr) int {
	result, _, _ := sendMessage.Call(hwnd, cbGetCurSel, 0, 0)
	return int(int32(result))
}

func comboAdd(hwnd uintptr, text string) {
	ptr, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	sendMessage.Call(hwnd, cbAddString, 0, uintptr(unsafe.Pointer(ptr)))
}

func listAdd(hwnd uintptr, text string) {
	ptr, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	sendMessage.Call(hwnd, lbAddString, 0, uintptr(unsafe.Pointer(ptr)))
}

func listReset(hwnd uintptr) {
	sendMessage.Call(hwnd, lbResetContent, 0, 0)
	sendMessage.Call(hwnd, lbSetHorizontalExtent, 0, 0)
}

func listIndex(hwnd uintptr) int {
	result, _, _ := sendMessage.Call(hwnd, lbGetCurSel, 0, 0)
	return int(int32(result))
}

func listSetHorizontalExtent(hwnd uintptr, extent int32) {
	sendMessage.Call(hwnd, lbSetHorizontalExtent, uintptr(extent), 0)
}

func measureTextWidth(hwnd, font uintptr, text string) int32 {
	if text == "" {
		return 0
	}
	dc, _, _ := getDC.Call(hwnd)
	if dc == 0 {
		return 0
	}
	defer releaseDC.Call(hwnd, dc)
	var previous uintptr
	if font != 0 {
		previous, _, _ = selectObject.Call(dc, font)
	}
	encoded, err := windows.UTF16FromString(text)
	if err != nil {
		return 0
	}
	var measured size
	getTextExtentPoint32.Call(
		dc,
		uintptr(unsafe.Pointer(&encoded[0])),
		uintptr(len(encoded)-1),
		uintptr(unsafe.Pointer(&measured)),
	)
	if previous != 0 {
		selectObject.Call(dc, previous)
	}
	return measured.CX
}

func listUpdateHorizontalExtent(hwnd, font uintptr, items []string) {
	var widest int32
	for _, item := range items {
		if width := measureTextWidth(hwnd, font, item); width > widest {
			widest = width
		}
	}
	if widest > 0 {
		// Extra padding so the last characters clear the vertical scrollbar.
		widest += 16
	}
	listSetHorizontalExtent(hwnd, widest)
}

func showError(owner uintptr, err error) {
	if err == nil {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	d := &errorDialog{}
	if createErr := d.create(owner, err.Error()); createErr == nil {
		runModal(owner, d.hwnd)
		return
	}
	titlePtr, _ := windows.UTF16PtrFromString(errorWindowTitle)
	textPtr, _ := windows.UTF16PtrFromString(err.Error())
	messageBox.Call(owner, uintptr(unsafe.Pointer(textPtr)), uintptr(unsafe.Pointer(titlePtr)), mbOK)
}

func utf16Filter(pairs ...string) []uint16 {
	var out []uint16
	for _, part := range pairs {
		encoded, err := windows.UTF16FromString(part)
		if err != nil {
			continue
		}
		out = append(out, encoded...)
	}
	return append(out, 0)
}

func pickOpenFile(owner uintptr, title, initialDir, initialFile string, filter []string, mustExist bool) (string, bool) {
	buf := make([]uint16, maxPathWide)
	if initialFile != "" {
		copyUTF16(buf, initialFile)
	}
	filterUTF16 := utf16Filter(filter...)
	ofn := openFileNameW{
		StructSize: uint32(unsafe.Sizeof(openFileNameW{})),
		Owner:      owner,
		Filter:     &filterUTF16[0],
		File:       &buf[0],
		MaxFile:    uint32(len(buf)),
		Flags:      ofnExplorer | ofnEnableHook | ofnHideReadOnly | ofnNoChangeDir | ofnPathMustExist,
		Hook:       filePickerCallback,
	}
	if mustExist {
		ofn.Flags |= ofnFileMustExist
	}
	if title != "" {
		ofn.Title, _ = windows.UTF16PtrFromString(title)
	}
	if initialDir != "" {
		ofn.InitialDir, _ = windows.UTF16PtrFromString(initialDir)
	}
	result, _, _ := getOpenFileName.Call(uintptr(unsafe.Pointer(&ofn)))
	runtime.KeepAlive(filterUTF16)
	runtime.KeepAlive(buf)
	if result == 0 {
		return "", false
	}
	return windows.UTF16ToString(buf), true
}

func filePickerWindowProc(window uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	if msg == 0x0110 { // WM_INITDIALOG: Explorer hooks receive a child dialog.
		parent, _, _ := user32.NewProc("GetParent").Call(window)
		if parent != 0 {
			ex, _, _ := getWindowLongPtr.Call(parent, ^uintptr(19))
			setWindowLongPtr.Call(parent, ^uintptr(19), ex|wsExAppWindow)
		}
	}
	return 0
}

func commandID(wParam uintptr) uintptr { return uintptr(uint16(wParam)) }

var errDialogCanceled = errors.New("canceled")
