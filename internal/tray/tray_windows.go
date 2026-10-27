//go:build windows

package tray

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/masahide/OmniSSHAgent/internal/app"
	"github.com/masahide/OmniSSHAgent/internal/autostart"
	"github.com/masahide/OmniSSHAgent/internal/backend"
	"github.com/masahide/OmniSSHAgent/internal/config"
	"github.com/masahide/OmniSSHAgent/internal/open"
	"golang.org/x/sys/windows"
)

//go:embed assets/tray.ico assets/openssh.ico assets/pageant.ico
var assets embed.FS

const (
	windowClass        = "OmniSSHAgentTrayWindow"
	windowTitle        = "OmniSSHAgent"
	wmDestroy          = 0x0002
	wmCommand          = 0x0111
	wmClose            = 0x0010
	wmLButtonUp        = 0x0202
	wmRButtonUp        = 0x0205
	wmUser             = 0x0400
	wmTray             = wmUser + 1
	wmApply            = wmUser + 2
	wmShowKeys         = wmUser + 8
	nimAdd             = 0
	nimModify          = 1
	nimDelete          = 2
	nifMessage         = 1
	nifIcon            = 2
	nifTip             = 4
	wsCaption          = 0x00C00000
	wsSysMenu          = 0x00080000
	wsThickFrame       = 0x00040000
	wsMinimizeBox      = 0x00020000
	wsMaximizeBox      = 0x00010000
	wsOverlappedWindow = wsCaption | wsSysMenu | wsThickFrame | wsMinimizeBox | wsMaximizeBox
	cwUseDefault       = 0x80000000
	swHide             = 0
	mfString           = 0
	mfDisabled         = 2
	mfSeparator        = 0x800
	tpmLeftAlign       = 0
	tpmBottomAlign     = 0x20
	menuStatus         = 1001
	menuOpenConfig     = 1002
	menuOpenConfigDir  = 1003
	menuOpenLogDir     = 1004
	menuSettings       = 1005
	menuManageKeys     = 1006
	menuRemoveAllKeys  = 1007
	menuQuit           = 1009
	smCXSmallIcon      = 49
	smCYSmallIcon      = 50
	lrDefaultColor     = 0
	mbOK               = 0
	mbIconError        = 0x10
)

var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	user32                 = windows.NewLazySystemDLL("user32.dll")
	shell32                = windows.NewLazySystemDLL("shell32.dll")
	getModuleHandle        = kernel32.NewProc("GetModuleHandleW")
	registerClass          = user32.NewProc("RegisterClassExW")
	createWindow           = user32.NewProc("CreateWindowExW")
	defWindowProc          = user32.NewProc("DefWindowProcW")
	destroyWindow          = user32.NewProc("DestroyWindow")
	showWindow             = user32.NewProc("ShowWindow")
	updateWindow           = user32.NewProc("UpdateWindow")
	getMessage             = user32.NewProc("GetMessageW")
	translateMessage       = user32.NewProc("TranslateMessage")
	dispatchMessage        = user32.NewProc("DispatchMessageW")
	postQuitMessage        = user32.NewProc("PostQuitMessage")
	postMessage            = user32.NewProc("PostMessageW")
	registerWindowMessage  = user32.NewProc("RegisterWindowMessageW")
	createPopupMenu        = user32.NewProc("CreatePopupMenu")
	appendMenu             = user32.NewProc("AppendMenuW")
	modifyMenu             = user32.NewProc("ModifyMenuW")
	destroyMenu            = user32.NewProc("DestroyMenu")
	getCursorPos           = user32.NewProc("GetCursorPos")
	setForegroundWindow    = user32.NewProc("SetForegroundWindow")
	trackPopupMenu         = user32.NewProc("TrackPopupMenu")
	messageBox             = user32.NewProc("MessageBoxW")
	getSystemMetrics       = user32.NewProc("GetSystemMetrics")
	createIconFromResource = user32.NewProc("CreateIconFromResourceEx")
	destroyIcon            = user32.NewProc("DestroyIcon")
	shellNotifyIcon        = shell32.NewProc("Shell_NotifyIconW")
	callback               = windows.NewCallback(windowProc)
	activeMu               sync.Mutex
	active                 *Tray
	openPath               = open.Path
	openConfiguration      = open.Configuration
	createDefaultConfig    = config.CreateDefault
	autoStartEnabled       = autostart.Enabled
	setAutoStartEnabled    = autostart.SetEnabled
	openSettingsDialog     = func(t *Tray) { t.openSettings() }
	openKeysDialog         = func(t *Tray) { t.openKeys(t.window) }
)

type menuEntry struct {
	flags uint32
	id    uintptr
	text  string
}

func requiredMenuEntries() []menuEntry {
	return []menuEntry{
		{mfString, menuManageKeys, "Manage Keys"},
		{mfString, menuRemoveAllKeys, "Remove Keys"},
		{mfString, menuSettings, "Settings"},
		{mfString, menuQuit, "Quit"},
	}
}

type point struct{ X, Y int32 }
type message struct {
	Window         uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Point          point
	Private        uint32
}
type wndClassEx struct {
	Size, Style                        uint32
	WndProc                            uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	MenuName, ClassName                *uint16
	IconSmall                          uintptr
}
type notifyIconData struct {
	Size                uint32
	Window              uintptr
	ID, Flags, Callback uint32
	Icon                uintptr
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	Version             uint32
	InfoTitle           [64]uint16
	InfoFlags           uint32
	GUID                windows.GUID
	BalloonIcon         uintptr
}

type Tray struct {
	wantKeys              bool
	configPath            string
	logDirectory          string
	onQuit                func()
	mu                    sync.Mutex
	state                 app.State
	agent                 backend.Backend
	window, icon, menu    uintptr
	nid                   notifyIconData
	taskbarCreated        uint32
	added                 bool
	shuttingDown          bool
	fluentIcon            bool
	iconAsset             string
	iconWidth, iconHeight int32
	countBackend          backend.Backend
	countToken            uintptr
	keyCount              int
	stopCount             func()
}

func New(configPath, logDirectory string, onQuit func()) *Tray {
	return &Tray{configPath: configPath, logDirectory: logDirectory, onQuit: onQuit, state: app.StateDegraded}
}

func (t *Tray) SetState(state app.State) {
	t.mu.Lock()
	if t.shuttingDown {
		t.mu.Unlock()
		return
	}
	t.state = state
	window := t.window
	t.mu.Unlock()
	if window != 0 {
		postMessage.Call(window, wmApply, 0, 0)
	}
}

func (t *Tray) Run(ctx context.Context) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	activeMu.Lock()
	if active != nil {
		activeMu.Unlock()
		return errors.New("tray already active")
	}
	active = t
	activeMu.Unlock()
	defer func() { activeMu.Lock(); active = nil; activeMu.Unlock() }()
	if err := t.initialize(); err != nil {
		ShowFatal(err)
		return err
	}
	defer t.close()
	if err := t.addIcon(); err != nil {
		ShowFatal(err)
		return err
	}
	go func() { <-ctx.Done(); t.quit() }()
	var msg message
	for {
		result, _, callErr := getMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(result) == -1 {
			return winErr(callErr)
		}
		if result == 0 {
			return nil
		}
		updateFocusCues(&msg)
		if translateKeysMessage(&msg) {
			continue
		}
		translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func (t *Tray) initialize() error {
	instance, _, callErr := getModuleHandle.Call(0)
	if instance == 0 {
		return winErr(callErr)
	}
	class, _ := windows.UTF16PtrFromString(windowClass)
	wc := wndClassEx{Size: uint32(unsafe.Sizeof(wndClassEx{})), WndProc: callback, Instance: instance, ClassName: class}
	if result, _, callErr := registerClass.Call(uintptr(unsafe.Pointer(&wc))); result == 0 {
		return winErr(callErr)
	}
	title, _ := windows.UTF16PtrFromString(windowTitle)
	window, _, callErr := createWindow.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)), wsOverlappedWindow, cwUseDefault, cwUseDefault, cwUseDefault, cwUseDefault, 0, 0, instance, 0)
	if window == 0 {
		return winErr(callErr)
	}
	t.mu.Lock()
	t.window = window
	t.mu.Unlock()
	showWindow.Call(window, swHide)
	updateWindow.Call(window)
	taskbarName, _ := windows.UTF16PtrFromString("TaskbarCreated")
	result, _, callErr := registerWindowMessage.Call(uintptr(unsafe.Pointer(taskbarName)))
	if result == 0 {
		return winErr(callErr)
	}
	t.taskbarCreated = uint32(result)
	if err := t.refreshIcon(); err != nil {
		return err
	}
	menu, _, callErr := createPopupMenu.Call()
	if menu == 0 {
		return winErr(callErr)
	}
	t.menu = menu
	for _, item := range requiredMenuEntries() {
		if err := appendMenuItem(menu, item.flags, item.id, item.text); err != nil {
			return err
		}
	}
	if err := styleTrayMenu(menu); err != nil {
		return err
	}
	t.nid = notifyIconData{Size: uint32(unsafe.Sizeof(notifyIconData{})), Window: window, ID: 1, Flags: nifMessage | nifIcon | nifTip, Callback: wmTray, Icon: t.icon}
	t.applyState()
	return nil
}

func (t *Tray) addIcon() error {
	if result, _, callErr := shellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&t.nid))); result == 0 {
		return winErr(callErr)
	}
	t.added = true
	return nil
}

func (t *Tray) applyState() {
	_ = t.refreshIcon()
	if keysDlg != nil && keysDlg.tray == t && keysDlg.backend != t.backend() {
		keysDlg.close()
	}
	t.syncKeyCount()
	t.updateKeyCountTooltip()
	if t.wantKeys && t.backend() != nil {
		t.wantKeys = false
		t.command(menuManageKeys)
	}
}

func stateLabel(state app.State) string {
	switch state {
	case app.StateRunning:
		return "Running"
	case app.StateConfigurationError:
		return "Configuration error"
	default:
		return "Degraded"
	}
}

func (t *Tray) showMenu() {
	var p point
	if result, _, _ := getCursorPos.Call(uintptr(unsafe.Pointer(&p))); result == 0 {
		return
	}
	setForegroundWindow.Call(t.window)
	trackTrayMenu(t.menu, tpmBottomAlign|tpmLeftAlign, uintptr(p.X), uintptr(p.Y), t.window)
}

func (t *Tray) command(id uintptr) {
	t.mu.Lock()
	if t.shuttingDown {
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()
	switch id {
	case menuOpenConfig:
		_, _ = createDefaultConfig(t.configPath)
		_ = openConfiguration(t.configPath)
	case menuOpenConfigDir:
		_ = openPath(filepathDir(t.configPath))
	case menuOpenLogDir:
		_ = openPath(t.logDirectory)
	case menuSettings:
		openSettingsDialog(t)
	case menuManageKeys:
		openKeysDialog(t)
	case menuRemoveAllKeys:
		t.removeAllKeys()
	case menuQuit:
		if t.onQuit != nil {
			go t.onQuit()
		}
	}
}

func (t *Tray) removeAllKeys() {
	b := t.backend()
	if b == nil {
		showError(t.window, errors.New("the SSH agent backend is unavailable"))
		return
	}
	err := b.RemoveAll()
	if keysDlg != nil && keysDlg.tray == t && keysDlg.backend == b {
		err = errors.Join(err, keysDlg.refresh())
	}
	if err != nil {
		showError(t.window, err)
	}
}

func (t *Tray) quit() {
	t.mu.Lock()
	if t.shuttingDown {
		t.mu.Unlock()
		return
	}
	t.shuttingDown = true
	window := t.window
	t.mu.Unlock()
	if window != 0 {
		postMessage.Call(window, wmClose, 0, 0)
	}
}

func (t *Tray) close() {
	t.stopKeyCount()
	if t.added {
		shellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&t.nid)))
		t.added = false
	}
	if t.menu != 0 {
		destroyMenu.Call(t.menu)
		t.menu = 0
	}
	if t.window != 0 {
		destroyWindow.Call(t.window)
		t.mu.Lock()
		t.window = 0
		t.mu.Unlock()
	}
	if t.icon != 0 {
		destroyIcon.Call(t.icon)
		t.icon = 0
	}
}

func windowProc(window uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	activeMu.Lock()
	t := active
	activeMu.Unlock()
	if t != nil {
		if msg == t.taskbarCreated && msg != 0 {
			t.added = false
			_ = t.refreshIcon()
			_ = t.addIcon()
			return 0
		}
		switch msg {
		case 0x002C: // WM_MEASUREITEM
			if measureTrayMenuItem(lParam) {
				return 1
			}
		case 0x002B: // WM_DRAWITEM
			if drawTrayMenuItem(lParam) {
				return 1
			}
		case 0x001A, 0x031A, 0x0015, 0x02E0: // Settings, theme, system colors, DPI.
			refreshUITheme()
			_ = t.refreshIcon()
		case wmTray:
			if uint32(lParam) == wmLButtonUp {
				t.command(menuManageKeys)
			} else if uint32(lParam) == wmRButtonUp {
				t.showMenu()
			}
			return 0
		case wmCommand:
			t.command(uintptr(uint16(wParam & 0xffff)))
			return 0
		case wmShowKeys:
			t.wantKeys = true
			t.applyState()
			return 0
		case wmApply:
			t.applyState()
			return 0
		case wmKeyCount:
			if wParam == t.countToken {
				t.keyCount = int(lParam)
				t.updateKeyCountTooltip()
			}
			return 0
		case wmDestroy:
			t.stopKeyCount()
			if t.added {
				shellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&t.nid)))
				t.added = false
			}
			t.mu.Lock()
			t.window = 0
			t.mu.Unlock()
			postQuitMessage.Call(0)
			return 0
		}
	}
	result, _, _ := defWindowProc.Call(window, uintptr(msg), wParam, lParam)
	return result
}

func appendMenuItem(menu uintptr, flags uint32, id uintptr, text string) error {
	var ptr *uint16
	if flags != mfSeparator {
		ptr, _ = windows.UTF16PtrFromString(text)
	}
	if result, _, callErr := appendMenu.Call(menu, uintptr(flags), id, uintptr(unsafe.Pointer(ptr))); result == 0 {
		return winErr(callErr)
	}
	return nil
}

func copyUTF16(dst []uint16, value string) {
	encoded, err := windows.UTF16FromString(value)
	if err != nil {
		return
	}
	copy(dst, encoded)
	dst[len(dst)-1] = 0
}

func int32Result(proc *windows.LazyProc, value uintptr) int32 {
	result, _, _ := proc.Call(value)
	if int32(result) <= 0 {
		return 16
	}
	return int32(result)
}

func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

func winErr(err error) error {
	if err == nil {
		return errors.New("Windows API call failed")
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return errors.New("Windows API call failed without an extended error code")
	}
	return err
}

func ShowFatal(err error) {
	showError(0, err)
}

func createIcon(ico []byte, width, height int32) (uintptr, error) {
	if len(ico) < 6 || binaryLE16(ico[2:4]) != 1 {
		return 0, errors.New("invalid embedded ICO")
	}
	count := int(binaryLE16(ico[4:6]))
	if count == 0 || 6+count*16 > len(ico) {
		return 0, errors.New("truncated embedded ICO")
	}
	bestOffset, bestSize, bestScore := uint32(0), uint32(0), int64(1<<62)
	for i := 0; i < count; i++ {
		base := 6 + i*16
		w, h := int32(ico[base]), int32(ico[base+1])
		if w == 0 {
			w = 256
		}
		if h == 0 {
			h = 256
		}
		score := abs(int64(w-width)) + abs(int64(h-height))
		if score < bestScore {
			bestScore = score
			bestSize = binaryLE32(ico[base+8 : base+12])
			bestOffset = binaryLE32(ico[base+12 : base+16])
		}
	}
	end := uint64(bestOffset) + uint64(bestSize)
	if bestSize == 0 || end > uint64(len(ico)) {
		return 0, errors.New("ICO image is outside file")
	}
	image := ico[bestOffset:end]
	result, _, callErr := createIconFromResource.Call(uintptr(unsafe.Pointer(&image[0])), uintptr(len(image)), 1, 0x00030000, uintptr(width), uintptr(height), lrDefaultColor)
	runtime.KeepAlive(ico)
	if result == 0 {
		return 0, fmt.Errorf("CreateIconFromResourceEx: %w", winErr(callErr))
	}
	return result, nil
}
func binaryLE16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
func binaryLE32(b []byte) uint32 { return uint32(binaryLE16(b)) | uint32(binaryLE16(b[2:]))<<16 }
func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
