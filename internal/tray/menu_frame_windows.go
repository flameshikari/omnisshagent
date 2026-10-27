//go:build windows

package tray

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type menuFrameState struct {
	shrinkX, shrinkY int32
	adjusted         bool
	flags            uint32
}

var menuFrames sync.Map
var menuTrackContexts sync.Map
var menuFrameCallback, menuCreateCallback uintptr
var nextMenuHook = user32.NewProc("CallNextHookEx")

func init() {
	menuFrameCallback = windows.NewCallback(menuFrameWindowProc)
	menuCreateCallback = windows.NewCallback(menuCreateHook)
}

func trackTrayMenu(menu uintptr, flags uint32, x, y, owner uintptr) {
	thread := windows.GetCurrentThreadId()
	previous, nested := menuTrackContexts.LoadOrStore(thread, flags)
	if nested {
		menuTrackContexts.Store(thread, flags)
	}
	defer func() {
		if nested {
			menuTrackContexts.Store(thread, previous)
		} else {
			menuTrackContexts.Delete(thread)
		}
	}()
	hook, _, _ := user32.NewProc("SetWindowsHookExW").Call(5, menuCreateCallback, 0, uintptr(windows.GetCurrentThreadId())) // WH_CBT, current UI thread only.
	if hook != 0 {
		defer user32.NewProc("UnhookWindowsHookEx").Call(hook)
	}
	trackPopupMenu.Call(menu, uintptr(flags), x, y, 0, owner, 0)
}

func menuCreateHook(code int32, wParam, lParam uintptr) uintptr {
	if code == 3 { // HCBT_CREATEWND, before the popup's non-client area is calculated.
		var class [32]uint16
		user32.NewProc("GetClassNameW").Call(wParam, uintptr(unsafe.Pointer(&class[0])), uintptr(len(class)))
		if windows.UTF16ToString(class[:]) == "#32768" {
			flags, _ := menuTrackContexts.Load(windows.GetCurrentThreadId())
			state := &menuFrameState{}
			if flags != nil {
				state.flags = flags.(uint32)
			}
			menuFrames.Store(wParam, state)
			if ok, _, _ := setWindowSubclass.Call(wParam, menuFrameCallback, 7, 0); ok == 0 {
				menuFrames.Delete(wParam)
			}
		}
	}
	result, _, _ := nextMenuHook.Call(0, uintptr(code), wParam, lParam)
	return result
}

func menuFrameWindowProc(window uintptr, msg uint32, wParam, lParam, id, data uintptr) uintptr {
	value, _ := menuFrames.Load(window)
	state, _ := value.(*menuFrameState)
	if state != nil && msg == 0x0046 && lParam != 0 && !state.adjusted {
		var position struct {
			Window, After       uintptr
			X, Y, Width, Height int32
			Flags               uint32
		}
		var copied uintptr
		if err := windows.ReadProcessMemory(windows.CurrentProcess(), lParam, (*byte)(unsafe.Pointer(&position)), unsafe.Sizeof(position), &copied); err == nil && position.Flags&1 == 0 && position.Width > state.shrinkX && position.Height > state.shrinkY && (state.shrinkX > 0 || state.shrinkY > 0) {
			position.Width -= state.shrinkX
			position.Height -= state.shrinkY
			if state.flags&0x20 != 0 {
				position.Y += state.shrinkY
			}
			if state.flags&0x08 != 0 {
				position.X += state.shrinkX
			}
			if windows.WriteProcessMemory(windows.CurrentProcess(), lParam, (*byte)(unsafe.Pointer(&position)), unsafe.Sizeof(position), &copied) == nil {
				state.adjusted = true
			}
		}
	}

	if msg == 0x0083 && lParam != 0 { // WM_NCCALCSIZE: both forms start with the client RECT.
		var bounds rect
		var copied uintptr
		if err := windows.ReadProcessMemory(windows.CurrentProcess(), lParam, (*byte)(unsafe.Pointer(&bounds)), unsafe.Sizeof(bounds), &copied); err == nil {
			defSubclassProc.Call(window, uintptr(msg), wParam, lParam)
			var native rect
			if state != nil && windows.ReadProcessMemory(windows.CurrentProcess(), lParam, (*byte)(unsafe.Pointer(&native)), unsafe.Sizeof(native), &copied) == nil {
				state.shrinkX = max(0, native.Left-bounds.Left+bounds.Right-native.Right-2)
				state.shrinkY = max(0, native.Top-bounds.Top+bounds.Bottom-native.Bottom-2)
			}
			bounds.Left++
			bounds.Top++
			bounds.Right = max(bounds.Left, bounds.Right-1)
			bounds.Bottom = max(bounds.Top, bounds.Bottom-1)
			if err := windows.WriteProcessMemory(windows.CurrentProcess(), lParam, (*byte)(unsafe.Pointer(&bounds)), unsafe.Sizeof(bounds), &copied); err == nil {
				return 0
			}
		}
	}
	if msg == 0x0085 { // WM_NCPAINT: one physical pixel, no themed outer gutter.
		dc, _, _ := getWindowDC.Call(window)
		if dc != 0 {
			var bounds rect
			getWindowRect.Call(window, uintptr(unsafe.Pointer(&bounds)))
			bounds = rect{Right: bounds.Right - bounds.Left, Bottom: bounds.Bottom - bounds.Top}
			frameRect.Call(dc, uintptr(unsafe.Pointer(&bounds)), uiBrush(16))
			releaseDC.Call(window, dc)
		}
		return 0
	}
	if msg == 0x0082 {
		menuFrames.Delete(window)
		removeWindowSubclass.Call(window, menuFrameCallback, id)
	}
	result, _, _ := defSubclassProc.Call(window, uintptr(msg), wParam, lParam)
	return result
}
