//go:build windows

package tray

import (
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const wmApplyTheme = 0x801F
const (
	themePopup = iota + 1
	themeControl
	themeButton
	themeList
	themeTooltip
)

type uiTheme struct{ dark, fallback bool }
type themedWindow struct {
	kind        uintptr
	fallback    bool
	dark        bool
	initialized bool
}

var activeTheme atomic.Pointer[uiTheme]
var themedWindows sync.Map
var themeCallback uintptr
var themeBrushes sync.Map // Fixed fallback colors; brushes live for the process lifetime.
var readUITheme = systemUITheme
var uiThemeAPI = windows.NewLazySystemDLL("uxtheme.dll")
var dwmSetAttribute = windows.NewLazySystemDLL("dwmapi.dll").NewProc("DwmSetWindowAttribute")

func init() { themeCallback = windows.NewCallback(themeWindowProc) }

func darkColor(color uintptr) bool {
	return ((color&255)*299 + ((color>>8)&255)*587 + ((color>>16)&255)*114) < 128000
}

func resolveUITheme(appsLight, highContrast bool, window, face uintptr) uiTheme {
	if highContrast {
		return uiTheme{}
	}
	nativeDark := darkColor(window) || darkColor(face)
	return uiTheme{dark: nativeDark || !appsLight, fallback: !nativeDark && !appsLight}
}

func systemUITheme() uiTheme {
	light := true
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err == nil {
		value, _, readErr := key.GetIntegerValue("AppsUseLightTheme")
		if readErr == nil {
			light = value != 0
		}
		key.Close()
	}
	contrast := struct {
		Size, Flags uint32
		Scheme      uintptr
	}{}
	contrast.Size = uint32(unsafe.Sizeof(contrast))
	systemParameters.Call(0x0042, uintptr(contrast.Size), uintptr(unsafe.Pointer(&contrast)), 0)
	window, _, _ := getSysColor.Call(5)
	face, _, _ := getSysColor.Call(15)
	return resolveUITheme(light, contrast.Flags&1 != 0, window, face)
}

func currentUITheme() uiTheme {
	if theme := activeTheme.Load(); theme != nil {
		return *theme
	}
	theme := readUITheme()
	activeTheme.CompareAndSwap(nil, &theme)
	return *activeTheme.Load()
}

func refreshUITheme() {
	theme := readUITheme()
	activeTheme.Store(&theme)
	themedWindows.Range(func(key, value any) bool { postMessage.Call(key.(uintptr), wmApplyTheme, 0, 0); return true })
}

func fallbackUIColor(index uintptr) (uintptr, bool) {
	switch index {
	case 4, 15, 24:
		return 0x202020, true
	case 5:
		return 0x292929, true
	case 7, 8, 18, 23:
		return 0xF0F0F0, true
	case 16:
		return 0x454545, true
	case 17:
		return 0x808080, true
	case 22:
		return 0x2D2D2D, true
	case 29:
		return 0x3A3A3A, true
	}
	return 0, false
}

func uiColor(index uintptr) uintptr {
	if currentUITheme().fallback {
		if color, ok := fallbackUIColor(index); ok {
			return color
		}
	}
	color, _, _ := getSysColor.Call(index)
	return color
}

func uiBrush(index uintptr) uintptr {
	color, custom := fallbackUIColor(index)
	if !currentUITheme().fallback || !custom {
		brush, _, _ := getSysColorBrush.Call(index)
		return brush
	}
	if brush, ok := themeBrushes.Load(color); ok {
		return brush.(uintptr)
	}
	brush, _, _ := gdi32.NewProc("CreateSolidBrush").Call(color)
	if brush == 0 {
		brush, _, _ = getSysColorBrush.Call(index)
		return brush
	}
	actual, loaded := themeBrushes.LoadOrStore(color, brush)
	if loaded {
		deleteObject.Call(brush)
	}
	return actual.(uintptr)
}

func installUITheme(window, kind uintptr) error {
	state := &themedWindow{kind: kind}
	if ok, _, err := setWindowSubclass.Call(window, themeCallback, 5, 0); ok == 0 {
		return winErr(err)
	}
	themedWindows.Store(window, state)
	if kind == themePopup {
		refreshUITheme()
	}
	applyUITheme(window, state)
	return nil
}

func applyUITheme(window uintptr, state *themedWindow) {
	theme := currentUITheme()
	if state.kind == themePopup && (!state.initialized || state.dark != theme.dark) {
		state.initialized, state.dark = true, theme.dark
		var dark int32
		if theme.dark {
			dark = 1
		}
		dwmSetAttribute.Call(window, 20, uintptr(unsafe.Pointer(&dark)), 4)
	}
	if state.kind == themeList {
		sendMessage.Call(window, 0x1001, 0, uiColor(5))
		sendMessage.Call(window, 0x1026, 0, uiColor(5))
		sendMessage.Call(window, 0x1024, 0, uiColor(8))
	}
	if state.kind == themeTooltip {
		changed := !state.initialized || state.fallback != theme.fallback
		state.initialized, state.fallback = true, theme.fallback
		if changed {
			var name *uint16
			if theme.fallback {
				name, _ = windows.UTF16PtrFromString("")
			}
			uiThemeAPI.NewProc("SetWindowTheme").Call(window, uintptr(unsafe.Pointer(name)), 0)
		}
		sendMessage.Call(window, 0x0413, uiColor(24), 0)
		sendMessage.Call(window, 0x0414, uiColor(23), 0)
	}
	user32.NewProc("RedrawWindow").Call(window, 0, 0, 0x485) // Invalidate clients, children, and frames.
}

func themeWindowProc(window uintptr, msg uint32, wParam, lParam, id, data uintptr) uintptr {
	value, ok := themedWindows.Load(window)
	if !ok {
		result, _, _ := defSubclassProc.Call(window, uintptr(msg), wParam, lParam)
		return result
	}
	state := value.(*themedWindow)
	if msg == 0x0082 {
		themedWindows.Delete(window)
		removeWindowSubclass.Call(window, themeCallback, id)
	}
	if msg == wmApplyTheme {
		applyUITheme(window, state)
		return 0
	}
	if msg == 0x0015 || msg == 0x001A || msg == 0x031A {
		if state.kind == themePopup {
			refreshUITheme()
		} else {
			postMessage.Call(window, wmApplyTheme, 0, 0)
		}
	}
	if msg >= 0x0132 && msg <= 0x0138 {
		background, foreground := uintptr(15), uintptr(18)
		if msg == 0x0133 || msg == 0x0134 {
			background, foreground = 5, 8
		}
		if lParam != 0 {
			if enabled, _, _ := isWindowEnabled.Call(lParam); enabled == 0 {
				foreground = 17
			}
		}
		setTextColor.Call(wParam, uiColor(foreground))
		gdi32.NewProc("SetBkColor").Call(wParam, uiColor(background))
		return uiBrush(background)
	}
	if state.kind == themePopup && (msg == 0x0014 || msg == 0x0318) {
		var bounds rect
		getClientRect.Call(window, uintptr(unsafe.Pointer(&bounds)))
		fillRect.Call(wParam, uintptr(unsafe.Pointer(&bounds)), uiBrush(15))
		if msg == 0x0014 {
			return 1
		}
		return 0
	}
	if state.kind == themeButton && currentUITheme().fallback {
		if handled, result := themeButtonMessage(window, msg, wParam); handled {
			return result
		}
	}
	repaint := state.kind == themeButton && currentUITheme().fallback && buttonVisualMessage(msg)
	suppress := repaint && (msg == wmSetText || msg == wmSetFont || msg == 0x00F1)
	if suppress {
		defSubclassProc.Call(window, 0x000B, 0, 0)
	} // Native state changes must not flash a light button.
	result, _, _ := defSubclassProc.Call(window, uintptr(msg), wParam, lParam)
	if suppress {
		defSubclassProc.Call(window, 0x000B, 1, 0)
	}
	if repaint {
		user32.NewProc("RedrawWindow").Call(window, 0, 0, 0x105)
	}
	return result
}
