//go:build windows

package tray

import (
	"crypto/ed25519"
	"crypto/rand"
	"runtime"
	"sync"
	"testing"
	"unsafe"

	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

type tablePaintProbe struct{ rows, directRows, hiddenUpdates, horizontalScrollbars, intermediateRows, frames, emptyFrames int }

var tablePaintProbes sync.Map
var tablePaintCallback = windows.NewCallback(tablePaintWindowProc)

func tablePaintWindowProc(window uintptr, msg uint32, wParam, lParam, id, data uintptr) uintptr {
	if value, ok := tablePaintProbes.Load(window); ok {
		probe := value.(*tablePaintProbe)
		if msg == 0x101E { // LVM_SETCOLUMNWIDTH
			style, _, _ := getWindowLongPtr.Call(window, ^uintptr(15))
			if style&0x10000000 == 0 {
				probe.hiddenUpdates++
			} // WS_VISIBLE
		}
		if msg == 0x002B && lParam != 0 {
			var item struct {
				Type, ID, Item, Action, State uint32
				Window, DC                    uintptr
			}
			var copied uintptr
			if windows.ReadProcessMemory(windows.CurrentProcess(), lParam, (*byte)(unsafe.Pointer(&item)), unsafe.Sizeof(item), &copied) == nil && item.Type == 102 {
				probe.rows++
				if keysDlg != nil && (keysDlg.fittingColumns || keysDlg.updatingKeys) {
					probe.intermediateRows++
				}
				if kind, _, _ := gdi32.NewProc("GetObjectType").Call(item.DC); kind != 10 {
					probe.directRows++
				}
			}
		}
	}
	before := 0
	var hadUpdate uintptr
	if msg == 0x000F {
		hadUpdate, _, _ = user32.NewProc("GetUpdateRect").Call(window, 0, 0)
		if value, ok := tablePaintProbes.Load(window); ok {
			before = value.(*tablePaintProbe).rows
		}
	}
	result, _, _ := defSubclassProc.Call(window, uintptr(msg), wParam, lParam)
	if msg == 0x000F && keysDlg != nil && window == keysDlg.list && hadUpdate != 0 {
		remaining, _, _ := user32.NewProc("GetUpdateRect").Call(window, 0, 0)
		if value, ok := tablePaintProbes.Load(window); ok && remaining == 0 {
			probe := value.(*tablePaintProbe)
			probe.frames++
			if probe.rows == before {
				probe.emptyFrames++
			}
		}
	}

	if msg == 0x101E {
		if value, ok := tablePaintProbes.Load(window); ok {
			style, _, _ := getWindowLongPtr.Call(window, ^uintptr(15))
			if style&0x100000 != 0 {
				value.(*tablePaintProbe).horizontalScrollbars++
			}
		}
	}
	return result
}

func TestColumnDragBuffersOwnerDrawnRows(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Add(agent.AddedKey{PrivateKey: private, Comment: "resize"}); err != nil {
		t.Fatal(err)
	}
	tray := New("", t.TempDir(), func() {})
	tray.SetBackend(b)
	tray.openKeys(0)
	d := keysDlg
	if d == nil {
		t.Fatal("Manage Keys did not open")
	}
	defer d.close()
	header, _, _ := sendMessage.Call(d.list, 0x101F, 0, 0)
	probe := &tablePaintProbe{}
	for _, window := range []uintptr{d.hwnd, d.list} {
		tablePaintProbes.Store(window, probe)
		if ok, _, err := setWindowSubclass.Call(window, tablePaintCallback, 77, 0); ok == 0 {
			t.Fatal(err)
		}
		defer func(window uintptr) {
			removeWindowSubclass.Call(window, tablePaintCallback, 77)
			tablePaintProbes.Delete(window)
		}(window)
	}
	user32.NewProc("RedrawWindow").Call(d.list, 0, 0, 0x185)
	var first rect
	sendMessage.Call(header, 0x1207, 0, uintptr(unsafe.Pointer(&first)))
	position := func(x int32) uintptr {
		return uintptr(uint32(uint16(x)) | uint32(uint16((first.Top+first.Bottom)/2))<<16)
	}
	x := first.Right - 1
	sendMessage.Call(header, 0x0201, 1, position(x))
	*probe = tablePaintProbe{}
	for step := int32(1); step <= 20; step++ {
		sendMessage.Call(header, 0x0200, 1, position(x+step))
	}
	for step := int32(19); step >= -20; step-- {
		sendMessage.Call(header, 0x0200, 1, position(x+step))
	}
	sendMessage.Call(header, 0x0202, 0, position(x-20))
	if probe.rows == 0 {
		t.Fatal("column drag did not repaint rows")
	}
	if probe.directRows != 0 {
		t.Errorf("column drag painted %d of %d rows directly to the screen instead of a buffer", probe.directRows, probe.rows)
	}
	if probe.hiddenUpdates != 0 {
		t.Errorf("column drag hid the table for %d width updates", probe.hiddenUpdates)
	}
	if probe.horizontalScrollbars != 0 {
		t.Errorf("column drag temporarily showed a horizontal scrollbar %d times", probe.horizontalScrollbars)
	}
	if probe.intermediateRows != 0 {
		t.Errorf("painted %d rows before column updates were complete", probe.intermediateRows)
	}
	t.Logf("completed frames=%d empty=%d rows=%d", probe.frames, probe.emptyFrames, probe.rows)
	if probe.emptyFrames != 0 {
		t.Errorf("column drag displayed %d empty frames", probe.emptyFrames)
	}
}
