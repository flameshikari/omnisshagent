//go:build windows && amd64

package tray

import (
	"syscall"
	"unsafe"
)

//go:uintptrescapes
func drawDWriteGlyph(target *dwObject, run *dwGlyphRun, parameters *dwObject, color uintptr, bounds *rect) uintptr {
	result, _, _ := syscall.SyscallN(target.vtable[3], uintptr(unsafe.Pointer(target)), 0, 0, 0,
		uintptr(unsafe.Pointer(run)), uintptr(unsafe.Pointer(parameters)), color, uintptr(unsafe.Pointer(bounds)))
	return result
}
