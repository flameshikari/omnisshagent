//go:build windows && arm64

package tray

import (
	"syscall"
	"unsafe"
)

func dwriteGlyphTrampolineAddress() uintptr

// Windows ARM64 allocates floating-point and integer argument registers
// independently. SyscallN supports integers only; the trampoline supplies the
// two zero baseline floats without changing any integer arguments.
//
//go:uintptrescapes
func drawDWriteGlyph(target *dwObject, run *dwGlyphRun, parameters *dwObject, color uintptr, bounds *rect) uintptr {
	result, _, _ := syscall.SyscallN(dwriteGlyphTrampolineAddress(), uintptr(unsafe.Pointer(target)), 0,
		uintptr(unsafe.Pointer(run)), uintptr(unsafe.Pointer(parameters)), color, uintptr(unsafe.Pointer(bounds)), target.vtable[3])
	return result
}
