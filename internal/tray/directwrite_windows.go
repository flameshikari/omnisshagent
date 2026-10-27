//go:build windows

package tray

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	dwriteCreateFactory   = windows.NewLazySystemDLL("dwrite.dll").NewProc("DWriteCreateFactory")
	dwriteFactoryIID      = windows.GUID{Data1: 0xb859ee5a, Data2: 0xd838, Data3: 0x4b5b, Data4: [8]byte{0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48}}
	dwriteBitmapTargetIID = windows.GUID{Data1: 0x791e8298, Data2: 0x3ef3, Data3: 0x4230, Data4: [8]byte{0x98, 0x80, 0xc9, 0xbd, 0xec, 0xc4, 0x20, 0x64}}
)

type dwObject struct{ vtable *[24]uintptr }

//go:uintptrescapes
func (o *dwObject) call(method int, args ...uintptr) uintptr {
	arguments := append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)
	result, _, _ := syscall.SyscallN(o.vtable[method], arguments...)
	runtime.KeepAlive(o)
	return result
}

func (o *dwObject) release() {
	if o != nil {
		o.call(2)
	}
}
func dwResult(result uintptr, operation string) error {
	if int32(result) < 0 {
		return fmt.Errorf("DirectWrite %s: HRESULT 0x%08x", operation, uint32(result))
	}
	return nil
}

type dwGlyphRun struct {
	Face     *dwObject
	EmSize   float32
	Count    uint32
	Indices  *uint16
	Advances *float32
	Offsets  unsafe.Pointer
	Sideways int32
	Bidi     uint32
}

type dwMatrix struct{ XX, XY, YX, YY, DX, DY float32 }
type nativeBitmap struct {
	Type, Width, Height, Stride int32
	Planes, BitsPerPixel        uint16
	Bits                        unsafe.Pointer
}
type nativeDIBSection struct {
	Bitmap    nativeBitmap
	Header    bitmapHeader
	Bitfields [3]uint32
	Section   uintptr
	Offset    uint32
}

// DirectWrite performs the grayscale blending, including the monitor's native
// gamma/contrast settings. We recover alpha from black-on-white or white-on-black
// output rather than treating uncorrected outline coverage as opacity.
func directWriteIconPixels(width, height int32, light bool) ([]byte, error) {
	if width <= 0 || height <= 0 || width > 256 || height > 256 {
		return nil, errors.New("invalid tray icon dimensions")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var factory, interop, parameters *dwObject
	result, _, _ := dwriteCreateFactory.Call(0, uintptr(unsafe.Pointer(&dwriteFactoryIID)), uintptr(unsafe.Pointer(&factory)))
	if err := dwResult(result, "create factory"); err != nil {
		return nil, err
	}
	defer factory.release()
	if err := dwResult(factory.call(17, uintptr(unsafe.Pointer(&interop))), "GDI interop"); err != nil {
		return nil, err
	}
	defer interop.release()
	class, _ := windows.UTF16PtrFromString("Shell_TrayWnd")
	window, _, _ := user32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(class)), 0)
	monitor, _, _ := user32.NewProc("MonitorFromWindow").Call(window, 1)
	if err := dwResult(factory.call(11, monitor, uintptr(unsafe.Pointer(&parameters))), "monitor rendering parameters"); err != nil {
		return nil, err
	}
	defer parameters.release()
	var lastErr error
	for _, family := range []string{"Segoe Fluent Icons", "Segoe MDL2 Assets"} {
		pixels, err := directWriteFontIcon(interop, parameters, family, width, height, light)
		if err == nil {
			return pixels, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func directWriteFontIcon(interop, parameters *dwObject, family string, width, height int32, light bool) ([]byte, error) {
	name, _ := windows.UTF16PtrFromString(family)
	font, _, callErr := createFont.Call(uintptr(-int64(min(width, height))), 0, 0, 0, 400, 0, 0, 0, 1, 7, 0, 4, 0, uintptr(unsafe.Pointer(name)))
	if font == 0 {
		return nil, winErr(callErr)
	}
	defer deleteObject.Call(font)
	dc, _, callErr := createCompatibleDC.Call(0)
	if dc == 0 {
		return nil, winErr(callErr)
	}
	defer deleteDC.Call(dc)
	previous, _, _ := selectObject.Call(dc, font)
	defer selectObject.Call(dc, previous)
	var faceName [64]uint16
	getTextFace.Call(dc, uintptr(len(faceName)), uintptr(unsafe.Pointer(&faceName[0])))
	if !strings.EqualFold(windows.UTF16ToString(faceName[:]), family) {
		return nil, errors.New("symbol font is not installed")
	}
	var face, target, grayscale *dwObject
	if err := dwResult(interop.call(6, dc, uintptr(unsafe.Pointer(&face))), "font face"); err != nil {
		return nil, err
	}
	defer face.release()
	codepoint := uint32(fluentTrayGlyph)
	var glyph uint16
	if err := dwResult(face.call(11, uintptr(unsafe.Pointer(&codepoint)), 1, uintptr(unsafe.Pointer(&glyph))), "glyph index"); err != nil {
		return nil, err
	}
	if glyph == 0 {
		return nil, errors.New("symbol font does not contain U+E192")
	}
	canvasWidth, canvasHeight := width*3, height*3
	if err := dwResult(interop.call(7, 0, uintptr(canvasWidth), uintptr(canvasHeight), uintptr(unsafe.Pointer(&target))), "bitmap target"); err != nil {
		return nil, err
	}
	defer target.release()
	if err := dwResult(target.call(0, uintptr(unsafe.Pointer(&dwriteBitmapTargetIID)), uintptr(unsafe.Pointer(&grayscale))), "grayscale target"); err != nil {
		return nil, err
	}
	defer grayscale.release()
	if err := dwResult(grayscale.call(12, 1), "grayscale antialiasing"); err != nil {
		return nil, err
	}
	transform := dwMatrix{XX: 1, YY: 1, DX: float32(width), DY: float32(height * 2)}
	if err := dwResult(target.call(8, uintptr(unsafe.Pointer(&transform))), "glyph transform"); err != nil {
		return nil, err
	}
	memoryDC := target.call(4)
	if memoryDC == 0 {
		return nil, errors.New("DirectWrite returned no bitmap DC")
	}
	canvas := rect{Right: canvasWidth, Bottom: canvasHeight}
	background, foreground := uintptr(4), uintptr(0xFFFFFF) // BLACK_BRUSH and white text.
	if light {
		background, foreground = 0, 0
	} // WHITE_BRUSH and black text.
	brush, _, _ := getStockObject.Call(background)
	fillRect.Call(memoryDC, uintptr(unsafe.Pointer(&canvas)), brush)
	advance := float32(min(width, height))
	run := dwGlyphRun{Face: face, EmSize: advance, Count: 1, Indices: &glyph, Advances: &advance}
	var painted rect
	if err := dwResult(drawDWriteGlyph(target, &run, parameters, foreground, &painted), "draw glyph"); err != nil {
		return nil, err
	}
	gdi32.NewProc("GdiFlush").Call()
	bitmap, _, _ := gdi32.NewProc("GetCurrentObject").Call(memoryDC, 7) // OBJ_BITMAP
	var section nativeDIBSection
	count, _, _ := gdi32.NewProc("GetObjectW").Call(bitmap, unsafe.Sizeof(section), uintptr(unsafe.Pointer(&section)))
	if count != unsafe.Sizeof(section) || section.Bitmap.Bits == nil || section.Bitmap.BitsPerPixel != 32 || section.Bitmap.Stride < canvasWidth*4 || section.Bitmap.Height != canvasHeight {
		return nil, errors.New("DirectWrite returned an unsupported bitmap")
	}
	data := unsafe.Slice((*byte)(section.Bitmap.Bits), int(section.Bitmap.Stride*canvasHeight))
	alphaAt := func(x, y int32) byte {
		// DirectWrite's memory DC always exposes a top-down 32-bit DIB.
		value := data[int(y*section.Bitmap.Stride+x*4)]
		if light {
			return 255 - value
		}
		return value
	}
	ink := rect{Left: canvasWidth, Top: canvasHeight}
	for y := int32(0); y < canvasHeight; y++ {
		for x := int32(0); x < canvasWidth; x++ {
			if alphaAt(x, y) != 0 {
				ink.Left = min(ink.Left, x)
				ink.Top = min(ink.Top, y)
				ink.Right = max(ink.Right, x+1)
				ink.Bottom = max(ink.Bottom, y+1)
			}
		}
	}
	if ink.Right <= ink.Left || ink.Bottom <= ink.Top {
		return nil, errors.New("DirectWrite returned an empty glyph")
	}
	if ink.Right-ink.Left > width+2 || ink.Bottom-ink.Top > height+2 {
		return nil, errors.New("DirectWrite glyph exceeds tray icon bounds")
	}
	pixels := make([]byte, int(width*height*4))
	xOffset, yOffset := (width-(ink.Right-ink.Left))/2-ink.Left, (height-(ink.Bottom-ink.Top))/2-ink.Top
	for y := int32(0); y < height; y++ {
		for x := int32(0); x < width; x++ {
			sx, sy := x-xOffset, y-yOffset
			if sx < 0 || sy < 0 || sx >= canvasWidth || sy >= canvasHeight {
				continue
			}
			alpha := alphaAt(sx, sy)
			i := int((y*width + x) * 4)
			pixels[i+3] = alpha
			if !light {
				pixels[i], pixels[i+1], pixels[i+2] = alpha, alpha, alpha
			}
		}
	}
	runtime.KeepAlive(target)
	return pixels, nil
}
