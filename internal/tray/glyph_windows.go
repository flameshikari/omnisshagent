//go:build windows

package tray

import (
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const fluentTrayGlyph = 0xE192

type glyphMetrics struct {
	Width, Height      uint32
	Origin             point
	AdvanceX, AdvanceY int16
}

type fixed struct {
	Fraction uint16
	Value    int16
}
type glyphMatrix struct{ XX, XY, YX, YY fixed }
type glyphRaster struct {
	Width, Height, Stride int
	Coverage              []byte
}

var (
	createFont         = gdi32.NewProc("CreateFontW")
	getTextFace        = gdi32.NewProc("GetTextFaceW")
	getGlyphIndices    = gdi32.NewProc("GetGlyphIndicesW")
	getGlyphOutline    = gdi32.NewProc("GetGlyphOutlineW")
	createCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	deleteDC           = gdi32.NewProc("DeleteDC")
	deleteObject       = gdi32.NewProc("DeleteObject")
	createDIBSection   = gdi32.NewProc("CreateDIBSection")
	createBitmap       = gdi32.NewProc("CreateBitmap")
	createIconIndirect = user32.NewProc("CreateIconIndirect")
)

func rasterFontGlyph(family string, pixels int32) (glyphRaster, error) {
	name, _ := windows.UTF16PtrFromString(family)
	font, _, err := createFont.Call(uintptr(-int64(pixels)), 0, 0, 0, 400,
		0, 0, 0, 1, 7, 0, 4, 0, uintptr(unsafe.Pointer(name)))
	if font == 0 {
		return glyphRaster{}, winErr(err)
	}
	defer deleteObject.Call(font)
	dc, _, err := createCompatibleDC.Call(0)
	if dc == 0 {
		return glyphRaster{}, winErr(err)
	}
	defer deleteDC.Call(dc)
	previous, _, _ := selectObject.Call(dc, font)
	defer selectObject.Call(dc, previous)
	var face [64]uint16
	getTextFace.Call(dc, uintptr(len(face)), uintptr(unsafe.Pointer(&face[0])))
	if !strings.EqualFold(windows.UTF16ToString(face[:]), family) {
		return glyphRaster{}, errors.New("symbol font is not installed")
	}
	text := [1]uint16{fluentTrayGlyph}
	var index uint16
	getGlyphIndices.Call(dc, uintptr(unsafe.Pointer(&text[0])), 1, uintptr(unsafe.Pointer(&index)), 1)
	if index == 0xFFFF {
		return glyphRaster{}, errors.New("symbol font does not contain U+E192")
	}
	matrix := glyphMatrix{XX: fixed{Value: 1}, YY: fixed{Value: 1}}
	var metrics glyphMetrics
	length, _, _ := getGlyphOutline.Call(dc, fluentTrayGlyph, 6, uintptr(unsafe.Pointer(&metrics)), 0, 0, uintptr(unsafe.Pointer(&matrix))) // GGO_GRAY8_BITMAP, grid-fitted.
	if length == 0 || uint32(length) == 0xFFFFFFFF || length > 1024*1024 {
		return glyphRaster{}, errors.New("could not rasterize symbol glyph")
	}
	data := make([]byte, int(length))
	result, _, _ := getGlyphOutline.Call(dc, fluentTrayGlyph, 6, uintptr(unsafe.Pointer(&metrics)), length, uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&matrix)))
	if uint32(result) == 0xFFFFFFFF {
		return glyphRaster{}, errors.New("could not read symbol glyph bitmap")
	}
	stride := (int(metrics.Width) + 3) &^ 3
	if metrics.Width == 0 || metrics.Height == 0 || stride*int(metrics.Height) > len(data) {
		return glyphRaster{}, errors.New("invalid symbol glyph dimensions")
	}
	return glyphRaster{int(metrics.Width), int(metrics.Height), stride, data}, nil
}

func fluentIconPixels(width, height int32, light bool) ([]byte, error) {
	if width <= 0 || height <= 0 || width > 256 || height > 256 {
		return nil, errors.New("invalid tray icon dimensions")
	}
	if pixels, err := directWriteIconPixels(width, height, light); err == nil {
		return pixels, nil
	}
	return gdiIconPixels(width, height, light)
}

func gdiIconPixels(width, height int32, light bool) ([]byte, error) {
	var glyph glyphRaster
	var err error
	for _, family := range []string{"Segoe Fluent Icons", "Segoe MDL2 Assets"} {
		for pixels := min(width, height); pixels >= 8; pixels-- {
			glyph, err = rasterFontGlyph(family, pixels)
			if err != nil {
				break
			}
			if glyph.Width <= int(width) && glyph.Height <= int(height) {
				break
			}
		}
		if err == nil && glyph.Width <= int(width) && glyph.Height <= int(height) {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	if glyph.Width > int(width) || glyph.Height > int(height) {
		return nil, errors.New("symbol glyph does not fit tray icon")
	}
	pixels := make([]byte, int(width*height*4))
	xOffset, yOffset := (int(width)-glyph.Width)/2, (int(height)-glyph.Height)/2
	for y := 0; y < glyph.Height; y++ {
		for x := 0; x < glyph.Width; x++ {
			alpha := byte((uint32(glyph.Coverage[y*glyph.Stride+x])*255 + 32) / 64)
			i := ((y+yOffset)*int(width) + x + xOffset) * 4
			pixels[i+3] = alpha
			if !light {
				pixels[i], pixels[i+1], pixels[i+2] = alpha, alpha, alpha
			} // Premultiplied white; otherwise black.
		}
	}
	return pixels, nil
}

type bitmapHeader struct {
	Size                   uint32
	Width, Height          int32
	Planes, Bits           uint16
	Compression, ImageSize uint32
	XPixels, YPixels       int32
	Colors, Important      uint32
}

type iconInfo struct {
	Icon        int32
	X, Y        uint32
	Mask, Color uintptr
}

func createFluentIcon(width, height int32, light bool) (uintptr, error) {
	pixels, err := fluentIconPixels(width, height, light)
	if err != nil {
		return 0, err
	}
	header := bitmapHeader{Size: uint32(unsafe.Sizeof(bitmapHeader{})), Width: width, Height: -height, Planes: 1, Bits: 32}
	var bits unsafe.Pointer
	bitmap, _, callErr := createDIBSection.Call(0, uintptr(unsafe.Pointer(&header)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bitmap == 0 {
		return 0, winErr(callErr)
	}
	defer deleteObject.Call(bitmap)
	copy(unsafe.Slice((*byte)(bits), len(pixels)), pixels)
	maskData := make([]byte, int((width+15)/16*2*height))
	mask, _, callErr := createBitmap.Call(uintptr(width), uintptr(height), 1, 1, uintptr(unsafe.Pointer(&maskData[0])))
	if mask == 0 {
		return 0, winErr(callErr)
	}
	defer deleteObject.Call(mask)
	info := iconInfo{Icon: 1, Mask: mask, Color: bitmap}
	icon, _, callErr := createIconIndirect.Call(uintptr(unsafe.Pointer(&info)))
	if icon == 0 {
		return 0, winErr(callErr)
	}
	return icon, nil
}
