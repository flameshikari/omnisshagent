//go:build windows

package tray

import (
	"image"
	"image/png"
	"os"
	"testing"
)

func TestFluentGlyphTransparencyAndTheme(t *testing.T) {
	black, err := fluentIconPixels(16, 16, true)
	if err != nil {
		t.Fatal(err)
	}
	white, err := fluentIconPixels(16, 16, false)
	if err != nil {
		t.Fatal(err)
	}
	visible, transparent := false, false
	for i := 0; i < len(white); i += 4 {
		alpha := white[i+3]
		visible = visible || alpha != 0
		transparent = transparent || alpha == 0
		for channel := 0; channel < 3; channel++ {
			if black[i+channel] != 0 || white[i+channel] != alpha {
				t.Fatal("glyph colors are not premultiplied black/white")
			}
		}
	}
	if !visible || !transparent {
		t.Fatal("glyph has no usable transparency")
	}
	if path := os.Getenv("OMNI_GLYPH_PREVIEW"); path != "" {
		glyph, err := rasterFontGlyph("Segoe Fluent Icons", 16)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Segoe Fluent Icons U+E192 at 16px: ink bounds %dx%d", glyph.Width, glyph.Height)
		preview := image.NewRGBA(image.Rect(0, 0, 16, 16))
		for i := 0; i < len(white); i += 4 {
			value := white[i] + byte(uint32(32)*(255-uint32(white[i+3]))/255)
			preview.Pix[i], preview.Pix[i+1], preview.Pix[i+2], preview.Pix[i+3] = value, value, value, 255
		}
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := png.Encode(file, preview); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDirectWriteGlyphRendering(t *testing.T) {
	for _, size := range []int32{16, 20, 24, 32, 40, 48} {
		for _, light := range []bool{true, false} {
			pixels, err := directWriteIconPixels(size, size, light)
			if err != nil {
				t.Fatalf("%dpx light=%v: %v", size, light, err)
			}
			visible, transparent := false, false
			for i := 0; i < len(pixels); i += 4 {
				alpha := pixels[i+3]
				visible = visible || alpha != 0
				transparent = transparent || alpha == 0
				for c := 0; c < 3; c++ {
					want := alpha
					if light {
						want = 0
					}
					if pixels[i+c] != want {
						t.Fatal("DirectWrite icon has color fringes or invalid premultiplication")
					}
				}
			}
			if !visible || !transparent {
				t.Fatal("DirectWrite returned an unusable alpha mask")
			}
		}
	}
}

func TestDirectWriteGlyphOrientation(t *testing.T) {
	const size = 32
	pixels, err := directWriteIconPixels(size, size, false)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := gdiIconPixels(size, size, false)
	if err != nil {
		t.Fatal(err)
	}
	var upright, flipped int64
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			want := int64(reference[(y*size+x)*4+3])
			upright += abs(int64(pixels[(y*size+x)*4+3]) - want)
			flipped += abs(int64(pixels[((size-1-y)*size+x)*4+3]) - want)
		}
	}
	if upright >= flipped {
		t.Fatalf("DirectWrite glyph is vertically mirrored: upright difference=%d, flipped=%d", upright, flipped)
	}
}
