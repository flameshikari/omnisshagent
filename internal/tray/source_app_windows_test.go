//go:build windows

package tray

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/masahide/OmniSSHAgent/internal/backend"
	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"golang.org/x/crypto/ssh/agent"
)

func TestManageKeysSourceApp(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	name := executableDisplayName(path)
	if name == "" || name == "powershell.exe" {
		t.Fatalf("missing executable description: %q", name)
	}
	b, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	add := func(path string) {
		t.Helper()
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		client := backend.ForClient(b, backend.Client{Source: "powershell.exe", Executable: path})
		if err := client.Add(agent.AddedKey{PrivateKey: private}); err != nil {
			t.Fatal(err)
		}
	}
	add(path)
	add(strings.ToUpper(path))
	tray := New("", t.TempDir(), func() {})
	tray.SetBackend(b)
	tray.openKeys(0)
	d := keysDlg
	if d == nil {
		t.Fatal("Manage Keys did not open")
	}
	defer d.close()
	id := sourceAppPath(path)
	app := d.sourceApps[id]
	if len(d.sourceApps) != 1 || app.icon == 0 || app.name != name || d.keyCell(d.keys[0], 2) != name {
		t.Fatalf("source presentation: entries=%d name=%q icon=%x", len(d.sourceApps), app.name, app.icon)
	}
	if width, height, live := sourceIconSize(app.icon); !live || width != d.m.s(16) || height != d.m.s(16) {
		t.Fatalf("source icon size=%dx%d valid=%v", width, height, live)
	}
	if err := d.refresh(); err != nil {
		t.Fatal(err)
	}
	if d.sourceApps[id].icon != app.icon {
		t.Fatal("unchanged executable reloaded its icon")
	}
	if target := os.Getenv("OMNI_SOURCE_PREVIEW"); target != "" {
		saveSettingsPreview(t, d.hwnd, target)
	}
	keys, err := b.List()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Remove(keys[0]); err != nil {
		t.Fatal(err)
	}
	if err := d.refresh(); err != nil {
		t.Fatal(err)
	}
	if d.sourceApps[id].icon != app.icon {
		t.Fatal("removing one of two matching sources released the shared icon")
	}
	if err := b.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if err := d.refresh(); err != nil {
		t.Fatal(err)
	}
	if len(d.sourceApps) != 0 {
		t.Fatal("removed keys retained source resources")
	}
	if _, _, live := sourceIconSize(app.icon); live {
		t.Fatal("removed source leaked its icon handle")
	}
	add(path)
	if err := d.refresh(); err != nil {
		t.Fatal(err)
	}
	icon := d.sourceApps[id].icon
	d.close()
	if len(d.sourceApps) != 0 {
		t.Fatal("closed window retained source resources")
	}
	if _, _, live := sourceIconSize(icon); live {
		t.Fatal("closed window leaked its source icon")
	}
}

func sourceIconSize(icon uintptr) (int32, int32, bool) {
	var info struct {
		Icon        int32
		X, Y        uint32
		Mask, Color uintptr
	}
	if ok, _, _ := user32.NewProc("GetIconInfo").Call(icon, uintptr(unsafe.Pointer(&info))); ok == 0 {
		return 0, 0, false
	}
	defer deleteObject.Call(info.Mask)
	if info.Color != 0 {
		defer deleteObject.Call(info.Color)
	}
	var bitmap struct {
		Type, Width, Height, WidthBytes int32
		Planes, BitsPixel               uint16
		Bits                            uintptr
	}
	image := info.Color
	if image == 0 {
		image = info.Mask
	}
	if count, _, _ := gdi32.NewProc("GetObjectW").Call(image, unsafe.Sizeof(bitmap), uintptr(unsafe.Pointer(&bitmap))); count == 0 {
		return 0, 0, false
	}
	if info.Color == 0 {
		bitmap.Height /= 2
	}
	return bitmap.Width, bitmap.Height, true
}

func TestSourceAppMissingResources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-resources.exe")
	if err := os.WriteFile(path, []byte("not a PE resource file"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{path, filepath.Join(t.TempDir(), "missing.exe")} {
		app := loadSourceApp(path, 16)
		defer destroyIcon.Call(app.icon)
		if app.name != "" || app.icon == 0 {
			t.Fatalf("missing resources did not use the default EXE icon: %+v", app)
		}
		stock := stockSourceIcon(2, 16)
		defer destroyIcon.Call(stock)
		if sourceIconDigest(t, app.icon) != sourceIconDigest(t, stock) {
			t.Fatal("fallback differs from Windows' default application icon")
		}
		d := &keysDialog{keySources: map[string]backend.KeySource{"key": {Name: "original.exe", Executable: path}}, sourceApps: map[string]sourceApp{sourceAppPath(path): app}}
		if got := d.keyCell(&agent.Key{Blob: []byte("key")}, 2); got != "original.exe" {
			t.Fatalf("fallback=%q", got)
		}
	}
}

func TestOpenSSHSourceIcon(t *testing.T) {
	data, err := assets.ReadFile("assets/openssh.ico")
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int32{16, 20, 24, 32} {
		expected, err := createIcon(data, size, size)
		if err != nil {
			t.Fatal(err)
		}
		defer destroyIcon.Call(expected)
		app := loadSourceApp(`C:\missing\SSH-ADD.EXE`, size)
		defer destroyIcon.Call(app.icon)
		if sourceIconDigest(t, app.icon) != sourceIconDigest(t, expected) {
			t.Fatalf("ssh-add did not use the embedded OpenSSH icon at %dpx", size)
		}
	}
}

func TestManualSourceFolder(t *testing.T) {
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
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := writePrivateKey(path, private, nil); err != nil {
		t.Fatal(err)
	}
	if err := addKeyFromFile(b, path, nil); err != nil {
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
	source := d.keySources[string(d.keys[0].Blob)]
	if source.Name != "Manual" || source.File != path || source.Executable != "" {
		t.Fatalf("manual source=%+v", source)
	}
	icon := d.sourceApps["manual"].icon
	if icon == 0 {
		t.Fatal("manual source has no standard icon")
	}
	previous := openPath
	var opened []string
	openPath = func(path string) error { opened = append(opened, path); return nil }
	defer func() { openPath = previous }()
	var activation struct {
		Header struct {
			Window, ID uintptr
			Code       int32
		}
		Item, SubItem               int32
		NewState, OldState, Changed uint32
		Action                      point
		Param                       uintptr
		KeyFlags                    uint32
	}
	activation.Header.Window, activation.Header.Code = d.list, -2
	activation.Item, activation.SubItem = 0, 2
	sendMessage.Call(d.hwnd, 0x004E, idKeyList, uintptr(unsafe.Pointer(&activation)))
	if len(opened) != 0 {
		t.Fatal("single-click on Manual opened a folder")
	}
	activation.Header.Code = -3
	for column := range keyColumnNames {
		activation.SubItem = int32(column)
		sendMessage.Call(d.hwnd, 0x004E, idKeyList, uintptr(unsafe.Pointer(&activation)))
		if len(opened) != column+1 || opened[column] != filepath.Dir(path) {
			t.Fatalf("manual row double-click opened %v", opened)
		}
	}
	d.close()
	if _, _, live := sourceIconSize(icon); live {
		t.Fatal("closed window leaked its Manual icon")
	}
}

func sourceIconDigest(t *testing.T, icon uintptr) [32]byte {
	t.Helper()
	var info struct {
		Icon        int32
		X, Y        uint32
		Mask, Color uintptr
	}
	if ok, _, _ := user32.NewProc("GetIconInfo").Call(icon, uintptr(unsafe.Pointer(&info))); ok == 0 {
		t.Fatal("invalid icon handle")
	}
	defer deleteObject.Call(info.Mask)
	defer deleteObject.Call(info.Color)
	var bitmap struct {
		Type, Width, Height, WidthBytes int32
		Planes, BitsPixel               uint16
		Bits                            uintptr
	}
	if count, _, _ := gdi32.NewProc("GetObjectW").Call(info.Color, unsafe.Sizeof(bitmap), uintptr(unsafe.Pointer(&bitmap))); count == 0 {
		t.Fatal("icon has no color bitmap")
	}
	pixels := make([]byte, int(bitmap.WidthBytes)*int(bitmap.Height))
	if len(pixels) == 0 {
		t.Fatal("empty icon bitmap")
	}
	if count, _, _ := gdi32.NewProc("GetBitmapBits").Call(info.Color, uintptr(len(pixels)), uintptr(unsafe.Pointer(&pixels[0]))); int(count) != len(pixels) {
		t.Fatal("could not read icon pixels")
	}
	return sha256.Sum256(pixels)
}
