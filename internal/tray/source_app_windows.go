//go:build windows

package tray

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/masahide/OmniSSHAgent/internal/backend"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

type sourceApp struct {
	name string
	icon uintptr
}

func sourceAppID(source backend.KeySource) string {
	switch source.Name {
	case "Manual":
		return "manual"
	case "Pageant":
		return "pageant"
	}
	return sourceAppPath(source.Executable)
}

func sourceAppPath(path string) string {
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	return strings.ToLower(filepath.Clean(path))
}

// Resource reads happen once per executable during refresh, never during paint.
func (d *keysDialog) syncSourceApps(keys []*agent.Key, sources map[string]backend.KeySource) {
	wanted := make(map[string]backend.KeySource)
	for _, key := range keys {
		source := sources[string(key.Blob)]
		if id := sourceAppID(source); id != "" {
			wanted[id] = source
		}
	}
	for id, app := range d.sourceApps {
		if _, keep := wanted[id]; !keep {
			if app.icon != 0 {
				destroyIcon.Call(app.icon)
			}
			delete(d.sourceApps, id)
		}
	}
	if len(wanted) != 0 && d.sourceApps == nil {
		d.sourceApps = make(map[string]sourceApp)
	}
	for id, source := range wanted {
		if _, loaded := d.sourceApps[id]; !loaded {
			app := sourceApp{}
			switch source.Name {
			case "Manual":
				app.icon = stockSourceIcon(81, d.m.s(16)) // SIID_KEY (imageres.dll)
			case "Pageant":
				if data, err := assets.ReadFile("assets/pageant.ico"); err == nil {
					app.icon, _ = createIcon(data, d.m.s(16), d.m.s(16))
				}
			default:
				app = loadSourceApp(source.Executable, d.m.s(16))
			}
			d.sourceApps[id] = app
		}
	}
}

func (d *keysDialog) clearSourceApps() {
	for _, app := range d.sourceApps {
		if app.icon != 0 {
			destroyIcon.Call(app.icon)
		}
	}
	clear(d.sourceApps)
}

func loadSourceApp(path string, size int32) sourceApp {
	app := sourceApp{name: executableDisplayName(path)}
	if strings.EqualFold(filepath.Base(path), "ssh-add.exe") {
		if data, err := assets.ReadFile("assets/openssh.ico"); err == nil {
			app.icon, _ = createIcon(data, size, size)
		}
	}
	if app.icon == 0 {
		app.icon = extractSourceIcon(path, 0, size)
	}
	if app.icon == 0 {
		app.icon = stockSourceIcon(2, size)
	} // SIID_APPLICATION
	return app
}

func extractSourceIcon(path string, index int32, size int32) uintptr {
	encoded, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}
	var icon uintptr
	result, _, _ := shell32.NewProc("SHDefExtractIconW").Call(uintptr(unsafe.Pointer(encoded)), uintptr(index), 0, uintptr(unsafe.Pointer(&icon)), 0, uintptr(size))
	if int32(result) != 0 && icon != 0 {
		destroyIcon.Call(icon)
		icon = 0
	}
	return icon
}

func stockSourceIcon(id uint32, size int32) uintptr {
	var info struct {
		Size                   uint32
		Icon                   uintptr
		SystemIndex, IconIndex int32
		Path                   [260]uint16
	}
	info.Size = uint32(unsafe.Sizeof(info))
	result, _, _ := shell32.NewProc("SHGetStockIconInfo").Call(uintptr(id), 0, uintptr(unsafe.Pointer(&info)))
	if int32(result) != 0 {
		return 0
	}
	return extractSourceIcon(windows.UTF16ToString(info.Path[:]), info.IconIndex, size)
}

// Query lengths are bytes for Translation and UTF-16 characters for strings.
// Validate the returned range before slicing the version-resource buffer.
func versionValue(block []byte, key string, unit uint32) []byte {
	if len(block) == 0 {
		return nil
	}
	var pointer unsafe.Pointer
	var length uint32
	if windows.VerQueryValue(unsafe.Pointer(&block[0]), key, unsafe.Pointer(&pointer), &length) != nil || pointer == nil {
		return nil
	}
	offset := uintptr(pointer) - uintptr(unsafe.Pointer(&block[0]))
	count := uint64(length) * uint64(unit)
	if offset > uintptr(len(block)) || count > uint64(len(block))-uint64(offset) {
		return nil
	}
	return block[offset : uint64(offset)+count]
}

func executableDisplayName(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 || size > 8<<20 {
		return ""
	}
	block := make([]byte, size)
	if windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&block[0])) != nil {
		return ""
	}
	translations := versionValue(block, `\VarFileInfo\Translation`, 1)
	var languages []string
	for len(translations) >= 4 {
		languages = append(languages, fmt.Sprintf("%04x%04x", binary.LittleEndian.Uint16(translations), binary.LittleEndian.Uint16(translations[2:])))
		translations = translations[4:]
	}
	languages = append(languages, "040904b0", "040904e4")
	for _, field := range []string{"FileDescription", "ProductName"} {
		for _, language := range languages {
			value := versionValue(block, `\StringFileInfo\`+language+`\`+field, 2)
			text := make([]uint16, len(value)/2)
			for i := range text {
				text[i] = binary.LittleEndian.Uint16(value[2*i:])
			}
			if name := strings.TrimSpace(windows.UTF16ToString(text)); name != "" {
				return name
			}
		}
	}
	return ""
}
