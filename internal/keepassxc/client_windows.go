//go:build windows

package keepassxc

import (
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/masahide/OmniSSHAgent/internal/backend"
)

// ForClient avoids a circular RPC: KeePassXC's settings/key checks synchronously
// list identities on its GUI thread, which cannot answer our browser status RPC
// until that list completes. Only the automatic unlock step is bypassed; the
// underlying backend still enforces key constraints and access restrictions.
func (b *Backend) ForClient(client backend.Client) backend.Backend {
	inner := backend.ForClient(b.Backend, client)
	if isKeePassClient(client, processExecutable) {
		return inner
	}
	return &connectionBackend{Backend: inner, owner: b}
}

func isKeePassClient(client backend.Client, executable func(uint32) (string, error)) bool {
	if client.PID != 0 {
		path, err := executable(client.PID)
		return err == nil && strings.EqualFold(filepath.Base(path), "KeePassXC.exe")
	}
	// KeePassXC 2.8 uses randomized 16-byte hex Pageant names and supplies no
	// sender HWND. This is a compatibility hint, not an authentication check:
	// Pageant validates the mapping's owner SID independently before dispatch.
	if len(client.PageantMapping) == 32 {
		_, err := hex.DecodeString(client.PageantMapping)
		return err == nil
	}
	return false
}
