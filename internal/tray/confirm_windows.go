//go:build windows

package tray

import (
	"context"
	"runtime"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// ConfirmSignature defaults to Cancel, expires after ten seconds, and never displays signing data. Agent
// protocol requests do not provide a trustworthy remote host or caller identity.
func ConfirmSignature(ctx context.Context, key ssh.PublicKey, comment string) bool {
	if ctx.Err() != nil {
		return false
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	comment = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, comment)
	if len([]rune(comment)) > 160 {
		comment = string([]rune(comment)[:160]) + "…"
	}
	return showSignatureDialog(ctx, ssh.FingerprintSHA256(key), comment)
}
