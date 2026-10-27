//go:build windows

package tray

import "testing"

func TestDisplayKeyType(t *testing.T) {
	for _, test := range []struct{ raw, want string }{
		{"ssh-ed25519", "ED25519"},
		{"ssh-rsa", "RSA"},
		{"rsa-sha2-512", "RSA"},
		{"ssh-dss", "DSA"},
		{"ecdsa-sha2-nistp256", "ECDSA P-256"},
		{"ecdsa-sha2-nistp384", "ECDSA P-384"},
		{"ecdsa-sha2-nistp521", "ECDSA P-521"},
		{"sk-ssh-ed25519@openssh.com", "ED25519-SK"},
		{"sk-ecdsa-sha2-nistp256@openssh.com", "ECDSA-SK P-256"},
		{"ssh-ed25519-cert-v01@openssh.com", "ED25519 Cert"},
		{"sk-ssh-ed25519-cert-v01@openssh.com", "ED25519-SK Cert"},
		{"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", "ECDSA-SK P-256 Cert"},
		{"ssh-mldsa-44", "ML-DSA-44"},
		{"ssh-mldsa-65-cert-v01@golang.org", "ML-DSA-65 Cert"},
		{"future-key@example.org", "future-key@example.org"},
		{"future-key-cert-v01@example.org", "future-key-cert-v01@example.org"},
	} {
		if got := displayKeyType(test.raw); got != test.want {
			t.Errorf("%q: got %q, want %q", test.raw, got, test.want)
		}
	}
}
