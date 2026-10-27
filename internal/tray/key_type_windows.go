//go:build windows

package tray

import "strings"

func displayKeyType(kind string) string {
	original := kind
	certificate := strings.Contains(kind, "-cert-v01@")
	if certificate {
		kind = strings.SplitN(kind, "-cert-v01@", 2)[0]
	}
	switch kind {
	case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
		kind = "RSA"
	case "ssh-dss":
		kind = "DSA"
	case "ssh-ed25519":
		kind = "ED25519"
	case "ecdsa-sha2-nistp256":
		kind = "ECDSA P-256"
	case "ecdsa-sha2-nistp384":
		kind = "ECDSA P-384"
	case "ecdsa-sha2-nistp521":
		kind = "ECDSA P-521"
	case "sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519":
		kind = "ED25519-SK"
	case "sk-ecdsa-sha2-nistp256@openssh.com", "sk-ecdsa-sha2-nistp256":
		kind = "ECDSA-SK P-256"
	case "ssh-mldsa-44":
		kind = "ML-DSA-44"
	case "ssh-mldsa-65":
		kind = "ML-DSA-65"
	case "ssh-mldsa-87":
		kind = "ML-DSA-87"
	default:
		return original
	}
	if certificate {
		kind += " Cert"
	}
	return kind
}
