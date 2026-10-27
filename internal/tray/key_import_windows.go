//go:build windows

package tray

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/masahide/OmniSSHAgent/internal/backend"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"os"
	"path/filepath"
	"strings"
)

func clearBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	zeros := make([]byte, len(b))
	subtle.ConstantTimeCopy(1, b, zeros)
}

func addKeyFromFile(b backend.Backend, path string, askPass func(string) ([]byte, bool)) error {
	name := filepath.Base(path)
	if b == nil {
		return fmt.Errorf("The SSH agent is unavailable. Cannot add %s.", name)
	}
	if strings.EqualFold(filepath.Ext(path), ".ppk") {
		return fmt.Errorf("%s is a PuTTY key. Convert it to OpenSSH format.", name)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("Could not read %s.", name)
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("Key file %s was not found.", name)
		}
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("Access to %s was denied.", name)
		}
		return fmt.Errorf("Could not read %s.", name)
	}
	defer clearBytes(data)
	key, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if missing.PublicKey != nil {
			found, listErr := backend.HasKey(b, missing.PublicKey)
			if listErr != nil {
				return fmt.Errorf("Could not check whether %s is already loaded.", name)
			}
			if found {
				return nil
			}
		}
		if askPass == nil {
			return fmt.Errorf("A password is required to unlock %s.", name)
		}
		fingerprint := ""
		if missing.PublicKey != nil {
			fingerprint = ssh.FingerprintSHA256(missing.PublicKey)
		}
		pass, ok := askPass(fingerprint)
		if !ok {
			return errDialogCanceled
		}
		defer clearBytes(pass)
		if len(pass) == 0 {
			return fmt.Errorf("Empty password for %s.", name)
		}
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(data, pass)
		if err != nil {
			return fmt.Errorf("Password decryption failed for %s.", name)
		}
	}
	if err != nil {
		return fmt.Errorf("%s is not a valid key.", name)
	}
	if err := backend.AddIfAbsentFromSource(b, agent.AddedKey{PrivateKey: key, Comment: filepath.Base(path)}, backend.KeySource{Name: "Manual", File: absolute}); err != nil {
		return fmt.Errorf("Could not add %s to the SSH agent.", name)
	}
	return nil
}
