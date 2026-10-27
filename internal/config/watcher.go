package config

import (
	"crypto/sha256"
	"os"
)

// Watcher compares contents, including atomic file replacements. Call Changed
// serially; transient invalid edits are validated by the caller before applying.
type Watcher struct {
	Path      string
	seen      bool
	hash      [32]byte
	lastError string
}

func (w *Watcher) Changed() (bool, error) {
	data, err := os.ReadFile(w.Path)
	errorText := ""
	if err != nil {
		errorText = err.Error()
	}
	hash := sha256.Sum256(data)
	changed := !w.seen || hash != w.hash || errorText != w.lastError
	w.seen, w.hash, w.lastError = true, hash, errorText
	return changed, err
}
