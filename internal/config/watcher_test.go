package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWatcherDetectsContentAndAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	w := Watcher{Path: path}
	if changed, err := w.Changed(); !changed || err == nil {
		t.Fatal("missing file not reported")
	}
	if changed, _ := w.Changed(); changed {
		t.Fatal("unchanged error repeated")
	}
	if err := os.WriteFile(path, []byte("version = 1"), 0600); err != nil {
		t.Fatal(err)
	}
	if changed, err := w.Changed(); !changed || err != nil {
		t.Fatalf("new file: changed=%v err=%v", changed, err)
	}
	if changed, err := w.Changed(); changed || err != nil {
		t.Fatal("unchanged file reported")
	}
	replacement := path + ".tmp"
	if err := os.WriteFile(replacement, []byte("version = 2"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if changed, err := w.Changed(); !changed || err != nil {
		t.Fatal("atomic replacement not detected")
	}
}
