//go:build windows

package tray

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/masahide/OmniSSHAgent/internal/backend"
	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"github.com/masahide/OmniSSHAgent/internal/testutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestDuplicateManualImportPreservesExistingKey(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	confirmations := 0
	b, err := embedded.NewWithConfirmation(func(context.Context, ssh.PublicKey, string) bool { confirmations++; return false })
	if err != nil {
		t.Fatal(err)
	}
	original := agent.AddedKey{PrivateKey: private, Comment: "original", ConfirmBeforeUse: true, LifetimeSecs: 60}
	if err := backend.ForClient(b, backend.Client{Source: "Pageant"}).Add(original); err != nil {
		t.Fatal(err)
	}
	events, stop := b.SubscribeChanges()
	defer stop()
	for _, encrypted := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "different-filename")
		var password []byte
		if encrypted {
			password = []byte("secret")
		}
		if err := writePrivateKey(path, private, password); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := addKeyFromFile(b, path, func(string) ([]byte, bool) { t.Fatal("duplicate requested a passphrase"); return nil, false }); err != nil {
				t.Fatal(err)
			}
		}
	}
	keys, err := b.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "original" {
		t.Fatalf("duplicate changed keys: %v %v", keys, err)
	}
	if source := b.KeySources()[string(keys[0].Blob)]; source.Name != "Pageant" || source.File != "" {
		t.Fatalf("duplicate changed source: %+v", source)
	}
	select {
	case <-events:
		t.Fatal("duplicate import emitted a key change")
	default:
	}
	if _, err := b.Sign(keys[0], []byte("confirmation check")); err == nil || confirmations != 1 {
		t.Fatal("duplicate import removed signature confirmation")
	}
}

func TestImportSkipsKeyAddedWhilePrompting(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "encrypted")
	if err := writePrivateKey(path, private, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := addKeyFromFile(b, path, func(string) ([]byte, bool) {
		if err := backend.ForClient(b, backend.Client{Source: "Pageant"}).Add(agent.AddedKey{PrivateKey: private, Comment: "added while prompting"}); err != nil {
			t.Fatal(err)
		}
		return []byte("secret"), true
	}); err != nil {
		t.Fatal(err)
	}
	keys, err := b.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "added while prompting" {
		t.Fatal("import replaced key added during the prompt")
	}
	if b.KeySources()[string(keys[0].Blob)].Name != "Pageant" {
		t.Fatal("import replaced concurrent source metadata")
	}
}

type countingImportBackend struct {
	*testutil.Backend
	adds int
}

func (b *countingImportBackend) Add(key agent.AddedKey) error {
	b.adds++
	return b.Backend.Add(key)
}

func TestDuplicateImportExternalBackend(t *testing.T) {
	b := &countingImportBackend{Backend: testutil.NewBackend()}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, encrypted := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "key")
		var password []byte
		if encrypted {
			password = []byte("secret")
		}
		if err := writePrivateKey(path, private, password); err != nil {
			t.Fatal(err)
		}
		if err := addKeyFromFile(b, path, func(string) ([]byte, bool) { t.Fatal("duplicate requested a password"); return nil, false }); err != nil {
			t.Fatal(err)
		}
	}
	if b.adds != 1 {
		t.Fatalf("Add called %d times, want 1", b.adds)
	}
}
