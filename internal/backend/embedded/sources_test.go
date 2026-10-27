package embedded

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/masahide/OmniSSHAgent/internal/backend"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestKeySources(t *testing.T) {
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	id := string(public.Marshal())
	key := agent.AddedKey{PrivateKey: private, Comment: "unchanged"}
	check := func(want string) {
		t.Helper()
		if got := b.KeySources()[id].Name; got != want {
			t.Fatalf("source=%q, want %q", got, want)
		}
	}
	client := backend.ForContext(backend.ForClient(b, backend.Client{Source: "Pageant", Executable: `C:\Tools\ssh-add.exe`}), context.Background())
	if err := client.Add(key); err != nil {
		t.Fatal(err)
	}
	check("Pageant")
	if b.KeySources()[id].Executable != `C:\Tools\ssh-add.exe` {
		t.Fatal("connection context lost source executable")
	}
	// Returned maps must not mutate internal metadata.
	snapshot := b.KeySources()
	snapshot[id] = backend.KeySource{Name: "modified"}
	check("Pageant")
	if err := backend.AddFromSource(b, key, backend.KeySource{Name: "Manual", File: `C:\Keys\id_ed25519`}); err != nil {
		t.Fatal(err)
	}
	check("Manual")
	if b.KeySources()[id].File != `C:\Keys\id_ed25519` {
		t.Fatal("manual import lost its file path")
	}
	if b.KeySources()[id].Executable != "" {
		t.Fatal("manual replacement retained previous executable")
	}
	if err := b.Lock([]byte("lock")); err != nil {
		t.Fatal(err)
	}
	if err := client.Add(key); err == nil {
		t.Fatal("locked import succeeded")
	}
	check("Manual")
	if err := b.Unlock([]byte("lock")); err != nil {
		t.Fatal(err)
	}
	if err := b.Remove(public); err != nil {
		t.Fatal(err)
	}
	if len(b.KeySources()) != 0 {
		t.Fatal("removed key retained source")
	}
	if err := b.Add(key); err != nil {
		t.Fatal(err)
	}
	check("")
	if err := b.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if len(b.KeySources()) != 0 {
		t.Fatal("RemoveAll retained sources")
	}
}
