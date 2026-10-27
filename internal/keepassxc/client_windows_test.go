//go:build windows

package keepassxc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/masahide/OmniSSHAgent/internal/backend"
	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"golang.org/x/crypto/ssh/agent"
)

func TestKeePassSettingsListDoesNotJoinPendingUnlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	raw, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	b := Wrap(ctx, raw, func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}, nil)
	sshDone := make(chan struct{})
	go func() { _, _ = b.List(); close(sshDone) }()
	<-started
	settings := backend.ForClient(b, backend.Client{PageantMapping: "1234567890abcdef1234567890abcdef"})
	done := make(chan error, 1)
	go func() { _, err := settings.List(); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("KeePassXC settings waited for its own unlock RPC")
	}
	select {
	case <-sshDone:
		t.Fatal("ordinary SSH request stopped waiting for unlock")
	default:
	}
	cancel()
	<-sshDone
}

func TestKeePassClientDetection(t *testing.T) {
	resolve := func(pid uint32) (string, error) {
		switch pid {
		case 10:
			return `B:\Programs\KeePassXC\KeePassXC.exe`, nil
		case 11:
			return `C:\Windows\System32\OpenSSH\ssh.exe`, nil
		default:
			return "", errors.New("unavailable")
		}
	}
	for _, test := range []struct {
		client backend.Client
		want   bool
	}{
		{backend.Client{PID: 10}, true},
		{backend.Client{PID: 11}, false},
		{backend.Client{PID: 12}, false},
		{backend.Client{PageantMapping: "1234567890abcdef1234567890abcdef"}, true},
		{backend.Client{PageantMapping: "PageantRequest12345678"}, false},
		{backend.Client{PageantMapping: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}, false},
		{backend.Client{}, false},
	} {
		if got := isKeePassClient(test.client, resolve); got != test.want {
			t.Fatalf("client=%+v got=%v want=%v", test.client, got, test.want)
		}
	}
}

func TestClientSourceSurvivesUnlockWrapper(t *testing.T) {
	raw, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	b := Wrap(context.Background(), raw, func(context.Context) error { return nil }, nil)
	for _, mapping := range []string{"", "1234567890abcdef1234567890abcdef"} {
		client := backend.ForContext(backend.ForClient(b, backend.Client{Source: "Pageant", PageantMapping: mapping}), context.Background())
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Add(agent.AddedKey{PrivateKey: private}); err != nil {
			t.Fatal(err)
		}
		keys, err := client.List()
		if err != nil || len(keys) == 0 {
			t.Fatalf("list: %v", err)
		}
	}
	for _, source := range raw.KeySources() {
		if source.Name != "Pageant" {
			t.Fatalf("source lost through unlock wrapper: %q", source)
		}
	}
}
