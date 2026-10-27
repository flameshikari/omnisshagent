package keepassxc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/masahide/OmniSSHAgent/internal/backend/embedded"
	"golang.org/x/crypto/ssh/agent"
)

func TestConcurrentUnlockAllowsKeyLoading(t *testing.T) {
	raw, err := embedded.New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	b := Wrap(ctx, raw, func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, nil)
	finished := make(chan error, 8)
	for range 8 {
		go func() {
			keys, err := b.List()
			if err == nil && len(keys) != 1 {
				err = errors.New("loaded key was missing")
			}
			finished <- err
		}()
	}
	<-started
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	added := make(chan error, 1)
	go func() { added <- b.Add(agent.AddedKey{PrivateKey: key}) }()
	select {
	case err := <-added:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("key loading blocked by unlock")
	}
	// Give all concurrent requests time to join the same pending operation.
	time.Sleep(30 * time.Millisecond)
	close(release)
	for range 8 {
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("unlock calls=%d", calls.Load())
	}
}

func TestUnlockFailureAndShutdown(t *testing.T) {
	raw, _ := embedded.New()
	b := Wrap(context.Background(), raw, func(context.Context) error { return errors.New("unavailable") }, nil)
	if keys, err := b.List(); err != nil || len(keys) != 0 {
		t.Fatalf("must allow normal SSH fallback: keys=%v err=%v", keys, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b = Wrap(ctx, raw, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }, nil)
	done := make(chan error, 1)
	go func() { _, err := b.List(); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked")
	}
}
