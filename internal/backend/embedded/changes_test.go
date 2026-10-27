package embedded

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

func TestKeyChangeNotifications(t *testing.T) {
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	events, stop := b.SubscribeChanges()
	defer stop()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	changed := func() {
		t.Helper()
		select {
		case <-events:
		case <-time.After(time.Second):
			t.Fatal("missing change notification")
		}
	}
	if err := b.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	changed()
	keys, err := b.List()
	if err != nil || len(keys) != 1 {
		t.Fatal("added key missing")
	}
	if err := b.Lock([]byte("test")); err != nil {
		t.Fatal(err)
	}
	changed()
	if err := b.Unlock([]byte("test")); err != nil {
		t.Fatal(err)
	}
	changed()
	if err := b.Remove(keys[0]); err != nil {
		t.Fatal(err)
	}
	changed()
	if err := b.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	changed()
	if err := b.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	changed()
	stop()
	if err := b.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events:
		t.Fatal("unsubscribed listener received an event")
	default:
	}
}

func TestKeyExpiryNotificationAndCleanup(t *testing.T) {
	b, _ := New()
	events, stop := b.SubscribeChanges()
	defer stop()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Add(agent.AddedKey{PrivateKey: private, LifetimeSecs: 1}); err != nil {
		t.Fatal(err)
	}
	<-events
	select {
	case <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("key expiry did not notify the listener")
	}
	keys, err := b.List()
	if err != nil || len(keys) != 0 {
		t.Fatalf("expired key remains: count=%d err=%v", len(keys), err)
	}
	if err := b.Add(agent.AddedKey{PrivateKey: private, LifetimeSecs: 60}); err != nil {
		t.Fatal(err)
	}
	stop()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.listeners) != 0 {
		t.Fatal("subscriber leaked")
	}
	for _, policy := range b.keys {
		if policy.timer != nil {
			t.Fatal("expiry timer retains backend after unsubscribe")
		}
	}
}

func TestKeyReplacementCancelsOldExpiry(t *testing.T) {
	b, _ := New()
	events, stop := b.SubscribeChanges()
	defer stop()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Add(agent.AddedKey{PrivateKey: private, LifetimeSecs: 1}); err != nil {
		t.Fatal(err)
	}
	<-events
	if err := b.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	<-events
	select {
	case <-events:
		t.Fatal("replaced key inherited the previous expiry")
	case <-time.After(1100 * time.Millisecond):
	}
	keys, err := b.List()
	if err != nil || len(keys) != 1 {
		t.Fatal("replacement key was removed")
	}
}
