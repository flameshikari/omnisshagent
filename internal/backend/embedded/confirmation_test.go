package embedded

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestDuplicateSignatureApprovalScope(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	b, _ := NewWithConfirmation(func(context.Context, ssh.PublicKey, string) bool { calls++; return true })
	add := func() {
		t.Helper()
		if err := b.Add(agent.AddedKey{PrivateKey: private, ConfirmBeforeUse: true}); err != nil {
			t.Fatal(err)
		}
	}
	sign := func(data string, flags agent.SignatureFlags, expected int) {
		t.Helper()
		signature, err := b.SignWithFlags(public, []byte(data), flags)
		if err != nil {
			t.Fatal(err)
		}
		if err := public.Verify([]byte(data), signature); err != nil {
			t.Fatal(err)
		}
		if calls != expected {
			t.Fatalf("confirmation calls=%d, want %d", calls, expected)
		}
	}
	add()
	sign("request A", 0, 1)
	sign("request A", 0, 1)
	sign("request B", 0, 2)
	sign("request B", agent.SignatureFlagRsaSha256, 3)
	b.mu.Lock()
	b.keys[string(public.Marshal())].approval.until = time.Now().Add(-time.Second)
	b.mu.Unlock()
	sign("request B", agent.SignatureFlagRsaSha256, 4)
	if err := b.Lock([]byte("test")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SignWithFlags(public, []byte("request B"), agent.SignatureFlagRsaSha256); err == nil {
		t.Fatal("cached approval bypassed agent lock")
	}
	if err := b.Unlock([]byte("test")); err != nil {
		t.Fatal(err)
	}
	sign("request B", agent.SignatureFlagRsaSha256, 5)
	if err := b.Remove(public); err != nil {
		t.Fatal(err)
	}
	add()
	sign("request B", agent.SignatureFlagRsaSha256, 6)
}

func TestConcurrentDuplicateSignaturesShareApproval(t *testing.T) {
	public, private := newKey(t)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	b, _ := NewWithConfirmation(func(context.Context, ssh.PublicKey, string) bool {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return true
	})
	if err := b.Add(agent.AddedKey{PrivateKey: private, ConfirmBeforeUse: true}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	sign := func() { _, err := b.Sign(public, []byte("same request")); done <- err }
	go sign()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("confirmation did not start")
	}
	go sign()
	close(release)
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("duplicate signing did not finish")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("confirmation calls=%d, want 1", calls.Load())
	}
}

func TestConfirmationOnEverySigningPath(t *testing.T) {
	for _, allow := range []bool{false, true} {
		calls := 0
		public, private := newKey(t)
		b, err := NewWithConfirmation(func(_ context.Context, key ssh.PublicKey, comment string) bool {
			calls++
			if string(key.Marshal()) != string(public.Marshal()) || comment != "confirmed key" {
				t.Error("incorrect confirmation identity")
			}
			return allow
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Add(agent.AddedKey{PrivateKey: private, ConfirmBeforeUse: true, Comment: "confirmed key"}); err != nil {
			t.Fatal(err)
		}
		signers, err := b.Signers()
		if err != nil || len(signers) != 1 {
			t.Fatalf("signers=%d err=%v", len(signers), err)
		}
		data := []byte("test message")
		for index, sign := range []func() (*ssh.Signature, error){
			func() (*ssh.Signature, error) { return b.Sign(public, data) },
			func() (*ssh.Signature, error) { return b.SignWithFlags(public, data, 0) },
			func() (*ssh.Signature, error) { return signers[0].Sign(nil, data) },
			func() (*ssh.Signature, error) {
				return signers[0].(ssh.AlgorithmSigner).SignWithAlgorithm(nil, data, ssh.KeyAlgoED25519)
			},
		} {
			data = append([]byte("test message "), byte('0'+index))
			signature, err := sign()
			if !allow {
				if err == nil || signature != nil {
					t.Fatal("declined signature was returned")
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := public.Verify(data, signature); err != nil {
				t.Fatal(err)
			}
		}
		if calls != 4 {
			t.Fatalf("confirmation calls=%d, want 4", calls)
		}
		if err := b.Lock([]byte("locked")); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Sign(public, data); err == nil {
			t.Fatal("locked key signed")
		}
		if calls != 4 {
			t.Fatal("locked key prompted for confirmation")
		}
	}
}

func TestKeyReplacementInvalidatesPendingApproval(t *testing.T) {
	public, private := newKey(t)
	var b *Backend
	b, _ = NewWithConfirmation(func(context.Context, ssh.PublicKey, string) bool {
		if err := b.Remove(public); err != nil {
			t.Error(err)
		}
		if err := b.Add(agent.AddedKey{PrivateKey: private}); err != nil {
			t.Error(err)
		}
		return true
	})
	if err := b.Add(agent.AddedKey{PrivateKey: private, ConfirmBeforeUse: true}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := b.Sign(public, []byte("message")); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("approval survived a key replacement")
		}
	case <-time.After(time.Second):
		t.Fatal("confirmation blocked key mutation")
	}
}

func TestCancelledContextCannotApproveSignature(t *testing.T) {
	public, private := newKey(t)
	ctx, cancel := context.WithCancel(context.Background())
	b, _ := NewWithConfirmation(func(context.Context, ssh.PublicKey, string) bool { cancel(); return true })
	b.SetContext(ctx)
	if err := b.Add(agent.AddedKey{PrivateKey: private, ConfirmBeforeUse: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Sign(public, []byte("message")); err == nil {
		t.Fatal("cancelled request signed")
	}
}
