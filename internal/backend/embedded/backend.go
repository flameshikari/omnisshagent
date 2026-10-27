package embedded

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/masahide/OmniSSHAgent/internal/backend"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var ErrConfirmBeforeUseUnsupported = errors.New("embedded backend does not support confirm-before-use")

const confirmationReuseWindow = 30 * time.Second

// Backend is an ephemeral, in-process SSH agent backend. Keys are retained
// only by this instance and are never persisted by this package.
type Backend struct {
	agent.ExtendedAgent
	mu        sync.Mutex
	prompt    chan struct{}
	confirm   func(context.Context, ssh.PublicKey, string) bool
	ctx       context.Context
	keys      map[string]*keyPolicy
	listeners map[chan struct{}]struct{}
}

type keyPolicy struct {
	source   backend.KeySource
	confirm  bool
	comment  string
	expires  time.Time
	timer    *time.Timer
	approval *signatureApproval
}

type signatureApproval struct {
	digest [sha256.Size]byte
	flags  agent.SignatureFlags
	until  time.Time
}

var _ backend.Backend = (*Backend)(nil)

func New() (*Backend, error) {
	return NewWithConfirmation(nil)
}

func NewWithConfirmation(confirm func(context.Context, ssh.PublicKey, string) bool) (*Backend, error) {
	keyring := agent.NewKeyring()
	extended, ok := keyring.(agent.ExtendedAgent)
	if !ok {
		return nil, fmt.Errorf("embedded keyring does not implement agent.ExtendedAgent")
	}
	return &Backend{ExtendedAgent: extended, confirm: confirm, ctx: context.Background(), prompt: make(chan struct{}, 1), keys: make(map[string]*keyPolicy)}, nil
}

func (b *Backend) SetContext(ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ctx = ctx
}

// The keyring handles lifetime constraints; this wrapper enforces confirmation
// on every signing path, including signers returned to in-process callers.
func (b *Backend) Add(key agent.AddedKey) error {
	return b.AddWithSource(key, backend.KeySource{})
}

func (b *Backend) AddWithSource(key agent.AddedKey, source backend.KeySource) error {
	return b.addWithSource(key, source, false)
}

func (b *Backend) AddIfAbsentWithSource(key agent.AddedKey, source backend.KeySource) error {
	return b.addWithSource(key, source, true)
}

func (b *Backend) addWithSource(key agent.AddedKey, source backend.KeySource, skipExisting bool) error {
	if key.ConfirmBeforeUse && b.confirm == nil {
		return ErrConfirmBeforeUseUnsupported
	}
	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		return err
	}
	public := signer.PublicKey()
	if key.Certificate != nil {
		public = key.Certificate
	}
	policy := &keyPolicy{source: source, confirm: key.ConfirmBeforeUse, comment: key.Comment}
	key.ConfirmBeforeUse = false
	b.mu.Lock()
	defer b.mu.Unlock()
	if skipExisting {
		if found, err := backend.HasKey(b.ExtendedAgent, public); err != nil || found {
			return err
		}
	}
	if err := b.ExtendedAgent.Add(key); err != nil {
		return err
	}
	if key.LifetimeSecs != 0 {
		// Arm the event after the keyring's own deadline has been recorded.
		policy.expires = time.Now().Add(time.Duration(key.LifetimeSecs) * time.Second)
	}
	id := string(public.Marshal())
	if previous := b.keys[id]; previous != nil && previous.timer != nil {
		previous.timer.Stop()
	}
	b.keys[id] = policy
	b.watchExpiryLocked(id, policy)
	b.changedLocked()
	return nil
}

func (b *Backend) Remove(key ssh.PublicKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.ExtendedAgent.Remove(key); err != nil {
		return err
	}
	id := string(key.Marshal())
	if policy := b.keys[id]; policy != nil && policy.timer != nil {
		policy.timer.Stop()
	}
	delete(b.keys, id)
	b.changedLocked()
	return nil
}

func (b *Backend) RemoveAll() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.ExtendedAgent.RemoveAll(); err != nil {
		return err
	}
	for _, policy := range b.keys {
		if policy.timer != nil {
			policy.timer.Stop()
		}
	}
	clear(b.keys)
	b.changedLocked()
	return nil
}

func (b *Backend) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return b.SignWithFlags(key, data, 0)
}

func (b *Backend) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	return b.signWithContext(context.Background(), key, data, flags)
}

type connectionBackend struct {
	*Backend
	ctx    context.Context
	source backend.KeySource
}

func (b *Backend) ForClient(client backend.Client) backend.Backend {
	return &connectionBackend{Backend: b, ctx: context.Background(), source: backend.KeySource{Name: client.Source, Executable: client.Executable}}
}

func (b *connectionBackend) Add(key agent.AddedKey) error {
	return b.Backend.AddWithSource(key, b.source)
}

func (b *connectionBackend) ForContext(ctx context.Context) backend.Backend {
	return &connectionBackend{Backend: b.Backend, ctx: ctx, source: b.source}
}

func (b *Backend) KeySources() map[string]backend.KeySource {
	b.mu.Lock()
	defer b.mu.Unlock()
	sources := make(map[string]backend.KeySource, len(b.keys))
	now := time.Now()
	for id, policy := range b.keys {
		if policy.expires.IsZero() || now.Before(policy.expires) {
			sources[id] = policy.source
		}
	}
	return sources
}

func (b *Backend) ForContext(ctx context.Context) backend.Backend {
	return &connectionBackend{Backend: b, ctx: ctx}
}

func (b *connectionBackend) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return b.SignWithFlags(key, data, 0)
}

func (b *connectionBackend) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	return b.signWithContext(b.ctx, key, data, flags)
}

func (b *Backend) signWithContext(requestCtx context.Context, key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	id := string(key.Marshal())
	b.mu.Lock()
	policy := b.keys[id]
	runCtx := b.ctx
	if err := requestCtx.Err(); err != nil {
		b.mu.Unlock()
		return nil, err
	}
	if err := runCtx.Err(); err != nil {
		b.mu.Unlock()
		return nil, err
	}
	if policy == nil {
		b.mu.Unlock()
		return nil, errors.New("key not found")
	}
	if !policy.confirm {
		defer b.mu.Unlock()
		return b.ExtendedAgent.SignWithFlags(key, data, flags)
	}
	b.mu.Unlock()
	digest := sha256.Sum256(data)
	ctx, cancel := context.WithCancel(requestCtx)
	stop := context.AfterFunc(runCtx, cancel)
	defer func() { stop(); cancel() }()
	select {
	case b.prompt <- struct{}{}:
		defer func() { <-b.prompt }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := runCtx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	keys, err := b.ExtendedAgent.List()
	found := false
	for _, candidate := range keys {
		if string(candidate.Blob) == id {
			found = true
			break
		}
	}
	current := b.keys[id] == policy
	if err != nil {
		b.mu.Unlock()
		return nil, err
	}
	if !current || !found {
		b.mu.Unlock()
		return nil, errors.New("key is unavailable")
	}
	if approved := policy.approval; approved != nil && approved.digest == digest && approved.flags == flags && time.Now().Before(approved.until) {
		defer b.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := runCtx.Err(); err != nil {
			return nil, err
		}
		return b.ExtendedAgent.SignWithFlags(key, data, flags)
	}
	b.mu.Unlock()
	// Never hold the mutation mutex while waiting for user interaction.
	if !b.confirm(ctx, key, policy.comment) {
		return nil, errors.New("signature declined")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := runCtx.Err(); err != nil {
		return nil, err
	}
	if b.keys[id] != policy {
		return nil, errors.New("key changed while confirming signature")
	}
	signature, err := b.ExtendedAgent.SignWithFlags(key, data, flags)
	if err == nil {
		policy.approval = &signatureApproval{digest: digest, flags: flags, until: time.Now().Add(confirmationReuseWindow)}
	}
	return signature, err
}

func (b *Backend) Signers() ([]ssh.Signer, error) {
	signers, err := b.ExtendedAgent.Signers()
	if err != nil {
		return nil, err
	}
	for i, signer := range signers {
		signers[i] = &guardedSigner{backend: b, public: signer.PublicKey()}
	}
	return signers, nil
}

type guardedSigner struct {
	backend *Backend
	public  ssh.PublicKey
}

func (s *guardedSigner) PublicKey() ssh.PublicKey { return s.public }
func (s *guardedSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.backend.Sign(s.public, data)
}
func (s *guardedSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	public := s.public
	if cert, ok := public.(*ssh.Certificate); ok {
		public = cert.Key
	}
	if algorithm == "" || algorithm == public.Type() {
		return s.Sign(nil, data)
	}
	if public.Type() == ssh.KeyAlgoRSA {
		switch algorithm {
		case ssh.KeyAlgoRSASHA256:
			return s.backend.SignWithFlags(s.public, data, agent.SignatureFlagRsaSha256)
		case ssh.KeyAlgoRSASHA512:
			return s.backend.SignWithFlags(s.public, data, agent.SignatureFlagRsaSha512)
		}
	}
	return nil, errors.New("unsupported signature algorithm")
}
