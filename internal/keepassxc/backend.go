package keepassxc

import (
	"context"
	"log/slog"
	"sync"

	"github.com/masahide/OmniSSHAgent/internal/backend"
	"golang.org/x/crypto/ssh/agent"
)

// Backend runs an unlock operation before identity requests. Mutation and signing
// requests never take the unlock mutex: KeePassXC must be able to add keys while
// a client is waiting for the unlock dialog.
type Backend struct {
	backend.Backend
	ctx     context.Context
	unlock  func(context.Context) error
	logger  *slog.Logger
	mu      sync.Mutex
	pending chan struct{}
}

func Wrap(ctx context.Context, b backend.Backend, unlock func(context.Context) error, logger *slog.Logger) *Backend {
	return &Backend{Backend: b, ctx: ctx, unlock: unlock, logger: logger}
}

type connectionBackend struct {
	backend.Backend
	owner *Backend
}

func (b *Backend) ForContext(ctx context.Context) backend.Backend {
	return &connectionBackend{Backend: backend.ForContext(b.Backend, ctx), owner: b}
}

func (b *connectionBackend) ForContext(ctx context.Context) backend.Backend {
	return &connectionBackend{Backend: backend.ForContext(b.Backend, ctx), owner: b.owner}
}

func (b *connectionBackend) List() ([]*agent.Key, error) { return b.owner.List() }

func (b *Backend) List() ([]*agent.Key, error) {
	if err := b.ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	done := b.pending
	if done == nil {
		done = make(chan struct{})
		b.pending = done
		go func() {
			defer func() {
				b.mu.Lock()
				b.pending = nil
				close(done)
				b.mu.Unlock()
			}()
			if err := b.unlock(b.ctx); err != nil && b.ctx.Err() == nil && b.logger != nil {
				// Never log protocol messages or response bodies.
				b.logger.Warn("KeePassXC unlock unavailable")
			}
		}()
	}
	b.mu.Unlock()
	select {
	case <-b.ctx.Done():
		return nil, b.ctx.Err()
	case <-done:
		return b.Backend.List()
	}
}
