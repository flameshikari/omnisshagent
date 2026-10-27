package embedded

import "time"

func (b *Backend) SubscribeChanges() (<-chan struct{}, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	changes := make(chan struct{}, 1)
	if b.listeners == nil {
		b.listeners = make(map[chan struct{}]struct{})
	}
	b.listeners[changes] = struct{}{}
	if len(b.listeners) == 1 {
		for id, policy := range b.keys {
			b.watchExpiryLocked(id, policy)
		}
	}
	return changes, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		delete(b.listeners, changes)
		if len(b.listeners) == 0 {
			for _, policy := range b.keys {
				if policy.timer != nil {
					policy.timer.Stop()
					policy.timer = nil
				}
			}
		}
	}
}

func (b *Backend) changedLocked() {
	for listener := range b.listeners {
		select {
		case listener <- struct{}{}:
		default:
		}
	}
}

// Deadline notifications exist only while a consumer is subscribed. They neither
// poll nor keep the backend and private keys alive after its UI is closed.
func (b *Backend) watchExpiryLocked(id string, policy *keyPolicy) {
	if len(b.listeners) == 0 || policy.expires.IsZero() || policy.timer != nil {
		return
	}
	policy.timer = time.AfterFunc(time.Until(policy.expires), func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.keys[id] != policy {
			return
		}
		delete(b.keys, id)
		b.changedLocked()
	})
}

func (b *Backend) Lock(passphrase []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.ExtendedAgent.Lock(passphrase); err != nil {
		return err
	}
	for _, policy := range b.keys {
		policy.approval = nil
	}
	b.changedLocked()
	return nil
}

func (b *Backend) Unlock(passphrase []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.ExtendedAgent.Unlock(passphrase); err != nil {
		return err
	}
	b.changedLocked()
	return nil
}
