//go:build windows

package tray

import (
	"bytes"
	"maps"
	"sync/atomic"

	"github.com/masahide/OmniSSHAgent/internal/backend"

	"golang.org/x/crypto/ssh/agent"
)

const wmKeysChanged = wmUser + 5

var keyChangeSequence atomic.Uint64

func (d *keysDialog) startLiveUpdates() error {
	if source, ok := d.backend.(backend.ChangeSource); ok {
		events, unsubscribe := source.SubscribeChanges()
		done := make(chan struct{})
		d.changeToken = uintptr(keyChangeSequence.Add(1))
		window, token := d.hwnd, d.changeToken
		d.stopChanges = func() { close(done); unsubscribe() }
		go func() {
			for {
				select {
				case <-done:
					return
				case _, open := <-events:
					if !open {
						return
					}
					if d.changePending.CompareAndSwap(false, true) {
						if ok, _, _ := postMessage.Call(window, wmKeysChanged, token, 0); ok == 0 {
							d.changePending.Store(false)
						}
					}
				}
			}
		}()
		return nil
	}
	// External OpenSSH agents do not provide change notifications.
	d.pollResults = make(chan keySnapshot, 1)
	if timer, _, err := user32.NewProc("SetTimer").Call(d.hwnd, 1, 1000, 0); timer == 0 {
		return winErr(err)
	}
	return nil
}

type keySnapshot struct {
	keys     []*agent.Key
	err      error
	revision uint64
}

// Only the List call runs in the worker. Window state stays on the tray thread,
// and one buffered result can finish safely even after the window is destroyed.
func (d *keysDialog) pollKeys() {
	if d.pollPending {
		select {
		case result := <-d.pollResults:
			d.pollPending = false
			if result.err == nil && result.revision == d.keysRevision {
				_ = d.replaceKeys(result.keys)
			}
		default:
			return
		}
	}
	d.pollPending = true
	backend, results, revision := d.backend, d.pollResults, d.keysRevision
	go func() {
		keys, err := backend.List()
		results <- keySnapshot{keys: keys, err: err, revision: revision}
	}()
}

func (d *keysDialog) replaceKeys(keys []*agent.Key) error {
	keys = append([]*agent.Key(nil), keys...)
	var sources map[string]backend.KeySource
	if provider, ok := d.backend.(backend.KeySourceProvider); ok {
		sources = provider.KeySources()
	}
	sameSources := maps.Equal(sources, d.keySources)
	d.keySources = sources
	d.syncSourceApps(keys, sources)
	d.sortKeys(keys)
	equal := len(keys) == len(d.keys) && sameSources
	if equal {
		for i, key := range keys {
			previous := d.keys[i]
			if key.Comment != previous.Comment || key.Format != previous.Format || !bytes.Equal(key.Blob, previous.Blob) {
				equal = false
				break
			}
		}
	}
	if equal {
		return nil
	}
	selected := d.selection()
	d.keys = keys
	return d.renderKeys(selected)
}
