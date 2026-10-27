//go:build windows

package tray

import (
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/masahide/OmniSSHAgent/internal/backend"
)

const wmKeyCount = wmUser + 6

var trayCountSequence atomic.Uint64

// Watch ownership, counters, and the notification icon stay on the tray thread.
func (t *Tray) syncKeyCount() {
	b := t.backend()
	if t.window == 0 || (t.countBackend == b && t.stopCount != nil) {
		return
	}
	t.stopKeyCount()
	t.countBackend, t.keyCount = b, 0
	if b == nil {
		return
	}
	t.countToken = uintptr(trayCountSequence.Add(1))
	window, token := t.window, t.countToken
	done := make(chan struct{})
	var events <-chan struct{}
	var tick <-chan time.Time
	var unsubscribe func()
	var ticker *time.Ticker
	if source, ok := b.(backend.ChangeSource); ok {
		events, unsubscribe = source.SubscribeChanges()
	} else {
		ticker = time.NewTicker(time.Second)
		tick = ticker.C
	}
	t.stopCount = func() {
		close(done)
		if unsubscribe != nil {
			unsubscribe()
		}
		if ticker != nil {
			ticker.Stop()
		}
	}
	go func() {
		for {
			if keys, err := b.List(); err == nil {
				postMessage.Call(window, wmKeyCount, token, uintptr(len(keys)))
			}
			select {
			case <-done:
				return
			case _, open := <-events:
				if !open {
					return
				}
			case <-tick:
			}
		}
	}()
}

func (t *Tray) stopKeyCount() {
	if t.stopCount != nil {
		t.stopCount()
		t.stopCount = nil
	}
	t.countToken = uintptr(trayCountSequence.Add(1))
	t.countBackend = nil
}

func (t *Tray) updateKeyCountTooltip() {
	copyUTF16(t.nid.Tip[:], fmt.Sprintf("OmniSSHAgent – %d keys loaded", t.keyCount))
	if t.added {
		shellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&t.nid)))
	}
}
