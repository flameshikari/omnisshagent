package backend

import (
	"context"

	"golang.org/x/crypto/ssh/agent"
)

// Backend is the protocol-level contract used by compatibility interfaces.
type Backend interface {
	agent.ExtendedAgent
}

// ChangeSource is optional. Notifications contain no key data and may coalesce;
// consumers fetch a fresh snapshot after receiving one and unsubscribe on close.
type ChangeSource interface {
	SubscribeChanges() (<-chan struct{}, func())
}

// Client identifies the transport peer when the protocol itself has no caller
// identity. PID must come from Windows, never from an SSH agent message.
type Client struct {
	Source         string
	Executable     string
	PID            uint32
	PageantMapping string
}

func ForClient(b Backend, client Client) Backend {
	if aware, ok := b.(interface{ ForClient(Client) Backend }); ok {
		return aware.ForClient(client)
	}
	return b
}

// ForContext scopes interactive operations to one transport connection.
func ForContext(b Backend, ctx context.Context) Backend {
	if aware, ok := b.(interface{ ForContext(context.Context) Backend }); ok {
		return aware.ForContext(ctx)
	}
	return b
}
