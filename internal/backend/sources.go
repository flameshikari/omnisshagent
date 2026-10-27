package backend

import (
	"bytes"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// KeySource describes the most recent successful add, not authenticated provenance.
type KeySource struct {
	Name       string
	File       string // Original manual-import path, retained only in memory.
	Executable string // Full path of the kernel-reported named-pipe peer, if known.
}

// KeySourceProvider exposes descriptive metadata indexed by public key blob.
type KeySourceProvider interface {
	KeySources() map[string]KeySource
}

// AddFromSource labels local imports when the backend supports source metadata.
func AddFromSource(b Backend, key agent.AddedKey, source KeySource) error {
	if aware, ok := b.(interface {
		AddWithSource(agent.AddedKey, KeySource) error
	}); ok {
		return aware.AddWithSource(key, source)
	}
	return b.Add(key)
}

// HasKey compares full public-key blobs, independently of filenames/comments.
func HasKey(b Backend, public ssh.PublicKey) (bool, error) {
	keys, err := b.List()
	if err != nil {
		return false, err
	}
	blob := public.Marshal()
	for _, key := range keys {
		if bytes.Equal(key.Blob, blob) {
			return true, nil
		}
	}
	return false, nil
}

// AddIfAbsentFromSource preserves existing keys and their constraints on import.
// Embedded backends perform the check and insertion under the same lock.
func AddIfAbsentFromSource(b Backend, key agent.AddedKey, source KeySource) error {
	if aware, ok := b.(interface {
		AddIfAbsentWithSource(agent.AddedKey, KeySource) error
	}); ok {
		return aware.AddIfAbsentWithSource(key, source)
	}
	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		return err
	}
	public := signer.PublicKey()
	if key.Certificate != nil {
		public = key.Certificate
	}
	if found, err := HasKey(b, public); err != nil || found {
		return err
	}
	return AddFromSource(b, key, source)
}
