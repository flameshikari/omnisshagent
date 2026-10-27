package agentstream

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

const MaxClients = 64
const MaxMessage = 1024 * 1024

var ErrPanic = errors.New("SSH agent request panicked")

// Serve isolates client failures without including sensitive panic values.
func Serve(a agent.Agent, rw io.ReadWriter) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrPanic
		}
	}()
	return agent.ServeAgent(a, rw)
}

// Conn bounds idle clients and incomplete frames. Deadlines are cleared before
// dispatch, so waiting for a user to unlock a database has no time limit.
type Conn struct {
	net.Conn
	pending []byte
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		var header [4]byte
		if err := c.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
			return 0, err
		}
		if _, err := io.ReadFull(c.Conn, header[:1]); err != nil {
			return 0, err
		}
		if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return 0, err
		}
		if _, err := io.ReadFull(c.Conn, header[1:]); err != nil {
			return 0, err
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 || size > MaxMessage {
			return 0, errors.New("invalid SSH agent frame size")
		}
		frame := make([]byte, 4+int(size))
		copy(frame, header[:])
		if _, err := io.ReadFull(c.Conn, frame[4:]); err != nil {
			return 0, err
		}
		if err := c.SetReadDeadline(time.Time{}); err != nil {
			return 0, err
		}
		c.pending = frame
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}
