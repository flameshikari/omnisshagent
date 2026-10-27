package agentstream

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type panicAgent struct{ agent.Agent }

func (panicAgent) List() ([]*agent.Key, error) { panic("sensitive value") }

func TestPanicIsIsolated(t *testing.T) {
	var out bytes.Buffer
	err := Serve(panicAgent{}, struct {
		io.Reader
		io.Writer
	}{
		bytes.NewReader([]byte{0, 0, 0, 1, 11}), &out,
	})
	if !errors.Is(err, ErrPanic) {
		t.Fatalf("err=%v", err)
	}
}

func TestMalformedEd25519RequestFailsWithoutPanic(t *testing.T) {
	request := ssh.Marshal(struct {
		Type      byte
		Algorithm string
		Public    []byte
		Private   []byte
		Comment   string
	}{17, ssh.KeyAlgoED25519, nil, []byte{1}, ""})
	frame := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(frame, uint32(len(request)))
	copy(frame[4:], request)
	var out bytes.Buffer
	err := agent.ServeAgent(agent.NewKeyring(), struct {
		io.Reader
		io.Writer
	}{bytes.NewReader(frame), &out})
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), []byte{0, 0, 0, 1, 5}) {
		t.Fatalf("response=%x", out.Bytes())
	}
}

func TestRejectsOversizedFrames(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], MaxMessage+1)
		_, _ = client.Write(header[:])
	}()
	_, err := (&Conn{Conn: server}).Read(make([]byte, 4))
	if err == nil {
		t.Fatal("oversized frame accepted")
	}
}

type deadlineConn struct {
	net.Conn
	readDeadline time.Time
}

func (c *deadlineConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline = deadline
	return c.Conn.SetReadDeadline(deadline)
}

func TestDeadlineClearedBeforeBackendDispatch(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() { _, _ = client.Write([]byte{0, 0, 0, 1, 11}) }()
	tracked := &deadlineConn{Conn: server}
	frame := make([]byte, 5)
	if _, err := io.ReadFull(&Conn{Conn: tracked}, frame); err != nil {
		t.Fatal(err)
	}
	if !tracked.readDeadline.IsZero() {
		t.Fatal("unlock would retain a read deadline")
	}
}

func TestPartialHeaderTimesOut(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() { _, _ = client.Write([]byte{0}) }()
	started := time.Now()
	_, err := (&Conn{Conn: server}).Read(make([]byte, 4))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || time.Since(started) > 8*time.Second {
		t.Fatalf("partial header timeout: %v", err)
	}
}
