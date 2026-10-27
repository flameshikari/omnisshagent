//go:build windows

package opensshpipe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/masahide/OmniSSHAgent/internal/backend"
	"github.com/masahide/OmniSSHAgent/internal/interfaces/agentstream"
	"golang.org/x/sys/windows"
)

const StandardPipePath = `\\.\pipe\openssh-ssh-agent`

type Component struct {
	backend   backend.Backend
	pipePath  string
	logger    *slog.Logger
	ready     chan error
	readyOnce sync.Once
}

func New(b backend.Backend, logger *slog.Logger) *Component {
	return newWithPipePath(b, StandardPipePath, logger)
}

func newWithPipePath(b backend.Backend, pipePath string, logger *slog.Logger) *Component {
	return &Component{
		backend:  b,
		pipePath: pipePath,
		logger:   logger,
		ready:    make(chan error, 1),
	}
}

func (c *Component) Name() string          { return "openssh" }
func (c *Component) Ready() <-chan error   { return c.ready }
func (c *Component) reportReady(err error) { c.readyOnce.Do(func() { c.ready <- err }) }

func (c *Component) Start(ctx context.Context) (resultErr error) {
	defer func() {
		if resultErr != nil {
			c.reportReady(resultErr)
		}
	}()

	securityDescriptor, err := pipeSecurityDescriptor()
	if err != nil {
		return err
	}
	listener, err := winio.ListenPipe(c.pipePath, &winio.PipeConfig{
		SecurityDescriptor: securityDescriptor,
	})
	if err != nil {
		return fmt.Errorf("listen on OpenSSH Named Pipe %s: %w", c.pipePath, err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	var clients sync.WaitGroup
	defer func() {
		cancel()
		_ = listener.Close()
		clients.Wait()
	}()
	go func() {
		<-runCtx.Done()
		_ = listener.Close()
	}()

	c.reportReady(nil)
	slots := make(chan struct{}, agentstream.MaxClients)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if runCtx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept OpenSSH Named Pipe client: %w", err)
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		clients.Add(1)
		go func() {
			defer clients.Done()
			defer func() { <-slots }()
			c.handle(runCtx, conn)
		}()
	}
}

func (c *Component) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var peer backend.Client
	var handle uintptr
	if pipe, ok := conn.(interface{ Fd() uintptr }); ok {
		handle = pipe.Fd()
		_ = windows.GetNamedPipeClientProcessId(windows.Handle(handle), &peer.PID)
	}
	peer.Source, peer.Executable = clientSource(peer.PID)
	clientBackend := backend.ForContext(backend.ForClient(c.backend, peer), ctx)
	stopCloser := make(chan struct{})
	closerDone := make(chan struct{})
	go func() {
		defer close(closerDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = conn.Close()
				return
			case <-stopCloser:
				return
			case <-ticker.C:
				// Peek does not consume bytes or disturb the protocol reader.
				if handle != 0 {
					if ok, _, _ := peekNamedPipe.Call(handle, 0, 0, 0, 0, 0); ok == 0 {
						cancel()
						_ = conn.Close()
						return
					}
				}
			}
		}
	}()

	err := agentstream.Serve(clientBackend, &agentstream.Conn{Conn: conn})
	close(stopCloser)
	<-closerDone
	if err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil && c.logger != nil {
		c.logger.Warn("OpenSSH Named Pipe client request failed", "error", err)
	}
}

var peekNamedPipe = windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekNamedPipe")

func pipeSecurityDescriptor() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("get current user SID: %w", err)
	}
	if user.User.Sid == nil {
		return "", errors.New("get current user SID: token has no user SID")
	}
	return "D:P(A;;GA;;;SY)(A;;GA;;;" + user.User.Sid.String() + ")", nil
}
