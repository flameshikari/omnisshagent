//go:build windows

package pageant

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

type waitingBackend struct {
	agent.ExtendedAgent
	started, added chan struct{}
}

func (b *waitingBackend) List() ([]*agent.Key, error) {
	close(b.started)
	<-b.added
	return b.ExtendedAgent.List()
}
func (b *waitingBackend) Add(key agent.AddedKey) error {
	err := b.ExtendedAgent.Add(key)
	close(b.added)
	return err
}

func TestPageantAcceptsKeysWhileIdentitiesWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := &waitingBackend{ExtendedAgent: agent.NewKeyring().(agent.ExtendedAgent), started: make(chan struct{}), added: make(chan struct{})}
	c := New(b, nil)
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()
	defer func() {
		select {
		case <-b.added:
		default:
			close(b.added)
		}
		cancel()
		<-done
	}()
	if err := <-c.Ready(); err != nil {
		t.Fatal(err)
	}
	class, _ := windows.UTF16PtrFromString(ClassName)
	window, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(class)))
	listed := make(chan error, 1)
	go func() {
		keys, err := agent.NewClient(&testPageantConnection{window: window}).List()
		if err == nil && len(keys) != 1 {
			err = fmt.Errorf("got %d keys", len(keys))
		}
		listed <- err
	}()
	select {
	case <-b.started:
	case err := <-listed:
		t.Fatalf("identities request failed before unlock: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("identities request did not reach backend")
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	added := make(chan error, 1)
	go func() {
		added <- agent.NewClient(&testPageantConnection{window: window}).Add(agent.AddedKey{PrivateKey: key})
	}()
	select {
	case err := <-added:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		close(b.added)
		t.Fatal("Pageant blocked key loading while waiting for identities")
	}
	if err := <-listed; err != nil {
		t.Fatal(err)
	}
}

var testMappingID atomic.Uint64

func TestKeePassXCMappingNames(t *testing.T) {
	for _, name := range []string{"SSHAgentRequest00001234", "PageantRequest00001234", "1234567890abcdef1234567890abcdef"} {
		if !validMappingName(name) {
			t.Fatalf("rejected compatible mapping %q", name)
		}
	}
	for _, name := range []string{"arbitrary-mapping", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", ""} {
		if validMappingName(name) {
			t.Fatalf("accepted invalid mapping %q", name)
		}
	}
}

type testPageantConnection struct {
	window   uintptr
	response bytes.Buffer
}

func (c *testPageantConnection) Read(data []byte) (int, error) { return c.response.Read(data) }
func (c *testPageantConnection) Write(data []byte) (int, error) {
	name := fmt.Sprintf("PageantRequest-%d-unlock-%d", os.Getpid(), testMappingID.Add(1))
	ptr, _ := windows.UTF16PtrFromString(name)
	mapping, err := windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_READWRITE, 0, 8196, ptr)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(mapping)
	address, err := windows.MapViewOfFile(mapping, windows.FILE_MAP_WRITE, 0, 0, 8196)
	if err != nil {
		return 0, err
	}
	defer windows.UnmapViewOfFile(address)
	memory := memoryAt(address, 8196)
	copy(memory, data)
	nameBytes := append([]byte(name), 0)
	request := copyDataStruct{Data: copyDataID, Size: uint32(len(nameBytes)), Pointer: uintptr(unsafe.Pointer(&nameBytes[0]))}
	send := user32.NewProc("SendMessageW")
	result, _, _ := send.Call(c.window, wmCopyData, 0, uintptr(unsafe.Pointer(&request)))
	if result != 1 {
		return 0, fmt.Errorf("Pageant rejected request")
	}
	length := int(memory[0])<<24 | int(memory[1])<<16 | int(memory[2])<<8 | int(memory[3])
	if length < 1 || length+4 > len(memory) {
		return 0, fmt.Errorf("invalid response length")
	}
	c.response.Write(memory[:length+4])
	return len(data), nil
}
