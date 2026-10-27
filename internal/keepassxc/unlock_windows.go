//go:build windows

package keepassxc

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Unlocker struct {
	Executable   string
	Database     string
	KeyLoadDelay time.Duration
	AllowStart   *bool
	StartOnly    bool
}

// Unlock uses only database status and unlock requests. It never associates with
// a database, reads credentials, or handles the master password.
func (u *Unlocker) Unlock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	allowStart := u.AllowStart == nil || *u.AllowStart
	pid, executable, err := resolveRequestExecutable(u.Executable, allowStart, findProcess)
	if err != nil {
		return err
	}
	if pid == 0 {
		args := []string{"--minimized"}
		if u.Database != "" {
			args = append(args, u.Database)
		}
		cmd := exec.Command(executable, args...)
		if err := cmd.Start(); err != nil {
			return errors.New("could not start KeePassXC")
		}
		pid = uint32(cmd.Process.Pid)
		_ = cmd.Process.Release()
	}
	if u.StartOnly {
		return nil
	}

	// The browser server may still be starting. Each attempt owns and closes its
	// proxy process; retries happen only during connection/key exchange.
	var p *proxyProcess
	var crypto *cryptoSession
	startup := time.Now().Add(5 * time.Second)
	for {
		p, crypto, err = connect(ctx, filepath.Join(filepath.Dir(executable), "keepassxc-proxy.exe"))
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(startup) {
			return err
		}
		if err := pause(ctx, 100*time.Millisecond); err != nil {
			return err
		}
	}
	defer p.close()
	opened, err := p.status(ctx, crypto, false)
	if err != nil || opened {
		return err
	}

	opened, err = p.status(ctx, crypto, true)
	if err != nil {
		return err
	}
	if !opened && p.unlocked {
		opened, err = p.status(ctx, crypto, false)
		if err != nil {
			return err
		}
	}
	if !opened {
		started := time.Now()
		var window uintptr
		var hiddenAt time.Time
		var presentUntil time.Time
		var presented bool
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case item := <-p.messages:
				if item.err != nil {
					return errors.New("KeePassXC proxy disconnected")
				}
				if item.message.Action == "database-unlocked" {
					opened, err = p.status(ctx, crypto, false)
					if err != nil {
						return err
					}
				}
			case <-time.After(50 * time.Millisecond):
				if window == 0 {
					window = unlockWindow(pid)
					if window != 0 {
						presentUntil = time.Now().Add(time.Second)
						presented = restoreUnlockWindow(window)
					}
					if window == 0 && time.Since(started) >= 5*time.Second {
						return errors.New("KeePassXC did not show an unlock dialog; enable browser unlock and reopen the last database on startup")
					}
				} else if visible(window) {
					hiddenAt = time.Time{}
					// Qt can apply its startup window state after the first show.
					// Repair late minimization briefly, not for the whole unlock.
					if time.Now().Before(presentUntil) {
						if minimized, _, _ := isIconic.Call(window); minimized != 0 {
							presented = restoreUnlockWindow(window)
						} else if !presented {
							presented = activateUnlockWindow(window)
						}
					}
				} else if hiddenAt.IsZero() {
					hiddenAt = time.Now()
				} else if time.Since(hiddenAt) >= 300*time.Millisecond {
					// A final authenticated status check distinguishes cancellation
					// from an unlock whose broadcast was delayed.
					opened, err = p.status(ctx, crypto, false)
					if err != nil || !opened {
						return err
					}
				}
			}
			if opened {
				break
			}
		}
	}
	return pause(ctx, u.KeyLoadDelay)
}

func pause(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type received struct {
	message message
	err     error
}
type proxyProcess struct {
	cmd      *exec.Cmd
	input    io.WriteCloser
	messages chan received
	stop     func() bool
	unlocked bool
}

func connect(ctx context.Context, path string) (*proxyProcess, *cryptoSession, error) {
	cmd := exec.Command(path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		input.Close()
		output.Close()
		return nil, nil, err
	}
	p := &proxyProcess{cmd: cmd, input: input, messages: make(chan received, 16)}
	readCtx, cancelRead := context.WithCancel(ctx)
	p.stop = context.AfterFunc(ctx, func() { _ = cmd.Process.Kill() })
	go func() {
		defer cancelRead()
		for {
			m, err := readMessage(output)
			select {
			case p.messages <- received{m, err}:
			case <-readCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	// Cancel a blocked channel send as well as the pipe read during cleanup.
	stopProcess := p.stop
	p.stop = func() bool { cancelRead(); return stopProcess() }
	s, err := newCryptoSession()
	if err == nil {
		var hello message
		hello, err = s.handshake()
		if err == nil {
			err = writeMessage(input, hello)
		}
		if err == nil {
			var response message
			response, err = p.response(ctx, "change-public-keys")
			if err == nil {
				err = s.accept(response)
			}
		}
	}
	if err != nil {
		p.close()
		return nil, nil, err
	}
	return p, s, nil
}

func (p *proxyProcess) close() {
	p.stop()
	_ = p.input.Close()
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}

func (p *proxyProcess) response(ctx context.Context, action string) (message, error) {
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return message{}, ctx.Err()
		case <-timer.C:
			return message{}, errors.New("KeePassXC proxy response timed out")
		case item := <-p.messages:
			if item.err != nil {
				return message{}, errors.New("KeePassXC proxy disconnected")
			}
			if item.message.Action == "database-unlocked" {
				p.unlocked = true
			}
			if item.message.Action == action {
				return item.message, nil
			}
		}
	}
}

func (p *proxyProcess) status(ctx context.Context, crypto *cryptoSession, unlock bool) (bool, error) {
	request, n, err := crypto.request(unlock)
	if err != nil {
		return false, err
	}
	if err := writeMessage(p.input, request); err != nil {
		return false, errors.New("KeePassXC proxy write failed")
	}
	response, err := p.response(ctx, "get-databasehash")
	if err != nil {
		return false, err
	}
	return crypto.isOpen(response, n)
}

func resolveRequestExecutable(configured string, allowStart bool, find func(string) (uint32, string, error)) (uint32, string, error) {
	pid, path, err := resolveExecutable(configured, find)
	if err == nil && pid == 0 && !allowStart {
		return 0, "", errors.New("KeePassXC is not running and automatic startup is disabled")
	}
	return pid, path, err
}

func resolveExecutable(configured string, find func(string) (uint32, string, error)) (uint32, string, error) {
	pid, path, err := find("KeePassXC.exe")
	if err == nil && pid == 0 && configured != "" && !strings.EqualFold(filepath.Base(configured), "KeePassXC.exe") {
		pid, path, err = find(filepath.Base(configured))
	}
	if err != nil {
		return 0, "", err
	}
	if pid != 0 {
		return pid, path, nil
	}
	if configured == "" {
		return 0, "", errors.New("KeePassXC is not running and no executable is configured")
	}
	return 0, configured, nil
}

func processExecutable(pid uint32) (string, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(process)
	var path [32768]uint16
	size := uint32(len(path))
	if err := windows.QueryFullProcessImageName(process, 0, &path[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(path[:size]), nil
}

func findProcess(name string) (uint32, string, error) {
	var currentSession uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &currentSession); err != nil {
		return 0, "", err
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, "", err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), name) {
			var session uint32
			if windows.ProcessIdToSessionId(entry.ProcessID, &session) != nil || session != currentSession {
				continue
			}
			path, queryErr := processExecutable(entry.ProcessID)
			if queryErr == nil {
				return entry.ProcessID, path, nil
			}
		}
	}
	if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return 0, "", nil
	}
	return 0, "", err
}

var user32 = windows.NewLazySystemDLL("user32.dll")
var enumWindows = user32.NewProc("EnumWindows")
var getWindowPID = user32.NewProc("GetWindowThreadProcessId")
var getWindowText = user32.NewProc("GetWindowTextW")
var isWindowVisible = user32.NewProc("IsWindowVisible")
var isIconic = user32.NewProc("IsIconic")
var showWindowAsync = user32.NewProc("ShowWindowAsync")
var postMessage = user32.NewProc("PostMessageW")
var setForegroundWindow = user32.NewProc("SetForegroundWindow")
var getForegroundWindow = user32.NewProc("GetForegroundWindow")
var attachThreadInput = user32.NewProc("AttachThreadInput")
var bringWindowToTop = user32.NewProc("BringWindowToTop")
var peekMessage = user32.NewProc("PeekMessageW")

func restoreUnlockWindow(hwnd uintptr) bool {
	// Ask Qt's window procedure to restore the dialog even if the initial
	// native IsIconic state has not caught up with Qt's startup state yet.
	postMessage.Call(hwnd, 0x0112, 0xF120, 0) // WM_SYSCOMMAND / SC_RESTORE
	showWindowAsync.Call(hwnd, 9)             // SW_RESTORE; only the popup, never its owner
	return activateUnlockWindow(hwnd)
}

func activateUnlockWindow(hwnd uintptr) bool {
	if hwnd == 0 || !visible(hwnd) {
		return false
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	foreground, _, _ := getForegroundWindow.Call()
	if foreground == hwnd {
		return true
	}
	setForegroundWindow.Call(hwnd)
	if current, _, _ := getForegroundWindow.Call(); current == hwnd {
		return true
	}

	// Background agents do not normally own the last input event. Share input
	// with the foreground thread only for this activation attempt. USER calls
	// create a message queue on the pinned Go thread before AttachThreadInput.
	var msg [8]uintptr
	peekMessage.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0, 0)
	foreground, _, _ = getForegroundWindow.Call()
	foregroundThread, _, _ := getWindowPID.Call(foreground, 0)
	currentThread := uintptr(windows.GetCurrentThreadId())
	if foregroundThread != 0 && foregroundThread != currentThread {
		if attached, _, _ := attachThreadInput.Call(currentThread, foregroundThread, 1); attached != 0 {
			defer attachThreadInput.Call(currentThread, foregroundThread, 0)
		}
	}
	bringWindowToTop.Call(hwnd)
	setForegroundWindow.Call(hwnd)
	current, _, _ := getForegroundWindow.Call()
	return current == hwnd
}

type windowSearch struct {
	pid    uint32
	window uintptr
}

var windowSearches sync.Map
var windowSearchID atomic.Uintptr

var searchCallback = windows.NewCallback(func(hwnd, state uintptr) uintptr {
	value, ok := windowSearches.Load(state)
	if !ok {
		return 0
	}
	s := value.(*windowSearch)
	var pid uint32
	getWindowPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid == s.pid && visible(hwnd) {
		var title [256]uint16
		getWindowText.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), uintptr(len(title)))
		if strings.HasPrefix(windows.UTF16ToString(title[:]), "Unlock Database") {
			s.window = hwnd
			return 0
		}
	}
	return 1
})

func unlockWindow(pid uint32) uintptr {
	s := &windowSearch{pid: pid}
	id := windowSearchID.Add(1)
	windowSearches.Store(id, s)
	defer windowSearches.Delete(id)
	enumWindows.Call(searchCallback, id)
	return s.window
}

func visible(hwnd uintptr) bool { r, _, _ := isWindowVisible.Call(hwnd); return r != 0 }
