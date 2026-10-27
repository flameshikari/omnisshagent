//go:build windows

package opensshpipe

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// PID is supplied by GetNamedPipeClientProcessId, never by the agent request.
// A bridge identifies the bridge process, not the application behind it.
func clientSource(pid uint32) (name, executable string) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "OpenSSH", ""
	}
	defer windows.CloseHandle(process)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if windows.QueryFullProcessImageName(process, 0, &buffer[0], &size) != nil || size == 0 {
		return "OpenSSH", ""
	}
	executable = windows.UTF16ToString(buffer[:size])
	return filepath.Base(executable), executable
}
