//go:build windows

package tray

import (
	"github.com/masahide/OmniSSHAgent/internal/config"
	"os"
	"path/filepath"
	"strings"
)

type middlewareOption struct{ value, label, executable string }

var middlewareOptions = []middlewareOption{
	{config.MiddlewareKeePassXC, "KeePassXC", "KeePassXC.exe"},
}

const embeddedBackendNote = "Keys are held only in memory and are lost when OmniSSHAgent exits.\r\n" +
	`Embedded mode exposes \\.\pipe\openssh-ssh-agent; another agent must not own this pipe.`

func (d *settingsDialog) storeMiddlewareProfile() {
	if d.middlewareCurrent == "" {
		return
	}
	if d.middlewareProfiles == nil {
		d.middlewareProfiles = make(map[string]config.MiddlewareProgramConfig)
	}
	database := windowText(d.middlewareDatabase)
	useDatabase := isChecked(d.middlewareDatabaseEnabled)
	useExecutable := isChecked(d.middlewareExecutableEnabled)
	d.middlewareProfiles[d.middlewareCurrent] = config.MiddlewareProgramConfig{
		Database:        &database,
		UseDatabase:     &useDatabase,
		UseExecutable:   &useExecutable,
		Executable:      windowText(d.middlewarePath),
		UnlockOnRequest: isChecked(d.middlewareUnlock),
		StartOnRequest:  isChecked(d.middlewareStart),
	}
}

func (d *settingsDialog) loadMiddlewareProfile() {
	profile := d.middlewareProfiles[d.middlewareCurrent]
	setWindowText(d.middlewarePath, profile.Executable)
	database := ""
	if profile.Database != nil {
		database = *profile.Database
	}
	setWindowText(d.middlewareDatabase, database)
	setChecked(d.middlewareDatabaseEnabled, profile.UsesDatabase())
	setChecked(d.middlewareExecutableEnabled, profile.UsesExecutable())
	setChecked(d.middlewareUnlock, profile.UnlockOnRequest)
	setChecked(d.middlewareStart, profile.StartOnRequest)
	d.updateMiddlewareControls()
}

func (d *settingsDialog) selectMiddleware() {
	i := comboIndex(d.middlewareProgram)
	if i < 0 || i >= len(middlewareOptions) || middlewareOptions[i].value == d.middlewareCurrent {
		return
	}
	d.storeMiddlewareProfile()
	d.middlewareCurrent = middlewareOptions[i].value
	d.loadMiddlewareProfile()
}

func (d *settingsDialog) updateMiddlewareControls() {
	var enabled uintptr
	if isChecked(d.middlewareEnabled) {
		enabled = 1
	}
	for _, window := range []uintptr{d.middlewareProgram, d.middlewareUnlock, d.middlewareStart} {
		enableWindow.Call(window, enabled)
	}
	if !isChecked(d.middlewareStart) {
		enabled = 0
	}
	for _, window := range []uintptr{d.middlewareExecutableEnabled, d.middlewareDatabaseEnabled} {
		enableWindow.Call(window, enabled)
	}
	executableEnabled := enabled
	if !isChecked(d.middlewareExecutableEnabled) {
		executableEnabled = 0
	}
	for _, window := range []uintptr{d.middlewarePath, d.middlewareBrowse} {
		enableWindow.Call(window, executableEnabled)
	}
	if !isChecked(d.middlewareDatabaseEnabled) {
		enabled = 0
	}
	for _, window := range []uintptr{d.middlewareDatabase, d.middlewareDatabaseBrowse} {
		enableWindow.Call(window, enabled)
	}
}

func (d *settingsDialog) browseMiddleware() {
	initialDir := os.Getenv("ProgramFiles")
	option := middlewareOptions[0]
	for _, candidate := range middlewareOptions {
		if candidate.value == d.middlewareCurrent {
			option = candidate
			break
		}
	}
	initialFile := option.executable
	if current := strings.TrimSpace(windowText(d.middlewarePath)); current != "" {
		initialDir = filepath.Dir(current)
		initialFile = filepath.Base(current)
	}
	path, ok := pickOpenFile(d.hwnd, option.label+" executable", initialDir, initialFile,
		[]string{option.label, option.executable, "Executable files", "*.exe"}, true)
	if ok {
		setWindowText(d.middlewarePath, path)
	}
}

func (d *settingsDialog) browseMiddlewareDatabase() {
	initialDir, initialFile := os.Getenv("USERPROFILE"), ""
	if current := strings.TrimSpace(windowText(d.middlewareDatabase)); current != "" {
		initialDir, initialFile = filepath.Dir(current), filepath.Base(current)
	}
	path, ok := pickOpenFile(d.hwnd, "Database", initialDir, initialFile,
		[]string{"KeePass databases", "*.kdbx", "All files", "*.*"}, true)
	if ok {
		setWindowText(d.middlewareDatabase, path)
	}
}
