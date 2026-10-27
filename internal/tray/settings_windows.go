//go:build windows

package tray

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/masahide/OmniSSHAgent/internal/config"
)

const (
	settingsClass                 = "OmniSSHAgentSettingsWindow"
	idGroupCompat                 = 2101
	idPageant                     = 2102
	idCygwin                      = 2103
	idSocketLabel                 = 2104
	idSocket                      = 2105
	idBrowse                      = 2106
	idGroupBackend                = 2107
	idPipeLabel                   = 2108
	idPipe                        = 2109
	idTimeoutLabel                = 2110
	idTimeout                     = 2111
	idGroupApp                    = 2112
	idAutoStart                   = 2113
	idLogLabel                    = 2114
	idLogLevel                    = 2115
	idLoggingEnabled              = 2116
	idOpenConfig                  = 2117
	idApply                       = 2118
	idBackendType                 = 2119
	idGroupMiddleware             = 2121
	idMiddlewareUnlock            = 2122
	idMiddlewarePath              = 2123
	idMiddlewareBrowse            = 2124
	idFluentIcon                  = 2125
	idTimeoutUnits                = 2126
	idMiddlewareStart             = 2127
	idLogsDirectory               = 2128
	idConfigDirectory             = 2129
	idMiddlewareEnabled           = 2130
	idMiddlewareProgram           = 2131
	idMiddlewareDatabase          = 2132
	idMiddlewareDatabaseBrowse    = 2133
	idMiddlewareDatabaseEnabled   = 2134
	idMiddlewareExecutableEnabled = 2135
	wmReleaseComboFocus           = wmUser + 4
	settingsWidth                 = 492
	settingsHeight                = 512
)

var logLevels = []string{"debug", "info", "warn", "error"}

type backendOption struct {
	value string
	label string
}

var backendOptions = []backendOption{
	{value: config.BackendWindowsOpenSSH, label: "Windows OpenSSH"},
	{value: config.BackendEmbedded, label: "Embedded Ephemeral Agent"},
}

type settingsValues struct {
	MiddlewareEnabled           bool
	MiddlewareProgram           string
	MiddlewareProfiles          map[string]config.MiddlewareProgramConfig
	PageantEnabled              bool
	CygwinEnabled               bool
	SocketPath                  string
	BackendType                 string
	Pipe                        string
	ConnectTimeout              string
	LogLevel                    string
	LoggingEnabled              bool
	FluentIcon                  bool
	AutoStart                   bool
	MiddlewareUnlock            bool
	MiddlewareStart             bool
	MiddlewarePath              string
	MiddlewareDatabase          string
	MiddlewareDatabaseEnabled   bool
	MiddlewareExecutableEnabled bool
}

type settingsDialog struct {
	middlewareEnabled           uintptr
	middlewareProgram           uintptr
	middlewareCurrent           string
	middlewareProfiles          map[string]config.MiddlewareProgramConfig
	tray                        *Tray
	m                           metrics
	hwnd                        uintptr
	pageant                     uintptr
	cygwin                      uintptr
	socket                      uintptr
	backendType                 uintptr
	pipeLabel                   uintptr
	pipe                        uintptr
	timeoutLabel                uintptr
	timeout                     uintptr
	timeoutUnits                uintptr
	timeoutOriginal             string
	timeoutDisplayed            string
	backendTip                  *hoverTip
	autoStart                   uintptr
	logLevel                    uintptr
	logLabel                    uintptr
	loggingEnabled              uintptr
	fluentIcon                  uintptr
	middlewareUnlock            uintptr
	middlewarePath              uintptr
	middlewareStart             uintptr
	middlewareBrowse            uintptr
	middlewareDatabase          uintptr
	middlewareDatabaseEnabled   uintptr
	middlewareExecutableEnabled uintptr
	middlewareDatabaseBrowse    uintptr
}

func mergeSettings(cfg config.Config, v settingsValues) config.Config {
	cfg.Interfaces.Pageant.Enabled = v.PageantEnabled
	cfg.Interfaces.Cygwin.Enabled = v.CygwinEnabled
	cfg.Interfaces.Cygwin.SocketPath = strings.TrimSpace(v.SocketPath)
	cfg.Backend.Type = strings.TrimSpace(v.BackendType)
	cfg.Backend.Pipe = strings.TrimSpace(v.Pipe)
	cfg.Backend.ConnectTimeout = strings.TrimSpace(v.ConnectTimeout)
	cfg.Logging.Level = strings.ToLower(strings.TrimSpace(v.LogLevel))
	cfg.Logging.Enabled = &v.LoggingEnabled
	cfg.Tray.FluentIcon = v.FluentIcon
	profiles := cfg.MiddlewareProfiles()
	for program, profile := range v.MiddlewareProfiles {
		profiles[program] = profile
	}
	program := v.MiddlewareProgram
	if program == "" {
		program = config.MiddlewareKeePassXC
	}
	database := strings.TrimSpace(v.MiddlewareDatabase)
	profiles[program] = config.MiddlewareProgramConfig{
		Database:        &database,
		UseDatabase:     &v.MiddlewareDatabaseEnabled,
		UseExecutable:   &v.MiddlewareExecutableEnabled,
		Executable:      strings.TrimSpace(v.MiddlewarePath),
		UnlockOnRequest: v.MiddlewareUnlock,
		StartOnRequest:  v.MiddlewareStart,
	}
	cfg.Middleware = &config.MiddlewareConfig{Enabled: v.MiddlewareEnabled, Program: program, Programs: profiles}
	// Keep legacy KeePassXC values consistent while retaining per-program
	// preferences in the middleware profiles when the master switch is off.
	effective := cfg.EffectiveKeePassXC()
	cfg.KeePassXC.Enabled = effective.Enabled
	profile := profiles[config.MiddlewareKeePassXC]
	cfg.KeePassXC.Executable, cfg.KeePassXC.Database = "", ""
	if profile.UsesExecutable() {
		cfg.KeePassXC.Executable = profile.Executable
	}
	if profile.UsesDatabase() && profile.Database != nil {
		cfg.KeePassXC.Database = *profile.Database
	}
	cfg.KeePassXC.StartOnRequest = effective.StartOnRequest
	return cfg
}

func validateSettings(cfg config.Config, configPath, userProfile string) error {
	_, err := config.Validate(cfg, configPath, "", userProfile)
	return err
}

func (t *Tray) openSettings() {
	if settingsDlg != nil && settingsDlg.hwnd != 0 {
		showWindow.Call(settingsDlg.hwnd, 9)
		setForegroundWindow.Call(settingsDlg.hwnd)
		return
	}
	if _, err := createDefaultConfig(t.configPath); err != nil {
		ShowFatal(err)
		return
	}
	d := &settingsDialog{tray: t, m: newMetrics()}
	settingsDlg = d
	defer func() {
		if settingsDlg == d {
			settingsDlg = nil
		}
	}()
	if err := d.create(t.window); err != nil {
		ShowFatal(err)
		return
	}
	runModal(t.window, d.hwnd)
}

var settingsDlg *settingsDialog

func (d *settingsDialog) create(owner uintptr) error {
	m := d.m
	width := m.s(settingsWidth)
	height := m.s(settingsHeight)
	hwnd, err := createPopup(settingsClass, "OpenSSHAgent – Settings", width, height, owner, settingsCallback)
	if err != nil {
		return err
	}
	d.hwnd = hwnd
	if err := d.createControls(); err != nil {
		destroyWindow.Call(hwnd)
		d.hwnd = 0
		return err
	}
	if err := d.load(); err != nil {
		destroyWindow.Call(hwnd)
		d.hwnd = 0
		return err
	}
	return nil
}

func (d *settingsDialog) createControls() error {
	m := d.m
	pad := m.s(12)
	labelW := m.s(92)
	editH := m.s(24)
	btnW := m.s(88)
	btnH := m.s(24)
	innerX := pad + m.s(10)
	innerW := m.s(448)
	browseW := btnW
	gap := m.s(8)

	var err error
	backendTop := pad
	backendH := m.s(84)
	if _, err = d.child("Button", " Backend ", bsGroupBox, 0, pad, backendTop, m.s(468), backendH, idGroupBackend); err != nil {
		return err
	}
	typeLabel, err := d.label("Type", innerX, backendTop+m.s(24), 0)
	if err != nil {
		return err
	}
	if d.timeoutLabel, err = d.label("Timeout", 0, backendTop+m.s(24), idTimeoutLabel); err != nil {
		return err
	}
	if d.timeoutUnits, err = d.label("Seconds", 0, backendTop+m.s(24), idTimeoutUnits); err != nil {
		return err
	}
	unitsX := innerX + innerW - controlWidth(d.timeoutUnits)
	timeoutW := controlTextSize(d.timeoutLabel, "0000").CX + m.s(12)
	timeoutX := unitsX - gap - timeoutW
	timeoutLabelX := timeoutX - gap - controlWidth(d.timeoutLabel)
	setWindowPos.Call(d.timeoutUnits, 0, uintptr(unitsX), uintptr(backendTop+m.s(24)), 0, 0, 0x15)
	setWindowPos.Call(d.timeoutLabel, 0, uintptr(timeoutLabelX), uintptr(backendTop+m.s(24)), 0, 0, 0x15)
	typeX := innerX + controlWidth(typeLabel) + gap
	if d.backendType, err = d.child("ComboBox", "", cbsDropDownList|wsVScroll|wsTabStop, 0, typeX, backendTop+m.s(20), timeoutLabelX-gap-typeX, m.s(100), idBackendType); err != nil {
		return err
	}
	for _, option := range backendOptions {
		comboAdd(d.backendType, option.label)
	}
	if d.timeout, err = d.child("Edit", "", esAutoHScroll|0x2000|2|wsTabStop, wsExClientEdge, timeoutX, backendTop+m.s(20), timeoutW, editH, idTimeout); err != nil {
		return err
	} // ES_NUMBER
	sendMessage.Call(d.timeout, 0x00C5, 4, 0) // EM_SETLIMITTEXT
	if d.pipeLabel, err = d.label("Named Pipe", innerX, backendTop+m.s(52), idPipeLabel); err != nil {
		return err
	}
	pipeX := innerX + controlWidth(d.pipeLabel) + gap
	if d.pipe, err = d.child("Edit", "", esAutoHScroll|wsTabStop, wsExClientEdge, pipeX, backendTop+m.s(48), innerX+innerW-pipeX, editH, idPipe); err != nil {
		return err
	}
	if d.backendTip, err = newHoverTip(d.hwnd, d.backendType, embeddedBackendNote, m.s(420)); err != nil {
		return err
	}

	interfacesTop := backendTop + backendH + m.s(10)
	interfacesH := m.s(86)
	if _, err = d.child("Button", " Interfaces ", bsGroupBox, 0, pad, interfacesTop, m.s(468), interfacesH, idGroupCompat); err != nil {
		return err
	}
	if d.pageant, err = d.child("Button", "Pageant", bsAutoCheckBox|wsTabStop, 0, innerX, interfacesTop+m.s(22), m.s(100), editH, idPageant); err != nil {
		return err
	}
	cygwinX := innerX + controlWidth(d.pageant) + m.s(12)
	if d.cygwin, err = d.child("Button", "Cygwin / MSYS2", bsAutoCheckBox|wsTabStop, 0, cygwinX, interfacesTop+m.s(22), innerX+innerW-cygwinX, editH, idCygwin); err != nil {
		return err
	}
	socketLabel, err := d.child("Static", "Socket Path", 0, 0, innerX, interfacesTop+m.s(54), labelW, editH, idSocketLabel)
	if err != nil {
		return err
	}
	socketLabelW := controlTextSize(socketLabel, "Socket Path").CX
	setWindowPos.Call(socketLabel, 0, 0, 0, uintptr(socketLabelW), uintptr(editH), 0x16)
	socketX := innerX + socketLabelW + gap
	socketW := innerW - socketLabelW - 2*gap - browseW
	if d.socket, err = d.child("Edit", "", esAutoHScroll|wsTabStop, wsExClientEdge, socketX, interfacesTop+m.s(50), socketW, editH, idSocket); err != nil {
		return err
	}
	if _, err = d.child("Button", "Browse", bsPushButton|wsTabStop, 0, socketX+socketW+gap, interfacesTop+m.s(50), browseW, btnH, idBrowse); err != nil {
		return err
	}

	middlewareTop := interfacesTop + interfacesH + m.s(10)
	middlewareH := m.s(170)
	if _, err = d.child("Button", " Middleware ", bsGroupBox, 0, pad, middlewareTop, m.s(468), middlewareH, idGroupMiddleware); err != nil {
		return err
	}
	if d.middlewareEnabled, err = d.child("Button", "Enabled", bsAutoCheckBox|wsTabStop, 0, innerX, middlewareTop+m.s(20), m.s(100), editH, idMiddlewareEnabled); err != nil {
		return err
	}
	programX := innerX + controlWidth(d.middlewareEnabled) + gap
	if d.middlewareProgram, err = d.child("ComboBox", "", cbsDropDownList|wsVScroll|wsTabStop, 0, programX, middlewareTop+m.s(20), innerX+innerW-programX, m.s(100), idMiddlewareProgram); err != nil {
		return err
	}
	for _, option := range middlewareOptions {
		comboAdd(d.middlewareProgram, option.label)
	}
	if d.middlewareUnlock, err = d.child("Button", "Trigger database unlock on SSH agent requests", bsAutoCheckBox|wsTabStop, 0, innerX, middlewareTop+m.s(46), innerW, editH, idMiddlewareUnlock); err != nil {
		return err
	}
	if d.middlewareStart, err = d.child("Button", "Start program on SSH agent requests", bsAutoCheckBox|wsTabStop, 0, innerX, middlewareTop+m.s(70), innerW, editH, idMiddlewareStart); err != nil {
		return err
	}
	if d.middlewareExecutableEnabled, err = d.child("Button", "Executable", bsAutoCheckBox|wsTabStop, 0, innerX, middlewareTop+m.s(102), m.s(100), editH, idMiddlewareExecutableEnabled); err != nil {
		return err
	}
	if d.middlewareDatabaseEnabled, err = d.child("Button", "Database", bsAutoCheckBox|wsTabStop, 0, innerX, middlewareTop+m.s(134), m.s(100), editH, idMiddlewareDatabaseEnabled); err != nil {
		return err
	}
	pathX := innerX + max(controlWidth(d.middlewareExecutableEnabled), controlWidth(d.middlewareDatabaseEnabled)) + gap
	pathW := innerX + innerW - gap - browseW - pathX
	if d.middlewarePath, err = d.child("Edit", "", esAutoHScroll|wsTabStop, wsExClientEdge, pathX, middlewareTop+m.s(102), pathW, editH, idMiddlewarePath); err != nil {
		return err
	}
	if d.middlewareBrowse, err = d.child("Button", "Browse", bsPushButton|wsTabStop, 0, pathX+pathW+gap, middlewareTop+m.s(102), browseW, btnH, idMiddlewareBrowse); err != nil {
		return err
	}
	if d.middlewareDatabase, err = d.child("Edit", "", esAutoHScroll|wsTabStop, wsExClientEdge, pathX, middlewareTop+m.s(134), pathW, editH, idMiddlewareDatabase); err != nil {
		return err
	}
	if d.middlewareDatabaseBrowse, err = d.child("Button", "Browse", bsPushButton|wsTabStop, 0, pathX+pathW+gap, middlewareTop+m.s(134), browseW, btnH, idMiddlewareDatabaseBrowse); err != nil {
		return err
	}
	appTop := middlewareTop + middlewareH + m.s(10)
	appH := m.s(86)
	if _, err = d.child("Button", " Application ", bsGroupBox, 0, pad, appTop, m.s(468), appH, idGroupApp); err != nil {
		return err
	}
	if d.autoStart, err = d.child("Button", "Start with Windows", bsAutoCheckBox|wsTabStop, 0, innerX, appTop+m.s(22), innerW, editH, idAutoStart); err != nil {
		return err
	}
	fluentX := innerX + controlWidth(d.autoStart) + m.s(12)
	if d.fluentIcon, err = d.child("Button", "Fluent Tray Icon", bsAutoCheckBox|wsTabStop, 0, fluentX, appTop+m.s(22), innerX+innerW-fluentX, editH, idFluentIcon); err != nil {
		return err
	}
	if d.loggingEnabled, err = d.child("Button", "Enable Logging", bsAutoCheckBox|wsTabStop, 0, innerX, appTop+m.s(50), innerW, editH, idLoggingEnabled); err != nil {
		return err
	}
	logLabelX := innerX + controlWidth(d.loggingEnabled) + m.s(12)
	if d.logLabel, err = d.label("Log Level", logLabelX, appTop+m.s(50), idLogLabel, 0x200); err != nil {
		return err
	}
	logX := logLabelX + controlWidth(d.logLabel) + gap
	logsX := innerX + innerW - btnW
	if d.logLevel, err = d.child("ComboBox", "", cbsDropDownList|wsVScroll|wsTabStop, 0, logX, appTop+m.s(50), logsX-gap-logX, m.s(140), idLogLevel); err != nil {
		return err
	}
	for _, level := range logLevels {
		comboAdd(d.logLevel, strings.ToUpper(level[:1])+level[1:])
	}
	if _, err = d.child("Button", "Logs Directory", bsPushButton|wsTabStop, 0, logsX, appTop+m.s(50), btnW, btnH, idLogsDirectory); err != nil {
		return err
	}
	buttonY := appTop + appH + gap
	rowWidth := m.s(settingsWidth) - 2*pad
	leftWidth := (rowWidth - gap) / 2
	for i, button := range []struct {
		text string
		id   uintptr
	}{{"Open Config", idOpenConfig}, {"Config Directory", idConfigDirectory}, {"OK", idOK}, {"Cancel", idCancel}, {"Apply", idApply}} {
		count, index, start, width := int32(2), int32(i), int32(0), leftWidth
		if i >= 2 {
			count, index, start, width = 3, int32(i-2), leftWidth+gap, rowWidth-leftWidth-gap
		}
		available := width - gap*(count-1)
		left, right := available*index/count, available*(index+1)/count
		x, buttonWidth := pad+start+left+gap*index, right-left
		style := uint32(bsPushButton | wsTabStop)
		if button.id == idOK {
			style = bsDefPushButton | wsTabStop
		}
		if _, err = d.child("Button", button.text, style, 0, x, buttonY, buttonWidth, btnH, button.id); err != nil {
			return err
		}
	}
	return nil
}

func (d *settingsDialog) child(class, title string, style, ex uint32, x, y, w, h int32, id uintptr) (uintptr, error) {
	hwnd, err := createChild(class, title, style, ex, x, y, w, h, d.hwnd, id)
	if err != nil {
		return 0, err
	}
	setChildFont(hwnd, d.m.font)
	if class == "Button" && style&0xF == bsAutoCheckBox {
		// Shrink the actual native control, so blank space belongs to the parent.
		glyph, _, _ := user32.NewProc("GetSystemMetricsForDpi").Call(71, uintptr(d.m.dpi)) // SM_CXMENUCHECK
		if glyph == 0 {
			glyph = uintptr(d.m.s(13))
		}
		width := min(w, controlTextSize(hwnd, title).CX+int32(glyph)+d.m.s(5))
		setWindowPos.Call(hwnd, 0, 0, 0, uintptr(width), uintptr(h), 0x16)
	}
	return hwnd, nil
}

func (d *settingsDialog) label(text string, x, y int32, id uintptr, styles ...uint32) (uintptr, error) {
	var style uint32
	for _, value := range styles {
		style |= value
	}
	window, err := d.child("Static", text, style, 0, x, y, d.m.s(100), d.m.s(24), id)
	if err == nil {
		setWindowPos.Call(window, 0, 0, 0, uintptr(controlTextSize(window, text).CX), uintptr(d.m.s(24)), 0x16)
	}
	return window, err
}

func (d *settingsDialog) load() error {
	cfg, err := config.Load(d.tray.configPath)
	if err != nil {
		return err
	}
	setChecked(d.pageant, cfg.Interfaces.Pageant.Enabled)
	setChecked(d.cygwin, cfg.Interfaces.Cygwin.Enabled)
	d.middlewareProfiles = cfg.MiddlewareProfiles()
	d.middlewareCurrent = cfg.MiddlewareProgram()
	setChecked(d.middlewareEnabled, cfg.MiddlewareEnabled())
	for i, option := range middlewareOptions {
		if option.value == d.middlewareCurrent {
			comboSelect(d.middlewareProgram, i)
			break
		}
	}
	d.loadMiddlewareProfile()
	setChecked(d.fluentIcon, cfg.Tray.FluentIcon)
	socket := cfg.Interfaces.Cygwin.SocketPath
	if socket == "" {
		if profile := os.Getenv("USERPROFILE"); profile != "" {
			socket = filepath.Join(profile, ".ssh", "omnisshagent-cygwin.sock")
		}
	}
	setWindowText(d.socket, socket)
	backendSelected := 0
	for i, option := range backendOptions {
		if option.value == cfg.Backend.Type {
			backendSelected = i
			break
		}
	}
	comboSelect(d.backendType, backendSelected)
	setWindowText(d.pipe, cfg.Backend.Pipe)
	seconds := ""
	if duration, err := time.ParseDuration(cfg.Backend.ConnectTimeout); err == nil && duration > 0 {
		value := duration / time.Second
		if duration%time.Second != 0 {
			value++
		}
		seconds = strconv.FormatInt(int64(min(value, 9999)), 10)
	}
	setWindowText(d.timeout, seconds)
	d.timeoutOriginal, d.timeoutDisplayed = cfg.Backend.ConnectTimeout, windowText(d.timeout)
	d.updateBackendControls()
	level := strings.ToLower(cfg.Logging.Level)
	selected := 1
	for i, name := range logLevels {
		if name == level {
			selected = i
			break
		}
	}
	comboSelect(d.logLevel, selected)
	setChecked(d.loggingEnabled, cfg.Logging.IsEnabled())
	d.updateLoggingControls()
	enabled, err := autoStartEnabled()
	if err != nil {
		return err
	}
	setChecked(d.autoStart, enabled)
	return nil
}

func (d *settingsDialog) values() settingsValues {
	backendType := config.BackendWindowsOpenSSH
	if i := comboIndex(d.backendType); i >= 0 && i < len(backendOptions) {
		backendType = backendOptions[i].value
	}
	level := "info"
	if i := comboIndex(d.logLevel); i >= 0 && i < len(logLevels) {
		level = logLevels[i]
	}
	timeout := windowText(d.timeout)
	if timeout == d.timeoutDisplayed {
		timeout = d.timeoutOriginal
	} else if timeout != "" {
		timeout += "s"
	}
	d.storeMiddlewareProfile()
	return settingsValues{
		MiddlewareEnabled:           isChecked(d.middlewareEnabled),
		MiddlewareProgram:           d.middlewareCurrent,
		MiddlewareProfiles:          d.middlewareProfiles,
		PageantEnabled:              isChecked(d.pageant),
		CygwinEnabled:               isChecked(d.cygwin),
		SocketPath:                  windowText(d.socket),
		BackendType:                 backendType,
		Pipe:                        windowText(d.pipe),
		ConnectTimeout:              timeout,
		LogLevel:                    level,
		LoggingEnabled:              isChecked(d.loggingEnabled),
		FluentIcon:                  isChecked(d.fluentIcon),
		AutoStart:                   isChecked(d.autoStart),
		MiddlewareUnlock:            isChecked(d.middlewareUnlock),
		MiddlewareStart:             isChecked(d.middlewareStart),
		MiddlewarePath:              windowText(d.middlewarePath),
		MiddlewareDatabase:          windowText(d.middlewareDatabase),
		MiddlewareDatabaseEnabled:   isChecked(d.middlewareDatabaseEnabled),
		MiddlewareExecutableEnabled: isChecked(d.middlewareExecutableEnabled),
	}
}

func (d *settingsDialog) updateBackendControls() {
	embedded := false
	if i := comboIndex(d.backendType); i >= 0 && i < len(backendOptions) {
		embedded = backendOptions[i].value == config.BackendEmbedded
	}
	enabled := uintptr(1)
	if embedded {
		enabled = 0
	}
	for _, control := range []uintptr{d.pipeLabel, d.pipe, d.timeoutLabel, d.timeout, d.timeoutUnits} {
		enableWindow.Call(control, enabled)
	}
	d.backendTip.setEnabled(embedded)
}

func (d *settingsDialog) updateLoggingControls() {
	var enabled uintptr
	if isChecked(d.loggingEnabled) {
		enabled = 1
	}
	enableWindow.Call(d.logLabel, enabled)
	enableWindow.Call(d.logLevel, enabled)
}

func (d *settingsDialog) openDirectory(path string) {
	err := os.MkdirAll(path, 0700)
	if err == nil {
		err = openPath(path)
	}
	if err != nil {
		showError(d.hwnd, err)
	}
}

func (d *settingsDialog) sanitizeTimeout() {
	text := windowText(d.timeout)
	digits := strings.Map(func(char rune) rune {
		if char >= '0' && char <= '9' {
			return char
		}
		return -1
	}, text)
	if len(digits) > 4 {
		digits = digits[:4]
	}
	if digits != text {
		setWindowText(d.timeout, digits)
		sendMessage.Call(d.timeout, 0x00B1, uintptr(len(digits)), uintptr(len(digits))) // EM_SETSEL
	}
}

func (d *settingsDialog) apply() bool {
	if _, err := createDefaultConfig(d.tray.configPath); err != nil {
		showError(d.hwnd, err)
		return false
	}
	cfg, err := config.Load(d.tray.configPath)
	if err != nil {
		showError(d.hwnd, err)
		return false
	}
	values := d.values()
	cfg = mergeSettings(cfg, values)
	if err := validateSettings(cfg, d.tray.configPath, os.Getenv("USERPROFILE")); err != nil {
		showError(d.hwnd, err)
		return false
	}
	if err := config.Save(d.tray.configPath, cfg); err != nil {
		showError(d.hwnd, err)
		return false
	}
	if err := setAutoStartEnabled(values.AutoStart); err != nil {
		showError(d.hwnd, err)
		return false
	}
	return true
}

func (d *settingsDialog) browseSocket() {
	initialDir := os.Getenv("USERPROFILE")
	current := strings.TrimSpace(windowText(d.socket))
	initialFile := "omnisshagent-cygwin.sock"
	if current != "" {
		initialDir = filepath.Dir(current)
		initialFile = filepath.Base(current)
	} else if initialDir != "" {
		initialDir = filepath.Join(initialDir, ".ssh")
	}
	path, ok := pickOpenFile(
		d.hwnd,
		"Cygwin socket path",
		initialDir,
		initialFile,
		[]string{"Socket files", "*.sock", "All files", "*.*"},
		false,
	)
	if ok {
		setWindowText(d.socket, path)
	}
}

func (d *settingsDialog) close() {
	if d.hwnd != 0 {
		destroyWindow.Call(d.hwnd)
	}
}

func settingsWindowProc(window uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	d := settingsDlg
	if d == nil || (d.hwnd != 0 && d.hwnd != window) {
		result, _, _ := defWindowProc.Call(window, uintptr(msg), wParam, lParam)
		return result
	}
	switch msg {
	case 0x002C: // WM_MEASUREITEM
		if measureControlItem(lParam, d.m.s(24), 3) {
			return 1
		}
	case 0x002B: // WM_DRAWITEM
		if drawComboItem(lParam) {
			return 1
		}
	case wmReleaseComboFocus:
		if focused, _, _ := user32.NewProc("GetFocus").Call(); focused == wParam {
			user32.NewProc("SetFocus").Call(d.hwnd)
		}
		return 0
	case wmCommand:
		if uint16(wParam>>16) == 9 && (commandID(wParam) == idBackendType || commandID(wParam) == idLogLevel || commandID(wParam) == idMiddlewareProgram) { // CBN_SELENDOK
			postMessage.Call(d.hwnd, wmReleaseComboFocus, lParam, 0)
		}
		switch commandID(wParam) {
		case idOK:
			if d.apply() {
				d.close()
			}
			return 0
		case idCancel:
			d.close()
			return 0
		case idApply:
			d.apply()
			return 0
		case idBrowse:
			d.browseSocket()
			return 0
		case idMiddlewareDatabaseBrowse:
			d.browseMiddlewareDatabase()
			return 0
		case idMiddlewareBrowse:
			d.browseMiddleware()
			return 0
		case idBackendType:
			d.updateBackendControls()
			return 0
		case idTimeout:
			if uint16(wParam>>16) == 0x0300 {
				d.sanitizeTimeout()
			} // EN_CHANGE also covers paste.
			return 0
		case idLoggingEnabled:
			d.updateLoggingControls()
			return 0
		case idMiddlewareEnabled:
			d.updateMiddlewareControls()
			return 0
		case idMiddlewareProgram:
			if uint16(wParam>>16) == 1 {
				d.selectMiddleware()
			} // CBN_SELCHANGE
			return 0
		case idMiddlewareExecutableEnabled, idMiddlewareDatabaseEnabled, idMiddlewareStart:
			d.updateMiddlewareControls()
			return 0
		case idOpenConfig:
			_, _ = createDefaultConfig(d.tray.configPath)
			_ = openConfiguration(d.tray.configPath)
			return 0
		case idConfigDirectory:
			d.openDirectory(filepath.Dir(d.tray.configPath))
			return 0
		case idLogsDirectory:
			d.openDirectory(d.tray.logDirectory)
			return 0
		}
	case wmClose:
		d.close()
		return 0
	case wmDestroy:
		d.hwnd = 0
		if settingsDlg == d {
			settingsDlg = nil
		}
		return 0
	}
	result, _, _ := defWindowProc.Call(window, uintptr(msg), wParam, lParam)
	return result
}
