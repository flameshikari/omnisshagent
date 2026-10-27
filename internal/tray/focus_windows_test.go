//go:build windows

package tray

import (
	"runtime"
	"testing"
)

func TestFocusCuesFollowMouseAndTab(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	window, err := createPopup("OmniSSHAgentFocusTest", "Focus test", 240, 100, 0, keysCallback)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyWindow.Call(window)
	button, err := createChild("Button", "Test", bsPushButton|wsTabStop, 0, 12, 12, 88, 24, window, 99)
	if err != nil {
		t.Fatal(err)
	}
	showWindow.Call(window, swShow)
	hidden := func(want bool) {
		t.Helper()
		state, _, _ := sendMessage.Call(button, 0x0129, 0, 0) // WM_QUERYUISTATE
		if (state&1 != 0) != want {
			t.Fatalf("button focus cues: hidden=%v, want %v", state&1 != 0, want)
		}
	}
	hidden(true)
	updateFocusCues(&message{Window: button, Message: 0x0100, WParam: 0x09})
	hidden(false)
	// A native button click must hide the indicator again without losing focus.
	sendMessage.Call(button, 0x0201, 1, 10|10<<16)
	sendMessage.Call(button, 0x0202, 0, 10|10<<16)
	hidden(true)
	updateFocusCues(&message{Window: button, Message: 0x0100, WParam: 0x09})
	hidden(false)
}
