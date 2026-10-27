package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type DailyWriter struct {
	dir      string
	now      func() time.Time
	fallback io.Writer
	mu       sync.Mutex
	date     string
	file     *os.File
	disabled bool
}

func NewDailyWriter(dir string, fallback io.Writer) *DailyWriter {
	return &DailyWriter{dir: dir, now: time.Now, fallback: fallback}
}

func (w *DailyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.disabled {
		return len(p), nil
	}
	date := w.now().Format("20060102")
	if w.file == nil || date != w.date {
		if w.file != nil {
			_ = w.file.Close()
		}
		if err := os.MkdirAll(w.dir, 0700); err != nil {
			return w.fallback.Write(p)
		}
		path := filepath.Join(w.dir, "omnisshagent-"+date+".log")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return w.fallback.Write(p)
		}
		w.file, w.date = f, date
	}
	return w.file.Write(p)
}

func (w *DailyWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// SetEnabled serializes with writes and closes the file before returning when
// disabled. No directories or files are created until the next enabled write.
func (w *DailyWriter) SetEnabled(enabled bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.disabled = !enabled
	if !enabled && w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

// Diagnostics gates the legacy standard logger without redirecting third-party
// protocol errors into application log files.
func (w *DailyWriter) Diagnostics() io.Writer { return diagnostics{w} }

type diagnostics struct{ writer *DailyWriter }

func (d diagnostics) Write(p []byte) (int, error) {
	d.writer.mu.Lock()
	defer d.writer.mu.Unlock()
	if d.writer.disabled {
		return len(p), nil
	}
	return d.writer.fallback.Write(p)
}

func New(dir string, level slog.Level) (*slog.Logger, io.Closer) {
	return NewWithLevel(dir, level)
}

func NewWithLevel(dir string, level slog.Leveler) (*slog.Logger, *DailyWriter) {
	writer := NewDailyWriter(dir, os.Stderr)
	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: level})
	return slog.New(handler), writer
}

func SafeError(operation string, err error) string {
	return fmt.Sprintf("%s: %v", operation, err)
}
