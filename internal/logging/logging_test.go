package logging

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDailyWriterRotatesByDate(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 7, 20, 23, 59, 0, 0, time.Local)
	var fallback bytes.Buffer
	writer := NewDailyWriter(dir, &fallback)
	writer.now = func() time.Time { return now }
	if _, err := writer.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := writer.Write([]byte("second\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, date := range []string{"20260720", "20260721"} {
		path := filepath.Join(dir, "omnisshagent-"+date+".log")
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	if fallback.Len() != 0 {
		t.Fatalf("unexpected fallback: %s", fallback.String())
	}
}

func TestConfiguredLevelFiltersRecords(t *testing.T) {
	dir := t.TempDir()
	logger, closer := New(dir, slog.LevelWarn)
	logger.Info("filtered")
	logger.Warn("kept")
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "omnisshagent-"+time.Now().Format("20060102")+".log")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "filtered") || !strings.Contains(string(data), "kept") {
		t.Fatalf("unexpected log contents: %s", data)
	}
}

func TestDisabledLoggingCreatesNothingAndCanResume(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	var fallback bytes.Buffer
	writer := NewDailyWriter(dir, &fallback)
	defer writer.Close()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.Local)
	writer.now = func() time.Time { return now }
	logger := slog.New(slog.NewJSONHandler(writer, nil))
	if err := writer.SetEnabled(false); err != nil {
		t.Fatal(err)
	}
	logger.Info("startup must not be logged")
	_, _ = writer.Diagnostics().Write([]byte("library output"))
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("disabled logging created directory: %v", err)
	}
	if fallback.Len() != 0 {
		t.Fatal("disabled diagnostics emitted output")
	}
	if err := writer.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	logger.Info("enabled")
	first := filepath.Join(dir, "omnisshagent-20261025.log")
	before, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), "enabled") || strings.Contains(string(before), "startup") {
		t.Fatalf("unexpected enabled output: %s", before)
	}
	if err := writer.SetEnabled(false); err != nil {
		t.Fatal(err)
	}
	logger.Error("must not append")
	after, err := os.ReadFile(first)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("disabled writer appended: %v", err)
	}
	// Renaming also verifies that the Windows file handle was closed.
	if err := os.Rename(first, first+".saved"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(24 * time.Hour)
	logger.Warn("must not rotate")
	second := filepath.Join(dir, "omnisshagent-20261026.log")
	if _, err := os.Stat(second); !os.IsNotExist(err) {
		t.Fatalf("disabled writer rotated: %v", err)
	}
	if err := writer.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	logger.Warn("resumed")
	_, _ = writer.Diagnostics().Write([]byte("enabled diagnostic"))
	if fallback.String() != "enabled diagnostic" {
		t.Fatalf("diagnostics=%q", fallback.String())
	}
	data, err := os.ReadFile(second)
	if err != nil || !strings.Contains(string(data), "resumed") || strings.Contains(string(data), "diagnostic") {
		t.Fatalf("unexpected resumed output: %s err=%v", data, err)
	}
}

func TestProductionLogCallsDoNotPassSensitivePayloadIdentifiers(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(data), "\n") {
				lower := strings.ToLower(line)
				if !strings.Contains(lower, "logger.") {
					continue
				}
				for _, forbidden := range []string{"privatekey", "passphrase", "payload", `"data"`, `"contents"`} {
					if strings.Contains(lower, forbidden) {
						t.Errorf("%s contains forbidden log argument %q: %s", path, forbidden, line)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
