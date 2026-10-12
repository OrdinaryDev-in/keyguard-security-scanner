package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/fixture"
)

func TestParseInterleaved(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	hist := fs.Bool("history", false, "")
	format := fs.String("format", "text", "")
	pos, err := parseInterleaved(fs, []string{"--format", "json", "./app", "--history"})
	if err != nil {
		t.Fatal(err)
	}
	if !*hist || *format != "json" || len(pos) != 1 || pos[0] != "./app" {
		t.Errorf("history=%v format=%s pos=%v", *hist, *format, pos)
	}
}

func TestExitCodes(t *testing.T) {
	vuln := t.TempDir()
	if err := fixture.Write(vuln); err != nil {
		t.Fatal(err)
	}
	clean := t.TempDir()
	os.WriteFile(filepath.Join(clean, "index.js"), []byte("console.log('hello')\n"), 0o644)

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"findings fail the build", []string{"scan", vuln}, exitFindings},
		{"clean project passes", []string{"scan", clean}, exitClean},
		{"fail-on none never fails", []string{"scan", vuln, "--fail-on", "none"}, exitClean},
		{"bad severity", []string{"scan", clean, "--fail-on", "urgent"}, exitError},
		{"missing dir", []string{"scan", filepath.Join(clean, "nope")}, exitError},
		{"bad format", []string{"scan", clean, "--format", "xml"}, exitError},
		{"bad max-size", []string{"scan", clean, "--max-size", "0"}, exitError},
		{"unknown command", []string{"deploy"}, exitError},
		{"version", []string{"version"}, exitClean},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(tt.args, io.Discard, io.Discard); got != tt.want {
				t.Errorf("exit = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestHTMLOutputFile(t *testing.T) {
	vuln := t.TempDir()
	fixture.Write(vuln)
	out := filepath.Join(t.TempDir(), "report.html")
	var stderr bytes.Buffer
	run([]string{"scan", vuln, "--format", "html", "-o", out}, io.Discard, &stderr)
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "<!doctype html>") || !strings.Contains(stderr.String(), "report written") {
		t.Errorf("bad html output; stderr=%s", stderr.String())
	}
}

func TestRulesListsWholeCatalogue(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"rules"}, &out, io.Discard); code != exitClean {
		t.Fatalf("exit %d", code)
	}
	for _, id := range []string{"aws-access-key-id", "high-entropy-string", "env-file-committed", "env-file-in-history", "supabase-admin-key-in-client"} {
		if !strings.Contains(out.String(), id) {
			t.Errorf("rules output is missing %s", id)
		}
	}
}
