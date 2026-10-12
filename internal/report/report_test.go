package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/finding"
)

func sample() *Report {
	fs := []finding.Finding{
		{
			RuleID: "stripe-live-key", Description: "Stripe live key", Severity: finding.High,
			Source: finding.SourceCode, File: "src/<script>alert(1)</script>.ts", Line: 4, Column: 9,
			Secret: "sk_l****", Fix: "Rotate it.",
			Context: []finding.ContextLine{{Number: 4, Text: `x = "</pre><img src=x onerror=alert(1)>"`, Hit: true}},
		},
		{
			RuleID: "env-file-in-history", Description: "Env committed", Severity: finding.High,
			Source: finding.SourceHistory, File: ".env", Fix: "Rotate all.",
			Commit: &finding.Commit{SHA: "0123456789abcdef0123456789abcdef01234567", Author: "Dev", Date: "2026-01-02T03:04:05Z"},
		},
		{RuleID: "debug-in-production-config", Description: "Debug on", Severity: finding.Low, Source: finding.SourceConfig, File: "prod.json", Line: 2},
	}
	return &Report{
		Tool: "keyguard", Version: "test", Root: "/tmp/app", ScannedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		FilesScanned: 10, Findings: fs, Summary: Summarize(fs), History: true, Commits: 5,
	}
}

// Scanned file names and contents are attacker-controlled input.
func TestHTMLEscapesScannedContent(t *testing.T) {
	var buf bytes.Buffer
	if err := HTML(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, bad := range []string{"<script>alert(1)", "<img src=x", "</pre><img"} {
		if strings.Contains(out, bad) {
			t.Errorf("unescaped %q in HTML output", bad)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("file name should appear escaped")
	}
}

func TestHTMLStructure(t *testing.T) {
	var buf bytes.Buffer
	HTML(&buf, sample())
	out := buf.String()
	for _, want := range []string{
		"<title>keyguard report: 3 findings</title>",
		"Secrets in code", "Risky configuration", "Secrets in git history",
		`data-sev="high"`, `data-sev="low"`, "01234567", // short SHA
		`class="ln hit"`, "prefers-color-scheme", // CSS inlined
		`getElementById("search")`, // JS inlined
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if strings.Contains(out, "http://") || strings.Contains(out, "https://cdn") {
		t.Error("report must be self-contained (no external URLs)")
	}
}

func TestHTMLEmpty(t *testing.T) {
	var buf bytes.Buffer
	HTML(&buf, &Report{Tool: "keyguard", Version: "test"})
	if !strings.Contains(buf.String(), "No secrets or risky configuration found") {
		t.Error("missing empty state")
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sample(), "json", false); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Summary  Summary `json:"summary"`
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Summary.High != 2 || got.Findings[0].Severity != "high" {
		t.Errorf("unexpected JSON: %s", buf.String())
	}
}

func TestSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sample(), "sarif", false); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if log.Version != "2.1.0" || len(run.Results) != 3 || len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("unexpected SARIF: %s", buf.String())
	}
	if run.Results[0].Level != "error" || run.Results[2].Level != "note" {
		t.Errorf("levels: %s, %s", run.Results[0].Level, run.Results[2].Level)
	}
}

func TestTextNoColor(t *testing.T) {
	var buf bytes.Buffer
	Write(&buf, sample(), "text", false)
	out := buf.String()
	if strings.Contains(out, "\033[") {
		t.Error("ANSI codes in no-color output")
	}
	if !strings.Contains(out, "3 findings: 2 high, 0 medium, 1 low") {
		t.Errorf("summary line missing:\n%s", out)
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, sample(), "xml", false); err == nil {
		t.Error("want error for unknown format")
	}
}

func TestSARIFFingerprintsUnique(t *testing.T) {
	fs := []finding.Finding{
		{RuleID: "secret-in-public-env-var", File: ".env", Line: 1, Secret: "NEXT_PUBLIC_A_SECRET"},
		{RuleID: "secret-in-public-env-var", File: ".env", Line: 2, Secret: "NEXT_PUBLIC_B_SECRET"},
	}
	var buf bytes.Buffer
	SARIF(&buf, &Report{Tool: "keyguard", Findings: fs})
	var log sarifLog
	json.Unmarshal(buf.Bytes(), &log)
	r := log.Runs[0].Results
	if r[0].PartialFingerprints["github.com/OrdinaryDev-in/keyguard-security-scanner/v1"] == r[1].PartialFingerprints["github.com/OrdinaryDev-in/keyguard-security-scanner/v1"] {
		t.Error("distinct config findings share a fingerprint")
	}
}

func TestTextStripsControlChars(t *testing.T) {
	r := &Report{Findings: []finding.Finding{{RuleID: "x", Description: "d", Severity: finding.High,
		Source: finding.SourceCode, File: "a\x1b[2K\rfake.ts"}}}
	var buf bytes.Buffer
	Text(&buf, r, false)
	if strings.Contains(buf.String(), "\x1b") || strings.Contains(buf.String(), "\r") {
		t.Errorf("control chars reached the terminal: %q", buf.String())
	}
}
