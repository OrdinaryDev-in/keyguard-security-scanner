// Package report renders scan results as text, JSON, SARIF or HTML.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/finding"
)

type Report struct {
	Tool         string            `json:"tool"`
	Version      string            `json:"version"`
	Root         string            `json:"root"`
	ScannedAt    time.Time         `json:"scanned_at"`
	DurationMS   int64             `json:"duration_ms"`
	FilesScanned int               `json:"files_scanned"`
	Commits      int               `json:"commits_scanned,omitempty"`
	History      bool              `json:"history_scanned"`
	Summary      Summary           `json:"summary"`
	Findings     []finding.Finding `json:"findings"`
}

type Summary struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

func (s Summary) Total() int { return s.High + s.Medium + s.Low }

func Summarize(fs []finding.Finding) Summary {
	var s Summary
	for _, f := range fs {
		switch f.Severity {
		case finding.High:
			s.High++
		case finding.Medium:
			s.Medium++
		case finding.Low:
			s.Low++
		}
	}
	return s
}

// Write renders r in the given format.
func Write(w io.Writer, r *Report, format string, color bool) error {
	if r.Findings == nil {
		r.Findings = []finding.Finding{} // JSON "[]" instead of "null"
	}
	switch format {
	case "text", "":
		return Text(w, r, color)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "sarif":
		return SARIF(w, r)
	case "html":
		return HTML(w, r)
	}
	return fmt.Errorf("unknown format %q (want text, json, sarif or html)", format)
}

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	green  = "\033[32m"
)

// Text prints a human-readable report grouped by source.
func Text(w io.Writer, r *Report, color bool) error {
	c := func(code, s string) string {
		s = sanitize(s)
		if !color {
			return s
		}
		return code + s + reset
	}
	sevColor := map[finding.Severity]string{finding.High: red, finding.Medium: yellow, finding.Low: cyan}

	groups := []struct {
		src   finding.Source
		title string
	}{
		{finding.SourceCode, "Secrets in code"},
		{finding.SourceConfig, "Risky configuration"},
		{finding.SourceHistory, "Secrets in git history"},
	}
	for _, g := range groups {
		var items []finding.Finding
		for _, f := range r.Findings {
			if f.Source == g.src {
				items = append(items, f)
			}
		}
		if len(items) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", c(bold, fmt.Sprintf("%s (%d)", g.title, len(items))))
		for _, f := range items {
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			sev := fmt.Sprintf("%-6s", strings.ToUpper(f.Severity.String()))
			fmt.Fprintf(w, "  %s  %-40s %s", c(sevColor[f.Severity], sev), sanitize(f.Description), c(bold, loc))
			if f.Secret != "" {
				fmt.Fprintf(w, "  %s", c(dim, f.Secret))
			}
			if f.Commit != nil {
				state := "removed from current files"
				if f.Commit.InWorkingTree {
					state = "still in current files"
				}
				fmt.Fprintf(w, "\n          %s", c(dim, fmt.Sprintf("introduced in %.8s by %s on %.10s (%s)", f.Commit.SHA, sanitize(f.Commit.Author), f.Commit.Date, state)))
			}
			fmt.Fprintln(w)
		}
	}

	s := r.Summary
	fmt.Fprintln(w)
	scope := fmt.Sprintf("%d files", r.FilesScanned)
	if r.History {
		scope += fmt.Sprintf(", %d commits", r.Commits)
	}
	if s.Total() == 0 {
		fmt.Fprintf(w, "%s No secrets or risky config found (%s, %dms)\n", c(green, "✔"), scope, r.DurationMS)
		return nil
	}
	fmt.Fprintf(w, "%s %d findings: %s, %s, %s (%s, %dms)\n", c(red, "✖"), s.Total(),
		c(red, fmt.Sprintf("%d high", s.High)), c(yellow, fmt.Sprintf("%d medium", s.Medium)),
		c(cyan, fmt.Sprintf("%d low", s.Low)), scope, r.DurationMS)
	fmt.Fprintln(w, c(dim, "Tip: --format html -o report.html for a full report with code context and fixes."))
	return nil
}

// sanitize strips control characters from untrusted text (file names, git
// author names) so a file named "\x1b[2K..." can't rewrite terminal or CI log lines.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
}
