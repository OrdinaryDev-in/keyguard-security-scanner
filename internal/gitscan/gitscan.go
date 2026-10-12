// Package gitscan finds secrets in git history.
//
// Deleting a key in a new commit doesn't remove it: every old commit still
// contains it, and anyone who clones the repo gets all of them. So we stream
// `git log -p` (every patch ever made) and run the detector on each added line.
package gitscan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"keyguard/internal/checks"
	"keyguard/internal/detect"
	"keyguard/internal/finding"
	"keyguard/internal/ignore"
	"keyguard/internal/scan"
)

type Options struct {
	Root       string
	MaxCommits int    // 0 = all
	Since      string // passed to git log --since, e.g. "6 months ago"
	Entropy    bool
}

type Result struct {
	Findings []finding.Finding
	Commits  int
}

// commitMarker starts each commit header line; \x1e/\x1f never appear in normal text.
const commitMarker = "\x1eKG"

var hunkHeader = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)`)

// Scan streams the history of the repo at opts.Root.
func Scan(ctx context.Context, opts Options) (*Result, error) {
	// --no-textconv/--no-ext-diff: a scanned repo's .git/config can name
	// programs git would run to render diffs. Never execute repo-supplied code.
	args := []string{"-c", "core.fsmonitor=false", "-C", opts.Root, "log", "-p", "--all", "--no-color", "--no-ext-diff", "--no-textconv",
		"--no-renames", "-U0", "--pretty=format:" + commitMarker + "%H%x1f%an%x1f%aI"}
	if opts.MaxCommits > 0 {
		args = append(args, "-n", strconv.Itoa(opts.MaxCommits))
	}
	if opts.Since != "" {
		args = append(args, "--since="+opts.Since)
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("running git: %w", err)
	}

	p := newParser(detect.New(opts.Entropy), opts.Root)
	readErr := eachLine(out, p.line)
	if readErr != nil {
		// Keep draining so git never blocks on a full pipe: calling Wait
		// before all output is read can deadlock (see os/exec docs).
		io.Copy(io.Discard, out)
	}
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("git log failed (is %s a git repo?): %w: %s", opts.Root, err, strings.TrimSpace(stderr.String()))
	}
	if readErr != nil {
		return nil, readErr
	}
	return &Result{Findings: p.results(), Commits: p.commits}, nil
}

// maxLine caps how much of one diff line is inspected. A committed minified
// bundle can have multi-megabyte lines; bufio.Scanner would fail on those and
// abort the whole scan, so long lines are truncated instead.
const maxLine = 64 * 1024

// eachLine calls fn for every line of r, truncating lines longer than maxLine.
func eachLine(r io.Reader, fn func(string)) error {
	br := bufio.NewReaderSize(r, maxLine)
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		line := string(chunk) // copy: ReadLine's buffer is reused
		for isPrefix {        // discard the rest of an over-long line
			if _, isPrefix, err = br.ReadLine(); err != nil {
				fn(line)
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
		fn(line)
	}
}

// parser is a small state machine over unified-diff output.
type parser struct {
	det      *detect.Detector
	commit   finding.Commit
	commits  int
	file     string
	inHeader bool // between "diff --git" and the first "@@"; "+++ " lines are headers here
	lineNo   int
	// keyed by rule+file+secret. git log prints newest first, so each
	// overwrite moves the finding to an older commit: we keep where it was introduced.
	found map[string]finding.Finding
	order []string
	ign   *ignore.Matcher
}

func newParser(det *detect.Detector, root string) *parser {
	p := &parser{det: det, found: map[string]finding.Finding{}}
	if root != "" {
		// Same ignore file as the working-tree scan; a missing file is fine.
		p.ign, _ = ignore.Load(filepath.Join(root, scan.IgnoreFile))
	}
	return p
}

// skip applies the same path policy as the working-tree scan, so history
// doesn't report node_modules/ or paths the user put in .keyguardignore.
func (p *parser) skip(file string) bool {
	return scan.SkipPath(file) || p.ign.Match(file, false)
}

func (p *parser) line(l string) {
	switch {
	case strings.HasPrefix(l, commitMarker):
		parts := strings.SplitN(strings.TrimPrefix(l, commitMarker), "\x1f", 3)
		if len(parts) == 3 {
			p.commit = finding.Commit{SHA: parts[0], Author: parts[1], Date: parts[2]}
			p.commits++
		}
		p.file = ""
	case strings.HasPrefix(l, "diff --git "):
		p.file, p.inHeader = "", true
	case p.inHeader && strings.HasPrefix(l, "+++ "):
		if f := strings.TrimPrefix(l, "+++ "); f != "/dev/null" {
			p.file = strings.TrimPrefix(f, "b/")
			if p.skip(p.file) {
				p.file = "" // no file = added lines below are ignored
			} else if checks.IsEnvFile(p.file) {
				p.record(finding.Finding{
					RuleID: "env-file-in-history", Severity: finding.High, Source: finding.SourceHistory,
					Description: "Environment file was committed",
					File:        p.file,
					Fix:         "Every value in this file is public to anyone with the repo. Rotate them all, then purge the file from history with git filter-repo or BFG.",
				}, "")
			}
		}
	case strings.HasPrefix(l, "@@"):
		p.inHeader = false
		if m := hunkHeader.FindStringSubmatch(l); m != nil {
			p.lineNo, _ = strconv.Atoi(m[1])
		}
	case !p.inHeader && strings.HasPrefix(l, "+") && p.file != "":
		content := l[1:]
		// History runs secret rules only, not checks.Line: config smells in
		// old commits are noise, but a leaked value there is still live.
		for _, h := range p.det.Line(content) {
			p.record(finding.Finding{
				RuleID: h.RuleID, Description: h.Description, Severity: h.Severity,
				Source: finding.SourceHistory, File: p.file, Line: p.lineNo, Column: h.Start + 1,
				Secret: finding.Redact(h.Secret), SecretHash: finding.Hash(h.RuleID, h.Secret),
				Fix:     h.Fix + " Removing it in a new commit is not enough: it stays in history until rewritten.",
				Context: []finding.ContextLine{{Number: p.lineNo, Text: p.det.RedactLine(content), Hit: true}},
			}, h.Secret)
		}
		p.lineNo++
	}
}

func (p *parser) record(f finding.Finding, secret string) {
	c := p.commit
	f.Commit = &c
	key := f.RuleID + "\x00" + f.File + "\x00" + finding.Hash(f.RuleID, secret)
	if _, seen := p.found[key]; !seen {
		p.order = append(p.order, key)
	}
	p.found[key] = f
}

func (p *parser) results() []finding.Finding {
	out := make([]finding.Finding, 0, len(p.order))
	for _, k := range p.order {
		out = append(out, p.found[k])
	}
	scan.Sort(out)
	return out
}
