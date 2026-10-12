// Command keyguard scans a project for leaked secrets and risky config before you deploy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"keyguard/internal/finding"
	"keyguard/internal/gitscan"
	"keyguard/internal/report"
	"keyguard/internal/rules"
	"keyguard/internal/scan"
)

const version = "0.1.0"

// Exit codes: CI only needs to check for non-zero.
const (
	exitClean    = 0
	exitFindings = 1
	exitError    = 2
)

const usage = `keyguard — find leaked secrets and risky config before you deploy

Usage:
  keyguard scan [path] [flags]   scan a project (default path: .)
  keyguard rules                 list built-in detection rules
  keyguard version

Scan flags:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		newScanFlags(stderr).fs.PrintDefaults()
		return exitError
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "rules":
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "RULE\tSEVERITY\tDESCRIPTION")
		for _, r := range rules.Default() {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.ID, r.Severity, r.Description)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", "high-entropy-string", finding.Medium, "Random-looking quoted string (disable with --no-entropy)")
		tw.Flush()
		return exitClean
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "keyguard", version)
		return exitClean
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		newScanFlags(stdout).fs.PrintDefaults()
		return exitClean
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return exitError
}

type scanFlags struct {
	fs         *flag.FlagSet
	format     *string
	output     *string
	failOn     *string
	history    *bool
	maxCommits *int
	since      *string
	noEntropy  *bool
	noColor    *bool
	workers    *int
	context    *int
}

func newScanFlags(out io.Writer) *scanFlags {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(out)
	return &scanFlags{
		fs:         fs,
		format:     fs.String("format", "text", "output format: text, json, sarif, html"),
		output:     fs.String("o", "", "write the report to this file instead of stdout"),
		failOn:     fs.String("fail-on", "high", "exit 1 if any finding is at or above: high, medium, low, none"),
		history:    fs.Bool("history", false, "also scan every commit in git history"),
		maxCommits: fs.Int("max-commits", 0, "with --history: only scan the newest N commits (0 = all)"),
		since:      fs.String("since", "", `with --history: only commits after this date, e.g. "6 months ago"`),
		noEntropy:  fs.Bool("no-entropy", false, "disable high-entropy string detection (fewer false positives)"),
		noColor:    fs.Bool("no-color", false, "disable colored output (also honours NO_COLOR)"),
		workers:    fs.Int("workers", 0, "parallel file workers (0 = number of CPUs)"),
		context:    fs.Int("context", 3, "lines of code context to include around each finding"),
	}
}

// parseInterleaved lets flags come before or after the path. Go's flag
// package stops at the first non-flag argument, so `scan . --history` would
// otherwise silently ignore --history.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	f := newScanFlags(stderr)
	pos, err := parseInterleaved(f.fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitClean
	}
	if err != nil {
		return exitError
	}
	if len(pos) > 1 {
		fmt.Fprintln(stderr, "keyguard: scan takes one path")
		return exitError
	}
	if !*f.history && (*f.maxCommits != 0 || *f.since != "") {
		fmt.Fprintln(stderr, "keyguard: warning: --max-commits/--since only apply with --history")
	}
	failOn, err := finding.ParseSeverity(*f.failOn)
	if err != nil {
		fmt.Fprintln(stderr, "keyguard:", err)
		return exitError
	}
	root := "."
	if len(pos) == 1 {
		root = pos[0]
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		fmt.Fprintf(stderr, "keyguard: %s is not a directory\n", root)
		return exitError
	}
	abs, _ := filepath.Abs(root)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	start := time.Now()
	res, err := scan.Dir(ctx, scan.Options{
		Root: root, Workers: *f.workers, Entropy: !*f.noEntropy, Context: *f.context,
	})
	if err != nil {
		fmt.Fprintln(stderr, "keyguard:", err)
		return exitError
	}
	rep := &report.Report{
		Tool: "keyguard", Version: version, Root: abs, ScannedAt: start,
		FilesScanned: res.FilesScanned, Findings: res.Findings, History: *f.history,
	}

	if *f.history {
		h, err := gitscan.Scan(ctx, gitscan.Options{
			Root: root, MaxCommits: *f.maxCommits, Since: *f.since, Entropy: !*f.noEntropy,
		})
		if err != nil {
			fmt.Fprintln(stderr, "keyguard:", err)
			return exitError
		}
		current := map[string]bool{}
		for _, cf := range res.Findings {
			if cf.SecretHash != "" {
				current[cf.SecretHash] = true
			}
		}
		for i := range h.Findings {
			hf := &h.Findings[i]
			hf.Commit.InWorkingTree = hf.SecretHash != "" && current[hf.SecretHash]
		}
		rep.Findings = append(rep.Findings, h.Findings...)
		rep.Commits = h.Commits
	}
	rep.DurationMS = time.Since(start).Milliseconds()
	rep.Summary = report.Summarize(rep.Findings)

	out := stdout
	color := os.Getenv("NO_COLOR") == "" && !*f.noColor && isTerminal(stdout)
	if *f.output != "" {
		file, err := os.Create(*f.output)
		if err != nil {
			fmt.Fprintln(stderr, "keyguard:", err)
			return exitError
		}
		out, color = file, false
	}
	err = report.Write(out, rep, strings.ToLower(*f.format), color)
	if file, ok := out.(*os.File); ok && *f.output != "" {
		// A failed Close can mean a truncated report; don't let CI pass on that.
		if cerr := file.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "keyguard:", err)
		return exitError
	}
	if *f.output != "" {
		fmt.Fprintf(stderr, "keyguard: %d findings, report written to %s\n", rep.Summary.Total(), *f.output)
	}

	if failOn != finding.None {
		for _, fd := range rep.Findings {
			if fd.Severity >= failOn {
				return exitFindings
			}
		}
	}
	return exitClean
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
