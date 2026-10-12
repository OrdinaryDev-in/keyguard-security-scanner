// Package scan walks a directory and runs every detector over every text file,
// using a pool of goroutines so large repos scan in parallel.
package scan

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"keyguard/internal/checks"
	"keyguard/internal/detect"
	"keyguard/internal/finding"
	"keyguard/internal/ignore"
	"keyguard/internal/pathpolicy"
	"keyguard/internal/rules"
)

type Options struct {
	Root        string
	Workers     int   // 0 = one per CPU
	MaxFileSize int64 // 0 = 2 MiB
	Entropy     bool
	Context     int // lines of context around each finding (0 = none)
}

type Result struct {
	Findings     []finding.Finding
	FilesScanned int
	Duration     time.Duration
}

type fileResult struct {
	rel      string
	findings []finding.Finding
	scanned  bool
	env      bool // a dotenv file: checked for git exposure once the walk is done
}

// Dir scans every file under opts.Root.
func Dir(ctx context.Context, opts Options) (*Result, error) {
	start := time.Now()
	if opts.Workers <= 0 {
		opts.Workers = runtime.NumCPU()
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 2 << 20
	}
	ign, err := ignore.Load(filepath.Join(opts.Root, pathpolicy.IgnoreFile))
	if err != nil {
		return nil, err
	}
	det, err := detect.New(opts.Entropy)
	if err != nil {
		return nil, err
	}

	// Pipeline: one walker goroutine -> paths channel -> N workers -> results channel -> this goroutine.
	// Everything the collector needs travels on a channel, so no variable is
	// shared between goroutines.
	paths := make(chan string)
	results := make(chan fileResult)
	walkErr := make(chan error, 1) // buffered: the walker can always send and exit
	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rel := range paths {
				found, ok := scanFile(det, opts, rel)
				results <- fileResult{rel: rel, findings: found, scanned: ok, env: pathpolicy.IsEnvFile(rel)}
			}
		}()
	}

	go func() {
		defer close(paths)
		walkErr <- filepath.WalkDir(opts.Root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable entry: skip it, keep walking
			}
			rel, _ := filepath.Rel(opts.Root, p)
			rel = filepath.ToSlash(rel)
			if rel == "." {
				return nil
			}
			if d.IsDir() {
				if pathpolicy.SkipDir(d.Name()) || ign.Match(rel, true) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || ign.Match(rel, false) {
				return nil
			}
			select {
			case paths <- rel:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
	}()
	// Close results once every worker has finished, so the range below ends.
	go func() { wg.Wait(); close(results) }()

	res := &Result{}
	var envFiles []string
	for r := range results {
		res.Findings = append(res.Findings, r.findings...)
		if r.scanned {
			res.FilesScanned++
		}
		if r.env {
			envFiles = append(envFiles, r.rel)
		}
	}
	if err := <-walkErr; err != nil {
		return nil, err
	}
	exposed, err := envExposure(ctx, opts.Root, envFiles)
	if err != nil {
		return nil, err
	}
	res.Findings = append(res.Findings, exposed...)
	finding.Sort(res.Findings)
	res.Duration = time.Since(start)
	return res, nil
}

func scanFile(det *detect.Detector, opts Options, rel string) ([]finding.Finding, bool) {
	if pathpolicy.Skippable(rel) {
		return nil, false
	}
	full := filepath.Join(opts.Root, filepath.FromSlash(rel))
	info, err := os.Stat(full)
	if err != nil || info.Size() > opts.MaxFileSize {
		return nil, false
	}
	data, err := os.ReadFile(full)
	if err != nil || isBinary(data) {
		return nil, false
	}
	// A real .env file is SUPPOSED to hold secrets; the risk is it being
	// committed or exposed, which envExposure handles. Here we only
	// look at variable names and never touch the values.
	if pathpolicy.IsEnvFile(rel) {
		return checks.EnvFile(rel, data), true
	}
	return Content(det, rel, data, opts.Context, checks.IsClientFile(rel, head(data))), true
}

// maxFindingsPerFile stops one generated file (thousands of random strings)
// from producing a huge report and quadratic work.
const maxFindingsPerFile = 100

// Content scans a file's bytes. Exported so tests and other scanners can reuse it.
func Content(det *detect.Detector, rel string, data []byte, contextLines int, client bool) []finding.Finding {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4<<20) // allow long minified lines
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	ctx := newContexter(det, lines, contextLines)
	var out []finding.Finding
	for i, line := range lines {
		if len(out) >= maxFindingsPerFile {
			f := rules.MustLookup("too-many-findings").Finding(finding.SourceCode)
			f.File, f.Line = rel, i+1
			out = append(out, f)
			break
		}
		if strings.Contains(line, detect.IgnoreMarker) {
			continue
		}
		for _, h := range det.Line(line) {
			f := h.Finding(finding.SourceCode, rel, i+1)
			f.Context = ctx.around(i)
			out = append(out, f)
		}
		for _, f := range checks.Line(rel, line, i+1, client) {
			f.Context = ctx.around(i)
			out = append(out, f)
		}
	}
	return out
}

const maxContextWidth = 200

// contexter builds redacted context lines, redacting each source line at most
// once per file (re-running detection per finding was quadratic).
type contexter struct {
	det      *detect.Detector
	lines    []string
	n        int
	redacted map[int]string
	inKey    []bool // line is inside a PEM private-key block
}

func newContexter(det *detect.Detector, lines []string, n int) *contexter {
	c := &contexter{det: det, lines: lines, n: n, redacted: map[int]string{}, inKey: make([]bool, len(lines))}
	// Only the BEGIN line matches a rule; the key body below it, in whatever
	// shape (bare base64, "...\n" + string concatenation, YAML), must never be shown.
	in := false
	for i, l := range lines {
		if strings.Contains(l, "-----BEGIN") && strings.Contains(l, "PRIVATE KEY") {
			in = true
			continue // the header itself is redacted by the private-key rule
		}
		if in {
			c.inKey[i] = true
			if strings.Contains(l, "-----END") {
				in = false
			}
		}
	}
	return c
}

func (c *contexter) line(i int) string {
	if t, ok := c.redacted[i]; ok {
		return t
	}
	var t string
	if c.inKey[i] {
		t = "[redacted private key]"
	} else {
		t = c.det.RedactLine(c.lines[i])
		if r := []rune(t); len(r) > maxContextWidth { // cut on runes, not bytes, to keep UTF-8 valid
			t = string(r[:maxContextWidth]) + "…"
		}
	}
	c.redacted[i] = t
	return t
}

func (c *contexter) around(idx int) []finding.ContextLine {
	if c.n <= 0 {
		return nil
	}
	var out []finding.ContextLine
	for i := max(0, idx-c.n); i <= min(len(c.lines)-1, idx+c.n); i++ {
		out = append(out, finding.ContextLine{Number: i + 1, Text: c.line(i), Hit: i == idx})
	}
	return out
}

func head(data []byte) []byte { return data[:min(len(data), 512)] }

// isBinary uses the same trick as git: a NUL byte near the start means binary.
func isBinary(data []byte) bool { return bytes.IndexByte(head(data), 0) >= 0 }
