// Package ignore implements a small subset of .gitignore syntax, used for
// .keyguardignore and as a fallback for checking .gitignore outside git.
//
// Supported: blank lines, # comments, ! negation, trailing / (dirs only),
// leading / or an inner / (anchored to the root), * ? [..] globs, and a
// leading **/ (treated as "any depth"). Not supported: ** in the middle.
package ignore

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

type pattern struct {
	glob     string
	negate   bool
	dirOnly  bool
	anchored bool
}

type Matcher struct{ patterns []pattern }

// Parse reads patterns, one per line.
func Parse(r io.Reader) *Matcher {
	m := &Matcher{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		m.Add(sc.Text())
	}
	return m
}

// Load parses a file. A missing file is not an error: it yields an empty Matcher.
func Load(file string) (*Matcher, error) {
	f, err := os.Open(file)
	if errors.Is(err, fs.ErrNotExist) {
		return &Matcher{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f), nil
}

// Add appends one pattern line.
func (m *Matcher) Add(line string) {
	line = strings.TrimRight(line, " \t\r")
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	p := pattern{}
	if strings.HasPrefix(line, "!") {
		p.negate, line = true, line[1:]
	}
	if strings.HasSuffix(line, "/") {
		p.dirOnly, line = true, strings.TrimSuffix(line, "/")
	}
	line = strings.TrimPrefix(line, "**/")
	if strings.HasPrefix(line, "/") {
		p.anchored, line = true, line[1:]
	} else if strings.Contains(line, "/") {
		p.anchored = true
	}
	p.glob = line
	m.patterns = append(m.patterns, p)
}

// Match reports whether rel (slash-separated, relative to the root) is
// ignored, either itself or because one of its parent directories is.
func (m *Matcher) Match(rel string, isDir bool) bool {
	if m == nil || len(m.patterns) == 0 {
		return false
	}
	rel = strings.TrimPrefix(path.Clean(rel), "./")
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		if m.matchOne(strings.Join(parts[:i], "/"), true) {
			return true
		}
	}
	return m.matchOne(rel, isDir)
}

func (m *Matcher) matchOne(rel string, isDir bool) bool {
	ignored := false
	base := path.Base(rel)
	for _, p := range m.patterns {
		if p.dirOnly && !isDir {
			continue
		}
		var ok bool
		if p.anchored {
			ok, _ = path.Match(p.glob, rel)
		} else {
			ok, _ = path.Match(p.glob, base)
		}
		if ok {
			ignored = !p.negate
		}
	}
	return ignored
}
