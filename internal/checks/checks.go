// Package checks finds risky configuration: problems that aren't a secret
// value on their own but lead to one leaking (an un-ignored .env file, a
// "public" env var holding a secret, an admin key used in browser code).
//
// Everything here is a pure function of a path and some bytes: no file or
// git I/O, so it is trivially testable. Whether a .env file is ignored or
// committed needs git, so that check lives in package scan.
package checks

import (
	"bufio"
	"bytes"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"keyguard/internal/finding"
	"keyguard/internal/rules"
)

// Framework prefixes that get inlined into the browser bundle.
var publicSecretVar = regexp.MustCompile(`\b((?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|PUBLIC)_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|ADMIN_KEY)[A-Z0-9_]*)\b`)

var supabaseAdminVar = regexp.MustCompile(`\bSUPABASE_(?:SERVICE_ROLE|SECRET)(?:_KEY)?\b`)

var debugTrue = regexp.MustCompile(`(?i)["']?\bdebug["']?\s*[:=]\s*["']?(?:true|1)\b`)

// Line runs per-line config checks on a code file.
func Line(rel, line string, lineNo int, client bool) []finding.Finding {
	var out []finding.Finding
	for _, m := range publicSecretVar.FindAllStringSubmatchIndex(line, -1) {
		out = append(out, publicVarFinding(rel, line[m[2]:m[3]], lineNo, m[2]+1))
	}
	if client && !strings.HasPrefix(strings.TrimSpace(line), "//") {
		if loc := supabaseAdminVar.FindStringIndex(line); loc != nil && !publicSecretVar.MatchString(line) {
			f := rules.MustLookup("supabase-admin-key-in-client").Finding(finding.SourceConfig)
			f.File, f.Line, f.Column, f.Secret = rel, lineNo, loc[0]+1, line[loc[0]:loc[1]]
			out = append(out, f)
		}
	}
	if isProdConfig(rel) && debugTrue.MatchString(line) {
		f := rules.MustLookup("debug-in-production-config").Finding(finding.SourceConfig)
		f.File, f.Line = rel, lineNo
		out = append(out, f)
	}
	return out
}

func publicVarFinding(rel, name string, line, col int) finding.Finding {
	f := rules.MustLookup("secret-in-public-env-var").Finding(finding.SourceConfig)
	f.File, f.Line, f.Column, f.Secret = rel, line, col, name
	return f
}

// EnvFile checks the key NAMES in a dotenv file. Values are never stored or reported.
func EnvFile(rel string, data []byte) []finding.Finding {
	var out []finding.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		key, _, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(key, "#") {
			continue
		}
		key = strings.TrimSpace(strings.TrimPrefix(key, "export "))
		if publicSecretVar.MatchString(key) {
			out = append(out, publicVarFinding(rel, key, n, 1))
		}
	}
	return out
}

var serverPath = regexp.MustCompile(`(^|/)(api|server|actions)(/|$)|\.server\.|(^|/)route\.[jt]s$`)
var clientDir = regexp.MustCompile(`(^|/)(components|hooks|public|client|frontend)/`)

// IsClientFile guesses whether a file ends up in the browser bundle.
func IsClientFile(rel string, head []byte) bool {
	rel = filepath.ToSlash(rel)
	switch path.Ext(rel) {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".vue", ".svelte":
	default:
		return false
	}
	if bytes.Contains(head, []byte(`"use client"`)) || bytes.Contains(head, []byte(`'use client'`)) {
		return true
	}
	return clientDir.MatchString(rel) && !serverPath.MatchString(rel)
}

func isProdConfig(rel string) bool {
	base := strings.ToLower(path.Base(filepath.ToSlash(rel)))
	switch path.Ext(base) {
	case ".json", ".yml", ".yaml", ".toml", ".ini":
		return strings.Contains(base, "prod")
	}
	return false
}
