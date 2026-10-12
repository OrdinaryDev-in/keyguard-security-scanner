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

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/finding"
	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/rules"
)

// Framework prefixes that get inlined into the browser bundle.
var publicSecretVar = regexp.MustCompile(`\b((?:NEXT_PUBLIC|VITE|REACT_APP|VUE_APP|NG_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|PUBLIC)_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|ADMIN_KEY)[A-Z0-9_]*)\b`)

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
	out = append(out, firebaseRules(rel, line, lineNo)...)
	if isTerraformState(rel) && strings.Contains(line, `"terraform_version"`) {
		out = append(out, at(rules.MustLookup("terraform-state-file"), rel, lineNo, 0, ""))
	}
	if isProdConfig(rel) && debugTrue.MatchString(line) {
		f := rules.MustLookup("debug-in-production-config").Finding(finding.SourceConfig)
		f.File, f.Line = rel, lineNo
		out = append(out, f)
	}
	return out
}

func at(m rules.Meta, rel string, line, col int, secret string) finding.Finding {
	f := m.Finding(finding.SourceConfig)
	f.File, f.Line, f.Column, f.Secret = rel, line, col, secret
	return f
}

// Firestore/Storage rules: `allow read, write;` or `allow write: if true;`.
// The statement must end right after the (optional) `if true`, so
// `allow read: if request.auth != null;` never matches.
var allowStmt = regexp.MustCompile(`\ballow\s+([a-z][a-z,\s]*?)\s*(?::\s*if\s+true\s*)?;`)
var testMode = regexp.MustCompile(`\ballow\s+[a-z,\s]+:\s*if\s+request\.time\s*<\s*timestamp\.date`)

// Realtime Database rules JSON: ".write": true
var rtdbOpen = regexp.MustCompile(`"\.(read|write)"\s*:\s*(?:true|"true")`)

func firebaseRules(rel, line string, lineNo int) []finding.Finding {
	base := path.Base(filepath.ToSlash(rel))
	var out []finding.Finding
	switch {
	case strings.HasSuffix(base, ".rules"): // firestore.rules, storage.rules
		code, _, _ := strings.Cut(line, "//")
		if loc := testMode.FindStringIndex(code); loc != nil {
			return append(out, at(rules.MustLookup("firebase-rules-test-mode"), rel, lineNo, loc[0]+1, ""))
		}
		for _, m := range allowStmt.FindAllStringSubmatchIndex(code, -1) {
			ops := code[m[2]:m[3]]
			id := "firebase-rules-public-read"
			if containsOp(ops, "write", "create", "update", "delete") {
				id = "firebase-rules-public-write"
			}
			out = append(out, at(rules.MustLookup(id), rel, lineNo, m[0]+1, strings.TrimSpace(ops)))
		}
	case base == "database.rules.json":
		for _, m := range rtdbOpen.FindAllStringSubmatchIndex(line, -1) {
			id := "firebase-rules-public-read"
			if line[m[2]:m[3]] == "write" {
				id = "firebase-rules-public-write"
			}
			out = append(out, at(rules.MustLookup(id), rel, lineNo, m[0]+1, "."+line[m[2]:m[3]]))
		}
	}
	return out
}

func containsOp(ops string, names ...string) bool {
	for _, f := range strings.FieldsFunc(ops, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		for _, n := range names {
			if f == n {
				return true
			}
		}
	}
	return false
}

func isTerraformState(rel string) bool {
	base := path.Base(filepath.ToSlash(rel))
	return strings.HasSuffix(base, ".tfstate") || strings.HasSuffix(base, ".tfstate.backup")
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
