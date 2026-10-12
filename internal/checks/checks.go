// Package checks finds risky configuration: problems that aren't a secret
// value on their own but lead to one leaking (an un-ignored .env file, a
// "public" env var holding a secret, an admin key used in browser code).
package checks

import (
	"bufio"
	"bytes"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"keyguard/internal/finding"
	"keyguard/internal/ignore"
)

// IsEnvFile reports whether name is a real dotenv file (.env, .env.local, ...).
// Templates like .env.example are scanned as normal code instead, because
// people do paste real keys into them.
func IsEnvFile(name string) bool {
	base := path.Base(filepath.ToSlash(name))
	if base != ".env" && !strings.HasPrefix(base, ".env.") {
		return false
	}
	for _, t := range []string{".example", ".sample", ".template", ".dist", ".defaults"} {
		if strings.HasSuffix(base, t) {
			return false
		}
	}
	return true
}

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
			out = append(out, finding.Finding{
				RuleID: "supabase-admin-key-in-client", Severity: finding.Medium, Source: finding.SourceConfig,
				Description: "Supabase admin key referenced in client-side code",
				File:        rel, Line: lineNo, Column: loc[0] + 1, Secret: line[loc[0]:loc[1]],
				Fix: "Admin keys must never reach the browser. Move this call into a server route/action (route.ts, a Server Action, or an Edge Function) and use the anon/publishable key in client code.",
			})
		}
	}
	if isProdConfig(rel) && debugTrue.MatchString(line) {
		out = append(out, finding.Finding{
			RuleID: "debug-in-production-config", Severity: finding.Low, Source: finding.SourceConfig,
			Description: "Debug mode enabled in a production config file", File: rel, Line: lineNo,
			Fix: "Debug output can leak stack traces, env values and internal paths. Disable it for production.",
		})
	}
	return out
}

func publicVarFinding(rel, name string, line, col int) finding.Finding {
	return finding.Finding{
		RuleID: "secret-in-public-env-var", Severity: finding.High, Source: finding.SourceConfig,
		Description: "Secret-looking variable uses a browser-exposed prefix",
		File:        rel, Line: line, Column: col, Secret: name,
		Fix: "Variables with NEXT_PUBLIC_/VITE_/REACT_APP_/EXPO_PUBLIC_ prefixes are baked into the JavaScript bundle that every visitor downloads. Drop the prefix, read it only on the server, and rotate the value.",
	}
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

// EnvExposure checks whether each dotenv file is protected from being committed.
func EnvExposure(root string, envFiles []string) []finding.Finding {
	if len(envFiles) == 0 {
		return nil
	}
	inRepo := git(root, "rev-parse", "--is-inside-work-tree") == nil
	var gi *ignore.Matcher
	if !inRepo {
		gi, _ = ignore.Load(filepath.Join(root, ".gitignore"))
	}
	var out []finding.Finding
	for _, f := range envFiles {
		base := finding.Finding{Source: finding.SourceConfig, File: f, Severity: finding.High}
		switch {
		case inRepo && git(root, "ls-files", "--error-unmatch", "--", f) == nil:
			base.RuleID = "env-file-committed"
			base.Description = "Environment file is committed to git"
			base.Fix = "Run `git rm --cached " + f + "`, add it to .gitignore, and rotate every value in it — they are in your git history now (see --history)."
		case inRepo && git(root, "check-ignore", "-q", "--", f) != nil:
			base.RuleID = "env-file-not-ignored"
			base.Description = "Environment file is not in .gitignore"
			base.Fix = "Add `.env*` and `!.env.example` to .gitignore so the next `git add .` can't commit it."
		case !inRepo && !gi.Match(f, false):
			base.RuleID = "env-file-not-ignored"
			base.Severity = finding.Medium
			base.Description = "Environment file is not covered by .gitignore (not a git repo yet)"
			base.Fix = "Add `.env*` and `!.env.example` to .gitignore before running `git init`/`git add`."
		default:
			continue
		}
		out = append(out, base)
	}
	return out
}

func git(dir string, args ...string) error {
	cmd := exec.Command("git", append([]string{"-c", "core.fsmonitor=false", "-C", dir}, args...)...)
	return cmd.Run()
}
