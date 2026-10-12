// Package pathpolicy decides which paths are worth scanning. The working-tree
// scan and the git-history scan share it, so both skip the same files.
package pathpolicy

import (
	"path"
	"path/filepath"
	"strings"
)

// IgnoreFile is read from the scan root, in .gitignore syntax.
const IgnoreFile = ".keyguardignore"

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".next": true, ".nuxt": true, ".svelte-kit": true, ".turbo": true, ".vercel": true,
	".expo": true, "coverage": true, "out": true, "__pycache__": true, ".venv": true,
	"venv": true, "target": true, "Pods": true, ".gradle": true, ".idea": true,
}

// Files whose contents are full of hashes that look random but are public.
var skipFiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "bun.lockb": true,
	"go.sum": true, "Cargo.lock": true, "poetry.lock": true, "Gemfile.lock": true,
	"composer.lock": true, "Podfile.lock": true,
}

var skipExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true,
	".svg": true, ".pdf": true, ".zip": true, ".gz": true, ".tar": true, ".woff": true,
	".woff2": true, ".ttf": true, ".eot": true, ".mp4": true, ".mov": true, ".mp3": true,
	".map": true, ".lock": true, ".snap": true,
}

// SkipDir reports whether a directory with this name is never descended into.
func SkipDir(name string) bool { return skipDirs[name] }

// Skippable reports whether a file is never worth scanning (lockfiles, media, minified bundles).
func Skippable(rel string) bool {
	name := path.Base(rel)
	return skipFiles[name] || skipExts[strings.ToLower(path.Ext(name))] ||
		strings.HasSuffix(name, ".min.js") || strings.HasSuffix(name, ".min.css")
}

// SkipPath reports whether a repo-relative path is excluded by the built-in
// policy: inside a skipped directory (node_modules, .git, dist...) or Skippable.
func SkipPath(rel string) bool {
	parts := strings.Split(rel, "/")
	for _, d := range parts[:len(parts)-1] {
		if skipDirs[d] {
			return true
		}
	}
	return Skippable(rel)
}

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
