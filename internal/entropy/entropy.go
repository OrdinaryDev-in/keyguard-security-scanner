// Package entropy finds random-looking strings that no regex rule knows about.
//
// Shannon entropy measures how unpredictable a string is, in bits per character:
//
//	H = -Σ p(c) · log2 p(c)    over every distinct character c
//
// "aaaaaaaa" scores 0, English words score ~3, and random API keys score 4.5+.
// The catch: a string of length n can never score more than log2(n), so a
// fixed threshold would ignore every short secret. Thresholds here scale with length.
package entropy

import (
	"math"
	"path"
	"regexp"
	"strings"
)

// Shannon returns the entropy of s in bits per character.
func Shannon(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int)
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// Token is a high-entropy string found inside a line.
type Token struct {
	Value      string
	Start, End int // byte offsets of Value within the line
	Entropy    float64
	Hex        bool
}

const (
	minLen = 20
	maxLen = 120 // longer quoted blobs are usually embedded images or fonts
)

// Only look inside quotes. Unquoted identifiers like handleOAuth2CallbackV2
// are long and mixed-case too, and were the biggest source of false positives.
var (
	quoted           = regexp.MustCompile("[\"'`]([A-Za-z0-9+/=_\\-]{20,})[\"'`]")
	quotedNoBacktick = regexp.MustCompile(`["']([A-Za-z0-9+/=_\-]{20,})["']`)
)

// backtickStrings are the file types where `...` is a string literal: JS/TS
// template strings and Go raw strings. Elsewhere backticks are Markdown code
// spans, shell command substitution or SQL identifiers, which hold names.
var backtickStrings = map[string]bool{
	".js": true, ".jsx": true, ".mjs": true, ".cjs": true,
	".ts": true, ".tsx": true, ".mts": true, ".cts": true,
	".vue": true, ".svelte": true, ".astro": true,
	".go": true,
}

var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Find returns quoted tokens in line, from an unknown file, that look like
// secrets. Backticks count as quotes; see FindIn.
func Find(line string) []Token { return FindIn("", line) }

// FindIn returns quoted tokens in a line of the file at rel that look like
// secrets. Backticks only count as quotes in languages that use them for
// strings. When the file is unknown (rel == "") they always count: missing a
// key costs more than an extra finding.
func FindIn(rel, line string) []Token {
	re := quoted
	if rel != "" && !backtickStrings[strings.ToLower(path.Ext(rel))] {
		re = quotedNoBacktick
	}
	var out []Token
	for _, m := range re.FindAllStringSubmatchIndex(line, -1) {
		start, end := m[2], m[3]
		v := line[start:end]
		if t, ok := classify(v); ok {
			t.Start, t.End = start, end
			out = append(out, t)
		}
	}
	return out
}

// IsRandom reports whether s looks random enough to be a secret.
// Rules use it to reject placeholder values like "your-api-key-here".
func IsRandom(s string, min float64) bool { return Shannon(s) >= min }

func classify(v string) (Token, bool) {
	if len(v) < minLen || len(v) > maxLen || uuid.MatchString(v) {
		return Token{}, false
	}
	// Subresource-integrity hashes ("sha512-...") are public by design.
	for _, p := range []string{"sha256-", "sha384-", "sha512-"} {
		if strings.HasPrefix(v, p) {
			return Token{}, false
		}
	}
	var digit, upper, lower bool
	isHex := true
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'a' && r <= 'f':
			lower = true
		case r >= 'A' && r <= 'F':
			upper = true
		case r >= 'g' && r <= 'z':
			lower, isHex = true, false
		case r >= 'G' && r <= 'Z':
			upper, isHex = true, false
		default:
			isHex = false
		}
	}
	// Real keys mix digits with letters; words_joined_like_this don't.
	if !digit || !(upper || lower) {
		return Token{}, false
	}
	h := Shannon(v)
	maxPossible := math.Log2(float64(len(v)))
	var threshold float64
	if isHex {
		// Hex has only 16 symbols, so it tops out at 4 bits/char.
		threshold = math.Min(3.0, 0.75*maxPossible)
	} else {
		if !(upper && lower) {
			return Token{}, false
		}
		threshold = math.Min(4.5, 0.85*maxPossible)
	}
	if h < threshold {
		return Token{}, false
	}
	// Checked last: it's the slowest test, and few strings get this far.
	if looksLikeWords(v) {
		return Token{}, false
	}
	return Token{Value: v, Entropy: h, Hex: isHex}, true
}
