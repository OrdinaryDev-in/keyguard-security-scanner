package entropy

import (
	_ "embed"
	"strings"
	"sync"
	"unicode"
)

//go:embed words.txt
var wordsTxt string

// shortWords are 2-letter fragments common in identifiers (getUserById, toJSON).
// They only count as a whole fragment, never as a piece of a longer one,
// because random keys are full of 2-letter runs.
var shortWords = map[string]bool{
	"id": true, "by": true, "to": true, "of": true, "in": true, "on": true,
	"at": true, "is": true, "as": true, "or": true, "if": true, "no": true,
	"ok": true, "up": true, "do": true, "go": true, "my": true, "io": true,
	"os": true, "db": true, "ui": true, "fs": true, "ip": true, "js": true,
	"ts": true,
}

var dictionary = sync.OnceValue(func() map[string]bool {
	m := make(map[string]bool, 6000)
	for _, w := range strings.Split(wordsTxt, "\n") {
		if w = strings.TrimSpace(w); w != "" && w[0] != '#' {
			m[w] = true
		}
	}
	return m
})

const (
	maxIdentDigits  = 4 // handleOAuth2CallbackV2 has 2, base64ToUint8Array 3
	minWordLen      = 3 // pieces of a compound fragment ("webhook" = web+hook)
	uncoveredDivide = 8 // at most 1 letter in 8 may be outside a word
)

// looksLikeWords reports whether v is built from dictionary words, like the
// identifier handleOAuth2CallbackV2 (handle·O·Auth·2·Callback·V·2), rather
// than random characters. It is deliberately strict, because returning true
// hides a finding:
//
//   - any of + / = (only base64 uses them) means it is not an identifier;
//   - at most 4 digits, and no more than 20% of the length (hex is ~60%);
//   - at least two words, and 7 in 8 letters must be inside one.
//
// Random keys change case every couple of characters, so they split into
// 1–2 letter fragments that are almost never words.
func looksLikeWords(v string) bool {
	if strings.ContainsAny(v, "+/=") {
		return false
	}
	// Cheap test first: most random keys fail here, before any splitting.
	digits := 0
	for i := 0; i < len(v); i++ {
		if v[i] >= '0' && v[i] <= '9' {
			digits++
		}
	}
	if digits > maxIdentDigits || digits*5 > len(v) {
		return false
	}
	var letters, uncovered, words int
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == '_' || r == '-' }) {
		for _, f := range splitCamel(part) {
			if f[0] >= '0' && f[0] <= '9' {
				continue
			}
			letters += len(f)
			if n := countWords(strings.ToLower(f)); n > 0 {
				words += n
			} else if uncovered += len(f); uncovered*uncoveredDivide > len(v) {
				return false // can't recover: letters <= len(v)
			}
		}
	}
	return words >= 2 && uncovered*uncoveredDivide <= letters
}

// splitCamel splits an ASCII identifier into words and digit runs:
// "parseHTTPRequest2" -> parse, HTTP, Request, 2. An upper-case run followed
// by a lower-case letter gives up its last letter: "HTTPServer" -> HTTP, Server.
func splitCamel(s string) []string {
	var out []string
	start := 0
	for i := 1; i < len(s); i++ {
		prev, cur := rune(s[i-1]), rune(s[i])
		split := false
		switch {
		case unicode.IsDigit(prev) != unicode.IsDigit(cur):
			split = true
		case unicode.IsLower(prev) && unicode.IsUpper(cur):
			split = true
		case unicode.IsUpper(prev) && unicode.IsUpper(cur) && i+1 < len(s) && unicode.IsLower(rune(s[i+1])):
			split = true
		}
		if split {
			out = append(out, s[start:i])
			start = i
		}
	}
	return append(out, s[start:])
}

// countWords returns how many dictionary words f (lowercase letters) splits
// into, or 0 if it can't be split completely. "callback" -> 1, "webhook" ->
// 2 if only "web" and "hook" are listed, "zr" -> 0.
func countWords(f string) int {
	if shortWords[f] {
		return 1
	}
	dict := dictionary()
	if dict[f] || dict[stem(f)] {
		return 1
	}
	if len(f) < 2*minWordLen {
		return 0
	}
	// best[i] = fewest words covering f[:i], or 0 if f[:i] can't be covered.
	best := make([]int, len(f)+1)
	for i := minWordLen; i <= len(f); i++ {
		for j := 0; j <= i-minWordLen; j++ {
			if (j == 0 || best[j] > 0) && dict[f[j:i]] {
				if n := best[j] + 1; best[i] == 0 || n < best[i] {
					best[i] = n
				}
			}
		}
	}
	return best[len(f)]
}

// stem strips one common English suffix, so "throttled" and "tokens" match
// "throttle" and "token". The stem must still be a 3+ letter word.
func stem(f string) string {
	for _, suf := range []string{"ing", "ed", "es", "er", "s", "d"} {
		if len(f)-len(suf) >= minWordLen && strings.HasSuffix(f, suf) {
			if s := f[:len(f)-len(suf)]; dictionary()[s] {
				return s
			}
		}
	}
	return f
}
