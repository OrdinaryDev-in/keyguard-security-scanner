package ignore

import (
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	m := Parse(strings.NewReader(`
# comment
.env*
!.env.example
docs/
/build.log
src/generated/*.ts
**/fixtures
`))
	tests := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{".env", false, true},
		{".env.local", false, true},
		{"apps/web/.env.production", false, true}, // unanchored: matches at any depth
		{".env.example", false, false},            // negated
		{"docs", true, true},
		{"docs/guide.md", false, true}, // inside an ignored dir
		{"docs", false, false},         // dir-only pattern vs a file
		{"build.log", false, true},
		{"sub/build.log", false, false}, // anchored to root
		{"src/generated/api.ts", false, true},
		{"src/generated/deep/api.ts", false, false},
		{"test/fixtures/a.json", false, true},
		{"src/index.ts", false, false},
	}
	for _, tt := range tests {
		if got := m.Match(tt.path, tt.isDir); got != tt.want {
			t.Errorf("Match(%q, dir=%v) = %v, want %v", tt.path, tt.isDir, got, tt.want)
		}
	}
}

func TestNilMatcher(t *testing.T) {
	var m *Matcher
	if m.Match("anything", false) {
		t.Error("nil matcher should match nothing")
	}
}
