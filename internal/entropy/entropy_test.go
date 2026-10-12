package entropy

import (
	"math"
	"testing"
)

func TestShannon(t *testing.T) {
	tests := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"aaaaaaaa", 0},
		{"abab", 1},             // two symbols, equal frequency = 1 bit
		{"abcd", 2},             // four symbols = 2 bits
		{"0123456789abcdef", 4}, // all 16 hex digits once = the hex maximum
	}
	for _, tt := range tests {
		if got := Shannon(tt.in); math.Abs(got-tt.want) > 1e-9 {
			t.Errorf("Shannon(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestFind(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"random base64 in quotes", `const s = "q8Zr2LmX9vB4nT7kP1sW6yH3dF5gJ0cA"`, true},
		{"random hex in quotes", `key: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b'`, true},
		{"same token unquoted", `q8Zr2LmX9vB4nT7kP1sW6yH3dF5gJ0cA`, false},
		{"identifier-like string", `"handleOAuth2CallbackV2Route"`, false},
		{"uuid", `"3f2c9a1e-8b4d-4e6f-9a2b-7c1d5e8f0a3b"`, false},
		{"SRI hash", `"sha512-q8Zr2LmX9vB4nT7kP1sW6yH3dF5gJ0cA"`, false},
		{"too short", `"aB3dE5gH9"`, false},
		{"no digits", `"ThisIsJustALongCamelCaseString"`, false},
		{"lowercase words", `"some_long_snake_case_value_1"`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := len(Find(tt.line)) > 0
			if got != tt.want {
				t.Errorf("Find(%s) found=%v, want %v (entropy %.2f)", tt.line, got, tt.want, Shannon(tt.line))
			}
		})
	}
}

func TestFindOffsets(t *testing.T) {
	line := `x = "q8Zr2LmX9vB4nT7kP1sW6yH3dF5gJ0cA";`
	toks := Find(line)
	if len(toks) != 1 {
		t.Fatalf("got %d tokens", len(toks))
	}
	if line[toks[0].Start:toks[0].End] != toks[0].Value {
		t.Errorf("offsets %d:%d don't point at the token", toks[0].Start, toks[0].End)
	}
}
