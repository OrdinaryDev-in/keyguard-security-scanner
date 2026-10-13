package entropy

import (
	"math"
	"math/rand"
	"strings"
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

func TestFindIn(t *testing.T) {
	key := randomKey(rand.New(rand.NewSource(1)), alnum, 32) // built at runtime: no literal secret in the repo
	tests := []struct {
		name, file, line string
		want             bool
	}{
		// Backticks are strings in JS/TS and Go...
		{"ts template string", "src/api.ts", "const k = `" + key + "`;", true},
		{"vue template string", "src/App.vue", "headers: { x: `" + key + "` }", true},
		{"go raw string", "cmd/main.go", "const k = `" + key + "`", true},
		{"unknown file keeps backticks", "", "`" + key + "`", true},
		// ...but code spans elsewhere.
		{"markdown code span", "docs/README.md", "Call `handleOAuth2CallbackV2` on redirect.", false},
		{"markdown span, random", "docs/README.md", "Set it to `" + key + "`.", false},
		{"shell substitution", "deploy.sh", "TOKEN=`" + key + "`", false},
		{"markdown double quotes still count", "docs/README.md", `token: "` + key + `"`, true},
		{"extension case-insensitive", "src/API.TS", "`" + key + "`", true},
		// Identifiers are skipped in any file, quoted any way.
		{"identifier in ts string", "src/routes.ts", `{ handler: "handleOAuth2CallbackV2" }`, false},
		{"identifier in ts template", "src/routes.ts", "`handleOAuth2CallbackV2`", false},
		{"no-digit identifier", "src/user.ts", `"getUserProfileSettingsById"`, false},
		{"snake case identifier", "app.py", `"handle_oauth2_callback_v2_route"`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(FindIn(tt.file, tt.line)) > 0; got != tt.want {
				t.Errorf("FindIn(%q, %s) found=%v, want %v", tt.file, tt.line, got, tt.want)
			}
		})
	}
}

func TestLooksLikeWords(t *testing.T) {
	// Each passes the entropy threshold on its own, so without the word
	// check every one of these would be reported.
	for _, id := range []string{
		"handleOAuth2CallbackV2",
		"handleOAuth2CallbackV2Route",
		"base64ToUint8ArrayHelper",
		"parseHTTP2ServerConfigV3",
		"useFirebaseAuthStateV2",
		"sha256DigestFromBytes",
		"getS3BucketPolicyForUser",
		"upload-avatar-thumbnail-v2",
		"STRIPE_WEBHOOK_HANDLER_V2",
	} {
		if v := `"` + id + `"`; !wouldFlag(id) {
			t.Errorf("%s is below the entropy threshold anyway; pick a harder example", v)
		}
		if !looksLikeWords(id) {
			t.Errorf("looksLikeWords(%q) = false, want true", id)
		}
	}
	r := rand.New(rand.NewSource(2))
	key := randomKey(r, alnum, 24)
	for _, s := range []string{
		key,                                // random alphanumeric
		randomKey(r, hexLower, 40),         // random hex
		"handleOAuth2Callback/" + key[:12], // base64 alphabet
		"handleOAuthCallback" + key,        // words, then a key
		"handle_oauth_callback_" + key,     // same, snake case
		"Handle2Get3Set4User5Auth6",        // too many digits
	} {
		if looksLikeWords(s) {
			t.Errorf("looksLikeWords(%q) = true, want false", s)
		}
	}
}

func TestSplitCamel(t *testing.T) {
	got := strings.Join(splitCamel("handleOAuth2CallbackV2"), "·")
	if want := "handle·O·Auth·2·Callback·V·2"; got != want {
		t.Errorf("splitCamel = %s, want %s", got, want)
	}
	got = strings.Join(splitCamel("parseHTTPServer"), "·")
	if want := "parse·HTTP·Server"; got != want {
		t.Errorf("splitCamel = %s, want %s", got, want)
	}
}

const (
	alnum     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	base64Std = alnum + "+/"
	base64URL = alnum + "-_"
	hexLower  = "0123456789abcdef"
	hexUpper  = "0123456789ABCDEF"
)

func randomKey(r *rand.Rand, charset string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	return string(b)
}

// wouldFlag reports whether v passes every check except the word check.
func wouldFlag(v string) bool {
	_, ok := classify(v)
	return ok || looksLikeWords(v)
}

// The word check hides findings, so it must never fire on a real key.
// Thousands of seeded random keys of every length and alphabet keyguard
// looks for: not one may look like words, and every one that passes the
// entropy checks must still be reported.
func TestRandomKeysNeverLookLikeWords(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	perLength := 100
	if testing.Short() {
		perLength = 10
	}
	for _, cs := range []string{alnum, base64Std, base64URL, hexLower, hexUpper} {
		for n := minLen; n <= maxLen; n++ {
			for i := 0; i < perLength; i++ {
				key := randomKey(r, cs, n)
				if looksLikeWords(key) {
					t.Fatalf("random key looks like words: %s", key)
				}
				if wouldFlag(key) && len(Find(`"`+key+`"`)) == 0 {
					t.Fatalf("random key no longer reported: %s", key)
				}
			}
		}
	}
}
