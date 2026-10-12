package scan

import (
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/detect"
	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/fixture"
	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/pathpolicy"
)

func newDetector(t *testing.T) *detect.Detector {
	t.Helper()
	d, err := detect.New(true)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func scanFixture(t *testing.T) (*Result, string) {
	t.Helper()
	dir := t.TempDir()
	if err := fixture.Write(dir); err != nil {
		t.Fatal(err)
	}
	res, err := Dir(context.Background(), Options{Root: dir, Entropy: true, Context: 3})
	if err != nil {
		t.Fatal(err)
	}
	return res, dir
}

// The fixture is the contract: exactly these findings, no more, no fewer.
func TestFixtureFindings(t *testing.T) {
	res, _ := scanFixture(t)
	var got []string
	for _, f := range res.Findings {
		got = append(got, f.File+"|"+f.RuleID)
	}
	sort.Strings(got)
	want := append([]string(nil), fixture.Expected...)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings mismatch\n got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// No raw secret may appear anywhere in a finding, including the code context.
func TestNoSecretLeaks(t *testing.T) {
	res, _ := scanFixture(t)
	out, _ := json.Marshal(res.Findings)
	// Every fake secret in the fixture is 20+ random chars; any such run that
	// also appears in the fixture files' secret values must not be in output.
	long := regexp.MustCompile(`[A-Za-z0-9+/_-]{20,}`)
	secrets := map[string]bool{}
	for rel, content := range fixture.Files() {
		if rel == "src/safe.ts" || rel == "package-lock.json" {
			continue
		}
		for _, s := range long.FindAllString(content, -1) {
			// Keep random-looking values only; skip names like NEXT_PUBLIC_SUPABASE_URL.
			if strings.ContainsAny(s, "0123456789") && strings.ToUpper(s) != s && strings.ToLower(s) != s {
				secrets[s] = true
			}
		}
	}
	for s := range secrets {
		if strings.Contains(string(out), s) {
			t.Errorf("report contains raw value %q", s)
		}
	}
}

func TestContextIsRedactedAndMarked(t *testing.T) {
	res, _ := scanFixture(t)
	for _, f := range res.Findings {
		if f.RuleID != "stripe-live-key" {
			continue
		}
		hits := 0
		for _, c := range f.Context {
			if c.Hit {
				hits++
				if c.Number != f.Line || !strings.Contains(c.Text, "sk_l****") {
					t.Errorf("hit line wrong: %+v", c)
				}
			}
		}
		if hits != 1 || len(f.Context) < 3 {
			t.Errorf("want 1 hit line in >=3 context lines, got %+v", f.Context)
		}
		return
	}
	t.Fatal("stripe finding missing")
}

func TestKeyguardIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	if err := fixture.Write(dir); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, pathpolicy.IgnoreFile), []byte("keys/\nconfig/aws.js\n"), 0o644)
	res, err := Dir(context.Background(), Options{Root: dir, Entropy: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if strings.HasPrefix(f.File, "keys/") || f.File == "config/aws.js" {
			t.Errorf("ignored path still reported: %s", f.File)
		}
	}
}

func TestSkipsBinaryAndVendorDirs(t *testing.T) {
	dir := t.TempDir()
	key := "sk_" + "live_" + strings.Repeat("aB3xY7kQ", 3)
	os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0o755)
	os.WriteFile(filepath.Join(dir, "node_modules", "pkg", "index.js"), []byte(`"`+key+`"`), 0o644)
	os.WriteFile(filepath.Join(dir, "blob.bin"), append([]byte{0, 1, 2}, []byte(key)...), 0o644)
	res, err := Dir(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("want no findings, got %+v", res.Findings)
	}
}

func BenchmarkScanFixture(b *testing.B) {
	dir := b.TempDir()
	fixture.Write(dir)
	for i := 0; i < b.N; i++ {
		Dir(context.Background(), Options{Root: dir, Entropy: true, Context: 3})
	}
}

// Security review repro: a PEM key embedded as a JS string. Only the BEGIN
// line matches a rule, but the body lines must never appear as context.
func TestPEMBodyInStringNotLeaked(t *testing.T) {
	body := []string{"MIIEpAIBAAKCAQEA7x9Qk2LmZ", "Rt5vB8nW3sY6hJ1cF4gD0aK7", "Pq2Xm9Lz3Vb6Nw1Ks8Jd5Hf0Gt"}
	src := "const key =\n  \"-----BEGIN RSA " + "PRIVATE KEY-----\\n\" +\n"
	for _, b := range body {
		src += "  \"" + b + "\\n\" +\n"
	}
	src += "  \"-----END RSA " + "PRIVATE KEY-----\";\n"
	fs := Content(newDetector(t), "key.js", []byte(src), 5, false)
	out, _ := json.Marshal(fs)
	for _, b := range body {
		if strings.Contains(string(out), b[:12]) {
			t.Errorf("key body %q leaked into context", b[:12])
		}
	}
}

// Security review repro: one generated line with thousands of random strings
// used to take over a minute (quadratic context redaction).
func TestManyHitsBounded(t *testing.T) {
	var b strings.Builder
	g := rand.New(rand.NewSource(1))
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for i := 0; i < 2000; i++ {
		b.WriteString(`"`)
		for j := 0; j < 32; j++ {
			b.WriteByte(alnum[g.Intn(len(alnum))])
		}
		b.WriteString(`",`)
	}
	start := time.Now()
	fs := Content(newDetector(t), "gen.js", []byte(b.String()), 3, false)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
	if len(fs) > maxFindingsPerFile+1 {
		t.Errorf("%d findings, want capped", len(fs))
	}
}

// A clean result must not hide what wasn't checked: unreadable and oversize
// paths are reported, deliberate skips (node_modules, images) are not.
func TestSkippedPathsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read everything; permission test is meaningless")
	}
	dir := t.TempDir()
	write := func(rel, s string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("ok.js", "console.log(1)\n")
	write("locked/inner.js", "x\n")
	write("secret.js", "x\n")
	write("big.js", strings.Repeat("a", 2048))
	write("node_modules/pkg/i.js", "x\n")
	write("logo.png", "x")
	for _, p := range []string{"locked", "secret.js"} {
		os.Chmod(filepath.Join(dir, p), 0)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(dir, "locked"), 0o755) }) // so TempDir can be removed

	res, err := Dir(context.Background(), Options{Root: dir, MaxFileSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range res.Skipped {
		got[s.Path] = s.Reason
	}
	want := map[string]string{"locked": "unreadable", "secret.js": "unreadable", "big.js": "too-large"}
	if len(got) != len(want) {
		t.Fatalf("skipped = %v, want %v", got, want)
	}
	for p, r := range want {
		if got[p] != r {
			t.Errorf("%s: reason %q, want %q", p, got[p], r)
		}
	}
	if res.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1 (ok.js)", res.FilesScanned)
	}
}

func TestUnreadableRootIsAnError(t *testing.T) {
	if _, err := Dir(context.Background(), Options{Root: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("want error when the root itself can't be read")
	}
}
