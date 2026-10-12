package scan

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/fixture"
)

// Unquoted config values (application.properties, docker-compose, Dockerfile)
// are short and have no quotes, so the generic context safety net (24+ char
// tokens) doesn't cover them. They must still never appear in any output.
func TestStackSecretsNotLeaked(t *testing.T) {
	res, _ := scanFixture(t)
	out, _ := json.Marshal(res.Findings)
	value := regexp.MustCompile(`(?m)(?:password=|PASSWORD: |PASSWORD=|_authToken=)(\S+)$`)
	checked := 0
	for rel, content := range fixture.Files() {
		for _, m := range value.FindAllStringSubmatch(content, -1) {
			v := m[1]
			if strings.HasPrefix(v, "${") {
				continue
			}
			checked++
			if strings.Contains(string(out), v) {
				t.Errorf("%s: raw value %q appears in findings", rel, v)
			}
		}
	}
	if checked < 4 {
		t.Fatalf("only checked %d values; did the fixture change?", checked)
	}
}
