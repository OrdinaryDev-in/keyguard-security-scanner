package detect

import (
	"strings"
	"testing"
)

// File-restricted rules only fire on their files, and LineIn with an unknown
// file ("") behaves like the old file-agnostic Line.
func TestFileSpecificRules(t *testing.T) {
	d := newDetector(t)
	pw := "Zq8" + "vLm2Rt7"
	tests := []struct {
		rel, line, want string
	}{
		{"src/main/resources/application.properties", "spring.datasource.password=" + pw, "config-file-secret"},
		{"src/app.js", "password=" + pw, ""}, // JS: could be a variable, not a literal
		{"", "spring.datasource.password=" + pw, ""},
		{"Dockerfile", "ENV API_TOKEN=" + pw, "dockerfile-secret"},
		{"Dockerfile.prod", "ARG DB_PASSWORD=" + pw, "dockerfile-secret"},
		{"Dockerfile", "ARG NPM_TOKEN", ""},
		{"Dockerfile", "ENV DB_PASSWORD=$DB_PASSWORD", ""},
		{"src/environments/environment.prod.ts", "  clientSecret: '" + pw + "',", "angular-environment-secret"},
		{"src/environments/environment.ts", "  firebase: { apiKey: 'public-firebase-key' },", "!angular-environment-secret"},
		{"src/app/config.ts", "  adminKey: '" + pw + "',", ""}, // not an environment file
		{"docker-compose.yml", "      POSTGRES_PASSWORD: " + pw, "config-file-secret"},
		{"application.yml", "    password: ${DB_PASSWORD}", ""},
		{"application.yml", "  secretName: my-tls-cert", ""},
		{"application.yml", "  password-encoder: bcrypt", ""},
	}
	for _, tt := range tests {
		hits := d.LineIn(tt.rel, tt.line)
		var got []string
		for _, h := range hits {
			got = append(got, h.Rule.ID)
		}
		if not, ok := strings.CutPrefix(tt.want, "!"); ok { // "!rule": only that rule must not fire
			if strings.Contains(strings.Join(got, ","), not) {
				t.Errorf("LineIn(%q, %q) = %v, must not include %s", tt.rel, tt.line, got, not)
			}
			continue
		}
		if (tt.want == "" && len(got) != 0) || (tt.want != "" && !strings.Contains(strings.Join(got, ","), tt.want)) {
			t.Errorf("LineIn(%q, %q) = %v, want %q", tt.rel, tt.line, got, tt.want)
		}
	}
}

func TestRedactLineInMasksConfigValues(t *testing.T) {
	d := newDetector(t)
	pw := "Zq8" + "vLm2Rt7"
	line := "spring.datasource.password=" + pw
	if got := d.RedactLineIn("application.properties", line); strings.Contains(got, pw) {
		t.Errorf("not masked: %s", got)
	}
}
