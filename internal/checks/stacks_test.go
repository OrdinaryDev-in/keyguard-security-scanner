package checks

import "testing"

func ids(rel, line string) []string {
	var out []string
	for _, f := range Line(rel, line, 1, false) {
		out = append(out, f.RuleID)
	}
	return out
}

func TestFirebaseRules(t *testing.T) {
	tests := []struct {
		rel, line, want string // want "" = no finding
	}{
		{"firestore.rules", "allow read, write: if true;", "firebase-rules-public-write"},
		{"firestore.rules", "allow read, write;", "firebase-rules-public-write"},
		{"storage.rules", "allow create: if true;", "firebase-rules-public-write"},
		{"firestore.rules", "allow read: if true;", "firebase-rules-public-read"},
		{"firestore.rules", "allow get, list;", "firebase-rules-public-read"},
		{"firestore.rules", "allow read, write: if request.time < timestamp.date(2026, 1, 1);", "firebase-rules-test-mode"},
		{"firestore.rules", "allow read, write: if request.auth != null;", ""},
		{"firestore.rules", "allow write: if true && isAdmin();", ""},
		{"firestore.rules", "// allow read, write: if true;", ""},
		{"rules.ts", "allow read, write: if true;", ""}, // not a rules file
		{"database.rules.json", `".write": true,`, "firebase-rules-public-write"},
		{"database.rules.json", `".read": "auth != null"`, ""},
	}
	for _, tt := range tests {
		got := ids(tt.rel, tt.line)
		if (tt.want == "" && len(got) != 0) || (tt.want != "" && (len(got) != 1 || got[0] != tt.want)) {
			t.Errorf("%s %q: got %v, want %q", tt.rel, tt.line, got, tt.want)
		}
	}
}

func TestTerraformState(t *testing.T) {
	if got := ids("infra/terraform.tfstate", `  "terraform_version": "1.9.0",`); len(got) != 1 || got[0] != "terraform-state-file" {
		t.Errorf("got %v", got)
	}
	if got := ids("main.tf", `required_version = "1.9.0" # "terraform_version"`); len(got) != 0 {
		t.Errorf(".tf files are fine, got %v", got)
	}
}

func TestMoreFrameworkPrefixes(t *testing.T) {
	for _, line := range []string{`process.env.VUE_APP_DB_PASSWORD`, `import.meta.env.NG_APP_ADMIN_KEY`} {
		if got := ids("src/a.ts", line); len(got) != 1 {
			t.Errorf("%s: got %v", line, got)
		}
	}
}
