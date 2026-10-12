package pathpolicy

import "testing"

func TestIsEnvFile(t *testing.T) {
	for name, want := range map[string]bool{
		".env": true, ".env.local": true, "apps/web/.env.production": true,
		".env.example": false, ".env.sample": false, "env.ts": false, ".envrc": false, "config.env": false,
	} {
		if got := IsEnvFile(name); got != want {
			t.Errorf("IsEnvFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestSkipPath(t *testing.T) {
	for rel, want := range map[string]bool{
		"node_modules/x/index.js": true, "a/.git/config": true, "package-lock.json": true,
		"web/app.min.js": true, "logo.PNG": true,
		"src/index.js": false, "dist.js": false, "src/build.ts": false,
	} {
		if got := SkipPath(rel); got != want {
			t.Errorf("SkipPath(%q) = %v, want %v", rel, got, want)
		}
	}
}
