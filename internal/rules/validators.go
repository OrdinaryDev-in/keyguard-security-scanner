package rules

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/entropy"
)

// A validator spec in rules.json is "name" or "name:arg". Each registered
// factory turns the arg into a check; it rejects bad args at load time.
type validatorFactory func(arg string) (func(secret string) bool, error)

var validators = map[string]validatorFactory{
	"not-placeholder": func(arg string) (func(string) bool, error) {
		if arg != "" {
			return nil, fmt.Errorf("takes no argument")
		}
		return notPlaceholder, nil
	},
	"min-entropy": func(arg string) (func(string) bool, error) {
		threshold, err := strconv.ParseFloat(arg, 64)
		if err != nil || threshold <= 0 {
			return nil, fmt.Errorf("want a positive number, got %q", arg)
		}
		return func(s string) bool { return entropy.IsRandom(s, threshold) }, nil
	},
	"jwt-role": func(arg string) (func(string) bool, error) {
		roles, err := roleList(arg)
		if err != nil {
			return nil, err
		}
		return func(s string) bool { return slices.Contains(roles, jwtRole(s)) }, nil
	},
	"jwt-role-not": func(arg string) (func(string) bool, error) {
		roles, err := roleList(arg)
		if err != nil {
			return nil, err
		}
		return func(s string) bool { return !slices.Contains(roles, jwtRole(s)) }, nil
	},
}

func roleList(arg string) ([]string, error) {
	if arg == "" {
		return nil, fmt.Errorf("want a comma-separated role list")
	}
	return strings.Split(arg, ","), nil
}

// buildValidators turns specs into one func that passes only if all do.
func buildValidators(specs []string) (func(string) bool, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	var fns []func(string) bool
	for _, spec := range specs {
		name, arg, _ := strings.Cut(spec, ":")
		factory, ok := validators[name]
		if !ok {
			return nil, fmt.Errorf("unknown validator %q", name)
		}
		fn, err := factory(arg)
		if err != nil {
			return nil, fmt.Errorf("validator %s: %w", name, err)
		}
		fns = append(fns, fn)
	}
	return func(s string) bool {
		for _, fn := range fns {
			if !fn(s) {
				return false
			}
		}
		return true
	}, nil
}

// jwtRole decodes the (unsigned, readable by anyone) JWT payload and returns its "role" claim.
func jwtRole(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var claims struct {
		Role string `json:"role"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	return claims.Role
}

var placeholders = []string{
	"your", "example", "xxxx", "changeme", "change-me", "placeholder", "dummy", "sample",
	"fake", "redacted", "<", ">", "${", "{{", "process.env", "os.environ", "****", "...", "password",
}

func notPlaceholder(s string) bool {
	l := strings.ToLower(s)
	for _, p := range placeholders {
		if strings.Contains(l, p) {
			return false
		}
	}
	return true
}
