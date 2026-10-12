package scan

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/finding"
	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/gitcmd"
	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/ignore"
	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/rules"
)

// envExposure checks whether each dotenv file is protected from being committed.
// It asks git itself (ls-files, check-ignore) rather than re-implementing its
// ignore rules; outside a repo it falls back to reading .gitignore.
func envExposure(ctx context.Context, root string, envFiles []string) ([]finding.Finding, error) {
	if len(envFiles) == 0 {
		return nil, nil
	}
	git := func(args ...string) bool { return gitcmd.Command(ctx, root, args...).Run() == nil }

	inRepo := git("rev-parse", "--is-inside-work-tree")
	var gi *ignore.Matcher
	if !inRepo {
		gi, _ = ignore.Load(filepath.Join(root, ".gitignore"))
	}
	var out []finding.Finding
	for _, f := range envFiles {
		var fd finding.Finding
		switch {
		case inRepo && git("ls-files", "--error-unmatch", "--", f):
			fd = rules.MustLookup("env-file-committed").Finding(finding.SourceConfig)
			fd.Fix = strings.ReplaceAll(fd.Fix, "{file}", f)
		case inRepo && !git("check-ignore", "-q", "--", f):
			fd = rules.MustLookup("env-file-not-ignored").Finding(finding.SourceConfig)
		case !inRepo && !gi.Match(f, false):
			// Same rule, but less certain (no repo yet), so softer wording.
			fd = rules.MustLookup("env-file-not-ignored").Finding(finding.SourceConfig)
			fd.Severity = finding.Medium
			fd.Description = "Environment file is not covered by .gitignore (not a git repo yet)"
			fd.Fix = "Add `.env*` and `!.env.example` to .gitignore before running `git init`/`git add`."
		default:
			continue
		}
		fd.File = f
		out = append(out, fd)
	}
	// A cancelled context makes every git call fail, which would read as
	// "not ignored". Report the cancellation instead of wrong findings.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
