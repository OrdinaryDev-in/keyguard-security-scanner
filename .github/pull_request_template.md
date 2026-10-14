## What and why

<!-- What does this change, and why? Link the issue: "Fixes #123". -->

## Checklist

- [ ] `make vet` and `make race` pass
- [ ] `make self-scan` passes, and no commit on this branch contains a literal secret (CI scans history)
- [ ] New or changed rules have a fixture sample, a look-alike that must not match, and an `Expected` entry
- [ ] No output path can print a secret unredacted
- [ ] README / `keyguard rules` output updated if user-facing behavior changed
