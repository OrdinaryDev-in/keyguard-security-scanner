# 09 · Getting my security tool security-reviewed

**Concept:** a security tool processes hostile input by definition, so it needs threat-modelling like anything else.

After v1 worked, I ran an automated security review against the scanner itself. It built the binary and **attacked it**. Three findings were confirmed by running exploits, not just by reading code.

| # | Finding | Severity | Fix |
|---|---|---|---|
| 1 | A private key embedded as a JS string (`"MIIE...\n" +`) leaked its body into the report's code context. My earlier fix only caught *bare* base64 lines. | HIGH | Track `BEGIN … PRIVATE KEY` → `END` across lines and never show anything in between. Also mask any 24+ char letter-and-digit token in context lines, even if no rule matched. |
| 2 | `--history` **hung forever** on a commit with a 9 MB minified file: `bufio.Scanner` gave up on the long line, nothing drained the pipe, and `cmd.Wait()` waited for a git process blocked on writing. | MEDIUM | Read with `bufio.Reader.ReadLine` and truncate lines over 64 KB; drain the pipe on any error before `Wait`. |
| 3 | One generated line with 2,000 random strings took **67 seconds**: every finding re-redacted its 7 context lines, and each redaction re-ran every rule. | MEDIUM | Redact each line once per file (cached), cap 100 findings per file and 20 entropy tokens per line. Now ~0.1s. |
| 4 | **Code execution when scanning an untrusted repo.** `git log -p` runs `diff.<x>.textconv` programs from the repo's own `.git/config`, and `--no-ext-diff` doesn't stop it. | MEDIUM | `--no-textconv` and `-c core.fsmonitor=false` on every git call. I verified it: without the flag, git ran the planted command. |
| 5 | SARIF fingerprints were derived from a fast, unsalted hash of the secret, so human-chosen passwords could be brute-forced offline from a CI artifact. | LOW–MED | Fingerprint uses only data already in the report (rule, file, redacted value, position). |
| 6 | A file named `\x1b[2K\r...` could rewrite lines in your terminal or CI log, e.g. fake a "No secrets found". | LOW | Strip control characters from file and author names in text output. |

Every fix has a regression test reproducing the attack (`TestPEMBodyInStringNotLeaked`, `TestEachLineTruncatesLongLines`, `TestManyHitsBounded`, `TestTextconvNotExecuted`, `TestTextStripsControlChars`).

## What I took from it

- **Your tool's input is the attacker's input.** File names, file contents, git config and commit authors are all controlled by whoever wrote the repo.
- **`os/exec` has a deadlock trap.** Never call `Wait` before you've finished reading `StdoutPipe`, including on the error path.
- **Look for O(n²) as well as wrong answers.** A security gate that never finishes is a gate that someone will disable.
- **"Redacted" must hold for every byte of output**, not just the field called `secret`.

## Your notes
<!-- Which of these would you have caught yourself? -->
