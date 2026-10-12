# Renders docs/assets/demo.gif. Run from the repo root: make demo-gif
# Only uses the generated demo app — all keys in it are fake.

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 1500
Set Height 620
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

# --- setup (not recorded) ---------------------------------------------------
Hide
Type "export PS1='$ ' PATH=$PWD/bin:$PATH GIT_CONFIG_GLOBAL=/dev/null GIT_AUTHOR_NAME=Dev GIT_AUTHOR_EMAIL=dev@example.com GIT_COMMITTER_NAME=Dev GIT_COMMITTER_EMAIL=dev@example.com"
Enter
Type "rm -rf /tmp/kg-demo && go run ./cmd/mkfixture /tmp/kg-demo/my-app >/dev/null && mkdir /tmp/kg-demo/history-app"
Enter
# history-app: a Stripe key is committed, then deleted in the next commit
Type "cd /tmp/kg-demo/history-app && git init -q && echo 'export {}' > app.js && git add . && git commit -qm init"
Enter
Type `printf 'const stripe = Stripe("sk_%s");\n' "live_$(LC_ALL=C tr -dc A-Za-z0-9 </dev/urandom | head -c 24)" > pay.js && git add . && git commit -qm 'add payments'`
Enter
Type "rm pay.js && git commit -qam 'remove key' && cd /tmp/kg-demo/my-app && clear"
Enter
Sleep 1s
Show

# --- 1. scan a project ------------------------------------------------------
Type "keyguard scan ."
Sleep 400ms
Enter
Sleep 9s

# --- 2. a "deleted" key is still in git history ------------------------------
Type "clear"
Enter
Type "cd ../history-app && git log --oneline"
Enter
Sleep 1.5s
Type "ls"
Enter
Sleep 1s
Type "keyguard scan . --history"
Sleep 400ms
Enter
Sleep 4s

# --- 3. HTML report ---------------------------------------------------------
Type "keyguard scan ../my-app --format html -o report.html"
Sleep 400ms
Enter
Sleep 4s
