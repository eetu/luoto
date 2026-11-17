# A virtual workspace with two repos and Claude, opened in a terminal workspace in the env.
# `just casts` records it; Claude answers from canned.py, so it plays the same every time.
# Each step stays on screen under the next, as in a real terminal.

Output docs/casts/virtual-workspace.gif

Set Shell "fish"
Set Theme "Catppuccin Mocha"
Set FontSize 15
Set Width 1280
Set Height 760
Set Padding 18
Set TypingSpeed 35ms

Hide
Type "source docs/casts/setup.fish" Enter
Sleep 2s
Show

Type "luoto init --virtual --name platform --repo ./api --repo ./app --agent claude --no-up"
Sleep 400ms
Enter
Wait+Screen@60s /Create it\?/
Sleep 2s
Enter
Wait+Screen@60s /created env/
Sleep 3s

Type "luoto up -e platform"
Sleep 400ms
Enter
# The minutes of a first `up` are skipped: the recording resumes at its summary.
Hide
Wait+Screen@900s /is up/
Sleep 3s
Show
Sleep 4s

Type "luoto open -e platform --with herdr"
Sleep 400ms
Enter
Wait+Screen@120s /spaces/
Sleep 2s

# The API runs in the env; it has no health check yet.
Type "python3 api/main.py &"
Sleep 400ms
Enter
Sleep 1s
Type "curl -s localhost:8000/health"
Sleep 400ms
Enter
Wait+Screen@20s /not found/
Sleep 2s

Type "claude --permission-mode acceptEdits 'add a health check to the api'"
Sleep 400ms
Enter
# Claude's summary line ("Worked for 1s · done") picks a verb at random.
Wait+Screen@120s /for [0-9]+s · done/
Sleep 4s
Type "/exit"
Sleep 400ms
Enter
Sleep 2s

Type "curl -s localhost:8000/health"
Sleep 400ms
Enter
Sleep 4s
