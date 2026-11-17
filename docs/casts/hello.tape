# From a plain folder to an agent at work in a sandbox, what the sandbox stopped, and the
# agent's change back in the folder.
# `just casts` records it; Claude answers from canned.py, so it plays the same every time.
# The folder's dev-dependency posts the environment to a host of its own as it builds, as a
# compromised crate would (setup.sh).

Output docs/casts/hello.gif

Set Shell "fish"
Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1200
Set Height 720
Set Padding 20
Set TypingSpeed 30ms

Hide
Type "source docs/casts/setup.fish" Enter
Wait+Screen@300s /demo ❯/
Type "cd pulse && clear" Enter
Sleep 500ms
Show
Sleep 1s

# The CLI's splash screen as it is.
Type "cargo run -q"
Sleep 400ms
Enter
Sleep 1500ms

Type "luoto init --agent claude"
Sleep 500ms
Enter
Wait+Screen@60s /Create it\?/
Sleep 2500ms
Enter
# Its first seconds show; the rest of the wait, and the installs of Rust and Claude, are skipped.
Sleep 2500ms
Hide
Wait+Screen@1800s /is up/
Show
Sleep 2s

# Each scene on a clear screen.
Hide
Type "clear"
Enter
Sleep 500ms
Show

# Inside the env, where Claude runs without its permission prompts.
Type "luoto shell"
Sleep 400ms
Enter
Wait+Screen@60s /workspace main %/
Sleep 600ms
Type "whoami"
Sleep 300ms
Enter
Sleep 1200ms
Type "claude --dangerously-skip-permissions"
Sleep 400ms
Enter
Wait+Screen@120s /bypass permissions on/
Sleep 800ms
Type "give the splash some sparkle: unicorns and lasers. run the tests"
Sleep 500ms
Enter
# Claude's summary line ("Worked for 1s · done") picks a verb at random.
Wait+Screen@300s /for [0-9]+s · done/
Sleep 2s
Type "/exit"
Sleep 500ms
Enter
Wait+Screen@60s /Resume this session/
Sleep 800ms
Type "exit"
Sleep 300ms
Enter
Wait+Screen@60s /the gate denied/
Sleep 3500ms

Type "luoto pull"
Sleep 500ms
Enter
Wait+Screen@60s /\[y\/N\]/
Sleep 1500ms
Type "y"
Sleep 300ms
Enter
Wait+Screen@60s /wrote 1 file/
Sleep 1500ms

Hide
Type "clear"
Enter
Sleep 500ms
Show

# The change, on this machine.
Type "cargo run -q"
Sleep 400ms
Enter
Sleep 5s
