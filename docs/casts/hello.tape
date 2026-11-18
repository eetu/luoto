# From a folder to an agent at work in a sandbox, and its change back in the folder and run.
# The folder is a clone of luoto without the splash of `luoto setup` (setup.sh), and
# Claude, answering from canned.py, writes that change as this checkout has it.
# `just casts` records it. The waits of builds are skipped, never what they print.

Output docs/casts/hello.gif

Set Shell "fish"
Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1200
Set Height 840
Set Padding 20
Set TypingSpeed 30ms

Hide
Type "source docs/casts/setup.fish" Enter
Wait+Screen@600s /demo ❯/
# The env builds luoto's tests once it is up, so Claude's run of them builds only its change.
Type "set -x LUOTO_CAST_WARM 'mkdir -p frontend/dist && cargo test -q -p luoto --no-run'" Enter
Type "cd luoto && clear" Enter
Sleep 500ms
Show
Sleep 1s

Type "luoto init --agent claude"
Sleep 500ms
Enter
Wait+Screen@60s /Create it\?/
Sleep 2500ms
Enter
# Its first seconds show; the rest of the wait and the installs are skipped.
Sleep 2500ms
Hide
Wait+Screen@900s /luoto ui\s+~\/demo\/luoto ❯/
Show
Sleep 1500ms

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
Type@6ms "add a splash to `luoto setup`: the logo's island as half-block pixel art (palm, orange arc, waves), the sun rising right of the island while its dim reflection sinks in the sea. Animate it once (~1.6 s) while setup detects the host, then leave the still frame. Plain under NO_COLOR, ASCII without UTF-8, nothing when piped, 80 columns. End a first setup with: Next: run `luoto init` inside a project folder."
Sleep 1s
Enter
# The wait of its test run is skipped.
Wait+Screen@120s /Its tests\./
Sleep 1500ms
Hide
# Claude's summary line ("Worked for 1s · done") picks a verb at random.
Wait+Screen@600s /for [0-9ms ]+s · done/
Show
Sleep 2500ms
Type "/exit"
Sleep 500ms
Enter
Wait+Screen@60s /Resume this session/
Sleep 800ms
Type "exit"
Sleep 300ms
Enter
Sleep 1500ms

Type "luoto pull"
Sleep 500ms
Enter
Wait+Screen@60s /\[y\/N\]/
Sleep 1500ms
Type "y"
Sleep 300ms
Enter
Wait+Screen@60s /wrote 4 file/
Sleep 1500ms

# The pulled code is built, and the setup about to run gets a config folder that names no
# runtime, which makes it a first one (first-setup.sh).
Hide
Type "set -x LUOTO_HOME (bash $casts/first-setup.sh); and clear" Enter
Wait+Screen@600s /^~\/demo\/luoto ❯\s*$/
Show

Type "cargo run -q -p luoto -- setup --runtime container --yes"
Sleep 500ms
Enter
Wait+Screen@120s /Next: run/
Sleep 4500ms
