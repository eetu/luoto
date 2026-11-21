# A host the gate denies, allowed for an hour from this machine, reached at once.
# `just casts` records it. The host is real: IANA's time zone database, whose `version` file
# is a few bytes of text.

Output docs/casts/allow.gif

Set Shell "fish"
Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1200
Set Height 540
Set Padding 20
Set TypingSpeed 30ms

# An env of a folder, up before the recording starts.
Hide
Type "source docs/casts/setup.fish" Enter
Wait+Screen@600s /demo ❯/
Type "cd tz && luoto init --yes" Enter
Wait+Screen@900s /is up/
Type "clear" Enter
Sleep 500ms
Show
Sleep 1s

Type "luoto shell -- curl -s https://data.iana.org/time-zones/tzdb/version"
Sleep 500ms
Enter
Wait+Screen@60s /Do not try to work around it/
Sleep 4s

Type "luoto egress --denied"
Sleep 400ms
Enter
Wait+Screen@60s /luoto allow -e tz data.iana.org/
Sleep 3s

Type "luoto allow data.iana.org --for 1h"
Sleep 500ms
Enter
Wait+Screen@60s /allowed data.iana.org/
Sleep 3500ms

# The same fetch, from the shell's history.
Up
Sleep 300ms
Up
Sleep 300ms
Up
Sleep 800ms
Enter
Wait+Screen@60s /\n20[0-9][0-9][a-z]/
Sleep 4s
