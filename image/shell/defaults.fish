# luoto defaults for fish (conf.d; ~/.config/fish/config.fish runs after and wins).
set -g fish_greeting
if status is-interactive; and command -q fzf
    fzf --fish | source
end
if command -q mise
    mise activate fish | source
end
abbr -a ll 'ls -lah'
