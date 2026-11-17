# Sourced, out of sight, at the start of a cast's tape (fish, for its highlighting): the cast's
# folder and canned server (setup.sh), and the `luoto` in bin/ first on the PATH.
set -l here (path dirname (status filename))
bash $here/setup.sh
set -gx PATH (path resolve $here/bin) $PATH
# VHS starts fish without config, so without colours: these are Catppuccin Mocha's, as the tape's
# theme, in 24-bit.
set -g fish_term24bit 1
set -g fish_color_normal cdd6f4
set -g fish_color_command 89b4fa --bold
set -g fish_color_param cdd6f4
set -g fish_color_option f9e2af
set -g fish_color_quote a6e3a1
set -g fish_color_operator f5c2e7
set -g fish_color_end f5c2e7
set -g fish_color_redirection f5c2e7
set -g fish_color_error f38ba8
set -g fish_color_valid_path --underline
set -g fish_color_autosuggestion 6c7086
function fish_prompt
    set_color 6c7086
    printf '%s ' (string replace -r "^$HOME" "~" $PWD)
    set_color --bold cba6f7
    printf '❯ '
    set_color normal
end
cd ~/demo
clear
