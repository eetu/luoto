#!/bin/sh
# Entrypoint of every luoto dev container (runs as root, from the read-only tools volume).
# Makes an arbitrary image usable behind the gate: CA trust, resolver, user + sudo, proxy
# config for tools that ignore the environment, git over HTTPS, agent briefing. Each step is
# best-effort so unusual images still start; `sandbox selftest` verifies the result.
set -u

T=/opt/luoto
CA="$T/env/ca.crt"
BUNDLE=/etc/luoto/ca-bundle.pem
USER_UID="${LUOTO_UID:-1000}"
USER_NAME="${LUOTO_USER:-dev}"
PROXY="${HTTPS_PROXY:-http://gate:3128}"

log() { echo "luoto-init: $*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }
# passwd field N of the user with USER_UID (busybox images have no getent)
pw() { awk -F: -v u="$USER_UID" -v f="$1" '$3==u{print $f; exit}' /etc/passwd 2>/dev/null; }

mkdir -p /etc/luoto

# --- tun link: an env without a network card reaches the gate over a socket the host joins --
if [ "${LUOTO_NET:-}" = tun ]; then
  LUOTO_GATE_IP="${LUOTO_GATE_IP:-169.254.1.1}"
  NET_SOCK="${LUOTO_NET_SOCKET:-/run/luoto-net/net.sock}"
  rm -f "$NET_SOCK"
  mkdir -p /run/luoto
  "$T/bin/sandbox" net --socket "$NET_SOCK" </dev/null >/run/luoto/net.log 2>&1 &
  i=0
  while [ ! -S "$NET_SOCK" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
  if [ ! -S "$NET_SOCK" ]; then
    log "warning: the tun link did not start; this env has no network"
    head -c 4096 /run/luoto/net.log >&2
  fi
fi

# --- resolver: the gate is the only DNS server -------------------------------------------
if [ -n "${LUOTO_GATE_IP:-}" ]; then
  if ! grep -q "nameserver ${LUOTO_GATE_IP}\$" /etc/resolv.conf 2>/dev/null; then
    printf 'nameserver %s\noptions ndots:0\n' "$LUOTO_GATE_IP" >/etc/resolv.conf 2>/dev/null ||
      log "warning: /etc/resolv.conf is read-only and does not point at the gate"
  fi
  grep -q "[[:space:]]gate\$" /etc/hosts 2>/dev/null ||
    printf '%s gate\n' "$LUOTO_GATE_IP" >>/etc/hosts 2>/dev/null || true
fi

# --- CA: system store + one combined bundle every tool points at -------------------------
if [ -f "$CA" ]; then
  if [ -d /usr/local/share/ca-certificates ] && have update-ca-certificates; then
    cp "$CA" /usr/local/share/ca-certificates/luoto-env.crt && update-ca-certificates >/dev/null 2>&1
  elif [ -d /etc/pki/ca-trust/source/anchors ] && have update-ca-trust; then
    cp "$CA" /etc/pki/ca-trust/source/anchors/luoto-env.crt && update-ca-trust extract >/dev/null 2>&1
  fi
  SYSTEM=""
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    [ -s "$f" ] && SYSTEM="$f" && break
  done
  if [ -n "$SYSTEM" ] && grep -q "$(sed -n 2p "$CA")" "$SYSTEM" 2>/dev/null; then
    cp "$SYSTEM" "$BUNDLE"
  else
    # No system store (or it could not be updated): Mozilla roots shipped with luoto + env CA.
    cat "${SYSTEM:-$T/ca-bundle.base.pem}" "$CA" >"$BUNDLE" 2>/dev/null ||
      cat "$T/ca-bundle.base.pem" "$CA" >"$BUNDLE"
  fi
  chmod 644 "$BUNDLE"
else
  log "warning: no env CA at $CA; HTTPS through the gate will fail"
fi

# --- user: uid 1000 with passwordless sudo ------------------------------------------------
EXISTING="$(pw 1)"
if [ -n "$EXISTING" ]; then
  USER_NAME="$EXISTING"
else
  SHELL_BIN=/bin/sh
  [ -x /bin/bash ] && SHELL_BIN=/bin/bash
  if have useradd; then
    useradd -u "$USER_UID" -U -m -d "/home/$USER_NAME" -s "$SHELL_BIN" "$USER_NAME" 2>/dev/null ||
      useradd -u "$USER_UID" -m -d "/home/$USER_NAME" -s "$SHELL_BIN" "$USER_NAME"
  elif have adduser; then
    adduser -D -u "$USER_UID" -h "/home/$USER_NAME" -s "$SHELL_BIN" "$USER_NAME"
  else
    log "warning: cannot create user $USER_NAME"
  fi
fi
HOME_DIR="$(pw 6)"
HOME_DIR="${HOME_DIR:-/home/$USER_NAME}"
mkdir -p "$HOME_DIR"
# A new volume on a runtime that formats it (Apple's) is root's and holds an empty lost+found.
for d in /workspace "$HOME_DIR"; do
  [ "$(ls -A "$d" 2>/dev/null)" = "lost+found" ] && rmdir "$d/lost+found" 2>/dev/null
done
[ "$(stat -c %u "$HOME_DIR" 2>/dev/null)" = "$USER_UID" ] || chown "$USER_UID:$USER_UID" "$HOME_DIR"
# zsh runs its new-user wizard in a home without zsh files; the image's defaults are enough.
if have zsh; then
  ZFILES=""
  for f in .zshenv .zprofile .zshrc .zlogin; do [ -e "$HOME_DIR/$f" ] && ZFILES=1; done
  if [ -z "$ZFILES" ]; then
    echo '# Your zsh config. Defaults: /etc/zsh/zshrc' >"$HOME_DIR/.zshrc"
    chown "$USER_UID:$USER_UID" "$HOME_DIR/.zshrc"
  fi
fi
if [ -d /workspace ] && [ "$(stat -c %u /workspace 2>/dev/null)" = "0" ] && [ -z "$(ls -A /workspace 2>/dev/null)" ]; then
  chown "$USER_UID:$USER_UID" /workspace
fi
# The proxy and CA variables the gate sets: kept through sudo, written to the profile.
VARS="HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy SSL_CERT_FILE NODE_EXTRA_CA_CERTS REQUESTS_CA_BUNDLE CURL_CA_BUNDLE PIP_CERT CARGO_HTTP_CAINFO GIT_SSL_CAINFO DENO_CERT NODE_USE_ENV_PROXY LUOTO_ENV"
if [ -d /etc/sudoers.d ] || have sudo; then
  mkdir -p /etc/sudoers.d
  cat >/etc/sudoers.d/luoto <<EOF
$USER_NAME ALL=(ALL) NOPASSWD:ALL
Defaults env_keep += "$VARS"
EOF
  chmod 440 /etc/sudoers.d/luoto
fi

# --- proxy for tools that read files instead of the environment ---------------------------
if [ -d /etc/apt/apt.conf.d ]; then
  printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "%s";\n' "$PROXY" "$PROXY" \
    >/etc/apt/apt.conf.d/99luoto-proxy
fi
: >/etc/profile.d/luoto.sh 2>/dev/null && {
  for v in $VARS; do
    eval "val=\${$v:-}"
    [ -n "$val" ] && printf 'export %s=%s\n' "$v" "$val" >>/etc/profile.d/luoto.sh
  done
  [ -f /etc/environment ] && grep -q LUOTO_ENV /etc/environment ||
    sed 's/^export //' /etc/profile.d/luoto.sh >>/etc/environment
  echo '. /etc/luoto-shell.sh' >>/etc/profile.d/luoto.sh
}
# Every shell, login or not: editors' SSH terminals start non-login shells that miss both the
# container's PATH and profile.d. User-level installs (agents, `npm i -g`, pipx) go on PATH;
# the per-run env (agent settings, placeholders, sandbox secrets) lives in memory only.
cat >/etc/luoto-shell.sh <<'EOF'
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) PATH="$HOME/.local/bin:$PATH"; export PATH ;; esac
[ -r /run/luoto/env.sh ] && . /run/luoto/env.sh
EOF
for rc in /etc/bash.bashrc /etc/bashrc /etc/zsh/zshenv /etc/zshenv; do
  [ -f "$rc" ] && ! grep -q /etc/luoto-shell.sh "$rc" && echo '. /etc/luoto-shell.sh' >>"$rc"
done
if [ -d /etc/fish ]; then
  mkdir -p /etc/fish/conf.d
  cat >/etc/fish/conf.d/luoto.fish <<'EOF'
contains -- $HOME/.local/bin $PATH; or set -gx PATH $HOME/.local/bin $PATH
test -r /run/luoto/env.fish; and source /run/luoto/env.fish
EOF
fi

# --- git: remote rewrites, written by luoto at `up` ------------------------------------------
# SSH remotes go to HTTPS unless `[credentials.ssh]` covers their host; Azure DevOps aliases
# and legacy URLs to dev.azure.com. A missing include is ignored until `up` writes it.
if have git; then
  git config --system http.sslCAInfo "$BUNDLE"
  git config --system safe.directory /workspace
  git config --system include.path /run/luoto/gitconfig
fi

# --- ssh: logins signed by the vault's agent, to pinned host keys only ---------------------
if [ -d /etc/ssh ]; then
  mkdir -p /etc/ssh/ssh_config.d /run/luoto/ssh
  chown "$USER_UID" /run/luoto/ssh 2>/dev/null || true
  chmod 700 /run/luoto/ssh
  cat >/etc/ssh/ssh_config.d/luoto.conf <<'EOF'
# Written by luoto: the key stays in the vault, and only pinned host keys are trusted.
Host *
  IdentityAgent /run/luoto/ssh/agent.sock
  GlobalKnownHostsFile /run/luoto/ssh_known_hosts
  UserKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  ForwardAgent no
EOF
  su -s /bin/sh "$USER_NAME" -c "$T/bin/sandbox ssh-agent >/dev/null 2>&1 &" 2>/dev/null || true
fi

# --- helper and agent briefing ------------------------------------------------------------
ln -sf "$T/bin/sandbox" /usr/local/bin/sandbox 2>/dev/null || true
mkdir -p /etc/claude-code
[ -e /etc/claude-code/CLAUDE.md ] || ln -s "$T/AGENTS.md" /etc/claude-code/CLAUDE.md

# --- Chromium/NSS trust (VS Code webviews, Electron tools) --------------------------------
# The db is in the home volume, which outlives renewed CAs: the ones it holds go first.
if have certutil && [ -f "$CA" ]; then
  su -s /bin/sh "$USER_NAME" -c "mkdir -p \"$HOME_DIR/.pki/nssdb\" &&
    (certutil -d sql:$HOME_DIR/.pki/nssdb -L >/dev/null 2>&1 || certutil -d sql:$HOME_DIR/.pki/nssdb -N --empty-password) &&
    for i in 1 2 3; do certutil -d sql:$HOME_DIR/.pki/nssdb -D -n luoto-env 2>/dev/null || break; done &&
    certutil -d sql:$HOME_DIR/.pki/nssdb -A -t C,, -n luoto-env -i $CA" >/dev/null 2>&1 || true
fi

# --- sshd host keys for SSH-capable editors (luoto ssh-proxy runs `sshd -i`) --------------
if have ssh-keygen && [ -d /etc/ssh ]; then
  ssh-keygen -A >/dev/null 2>&1 || true
  mkdir -p /run/sshd
fi

mkdir -p /run/luoto
echo "$USER_NAME" >/run/luoto/user
touch /run/luoto/ready
log "ready (user $USER_NAME, env ${LUOTO_ENV:-?})"
# A runtime that keeps the container's output uncapped (Apple's) gets nothing more: no process
# keeps it open, so root in the sandbox can't write to it through /proc either. Its /dev is the
# VM's, whose consoles the runtime logs uncapped on the host: their nodes go, and the container
# lacks MKNOD to make them again.
if [ "${LUOTO_OUTPUT:-}" = startup ]; then
  rm -f /dev/console /dev/kmsg /dev/hvc[0-9]* /dev/tty[0-9]* /dev/ttyS[0-9]* /dev/ttyAMA[0-9]*
  exec </dev/null >/dev/null 2>&1
fi

trap 'exit 0' TERM INT
while :; do sleep 3600 & wait $!; done
