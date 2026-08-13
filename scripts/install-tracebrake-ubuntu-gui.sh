#!/usr/bin/env bash
# Install TraceBrake's self-contained Ubuntu agent and Avalonia GUI.
# Run this script from the root of the supplied binary bundle.

set -Eeuo pipefail

readonly PRODUCT_NAME="TraceBrake"
readonly EXPECTED_VERSION="0.1.0-ubuntu-alpha1"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PAYLOAD_DIR="${SCRIPT_DIR}/payload"

ENABLE_AUTOSTART=true
START_SERVICE=true
OPEN_GUI=true
ENABLE_LINGER=false
ASSUME_YES=false

usage() {
  cat <<'EOF'
Install TraceBrake for Ubuntu/Linux x86-64.

Usage:
  ./install.sh [options]

Options:
  --yes             Do not pause for confirmation.
  --no-autostart    Do not start the desktop/tray application at login.
  --no-start        Install the user service without starting it now.
  --no-open         Do not open the GUI after installation.
  --enable-linger   Keep the monitor running after logout and start it at boot.
                    This runs: sudo loginctl enable-linger "$USER"
  -h, --help        Show this help.

No .NET SDK, Node.js or npm installation is required. The supplied executables
are self-contained. The monitor runs as the current unprivileged user.
EOF
}

log() {
  printf '\n\033[1;34m==>\033[0m %s\n' "$*"
}

warn() {
  printf '\n\033[1;33mwarning:\033[0m %s\n' "$*" >&2
}

die() {
  printf '\n\033[1;31merror:\033[0m %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --yes) ASSUME_YES=true ;;
    --no-autostart) ENABLE_AUTOSTART=false ;;
    --no-start) START_SERVICE=false ;;
    --no-open) OPEN_GUI=false ;;
    --enable-linger) ENABLE_LINGER=true ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (run with --help)" ;;
  esac
  shift
done

[[ $EUID -ne 0 ]] || die \
  "run this installer as the desktop user, not root"

[[ -r /etc/os-release ]] || die "cannot identify this operating system"
# shellcheck disable=SC1091
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" && " ${ID_LIKE:-} " != *" ubuntu "* ]]; then
  die "this alpha bundle supports Ubuntu only (detected: ${PRETTY_NAME:-unknown})"
fi

case "$(uname -m)" in
  x86_64|amd64) ;;
  *) die "this bundle is linux-x64; detected architecture: $(uname -m)" ;;
esac

for payload in foreman-agent foreman-desktop foreman.png; do
  [[ -f "${PAYLOAD_DIR}/${payload}" ]] || die \
    "missing payload/${payload}; keep install.sh beside the supplied payload directory"
done

if [[ -f "${SCRIPT_DIR}/SHA256SUMS" ]]; then
  log "Verifying bundle checksums"
  (cd "$SCRIPT_DIR" && sha256sum --check SHA256SUMS)
else
  warn "SHA256SUMS is missing; refusing an unverifiable bundle"
  exit 1
fi

payload_version="$("${PAYLOAD_DIR}/foreman-agent" version)"
[[ "$payload_version" == *"${EXPECTED_VERSION}"* ]] || die \
  "the payload reports an unexpected version: ${payload_version}"

cat <<EOF

${PRODUCT_NAME} Ubuntu installer
  Version: ${EXPECTED_VERSION}
  Target:  ${PRETTY_NAME:-Ubuntu} x86-64
  User:    ${USER}

This is an unsigned alpha. It installs a per-user background monitor, an
application-menu launcher and the native Avalonia dashboard/tray interface.
Configuration and audit state remain owned by ${USER}; nothing runs as root.
EOF

if ! $ASSUME_YES; then
  [[ -t 0 ]] || die "confirmation requires a terminal; rerun with --yes after reviewing the script"
  read -r -p "Continue? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || exit 0
fi

readonly INSTALL_DIR="$HOME/.local/lib/foreman"
readonly BIN_DIR="$HOME/.local/bin"
readonly UNIT_DIR="$HOME/.config/systemd/user"
readonly APPLICATIONS_DIR="$HOME/.local/share/applications"
readonly AUTOSTART_DIR="$HOME/.config/autostart"
readonly ICON_DIR="$HOME/.local/share/icons/hicolor/128x128/apps"
readonly CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/foreman"
readonly STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/foreman"
readonly DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/foreman"

# The service, payload and state paths keep their shipped Foreman identifiers for in-place upgrades. Public
# command aliases and desktop labels use TraceBrake.

log "Installing the monitor and desktop application"
install -d -m 700 "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" "$DATA_DIR"
install -d -m 755 "$BIN_DIR" "$UNIT_DIR" "$APPLICATIONS_DIR" "$ICON_DIR"
install -m 755 "$PAYLOAD_DIR/foreman-agent" "$INSTALL_DIR/foreman-agent"
install -m 755 "$PAYLOAD_DIR/foreman-desktop" "$INSTALL_DIR/foreman-desktop"
install -m 644 "$PAYLOAD_DIR/foreman.png" "$ICON_DIR/foreman-agent-safety.png"
ln -sfn "$INSTALL_DIR/foreman-agent" "$BIN_DIR/foreman-agent"
ln -sfn "$INSTALL_DIR/foreman-desktop" "$BIN_DIR/foreman-desktop"
ln -sfn "$INSTALL_DIR/foreman-agent" "$BIN_DIR/tracebrake"
ln -sfn "$INSTALL_DIR/foreman-desktop" "$BIN_DIR/tracebrake-desktop"

cat > "$UNIT_DIR/foreman-agent.service" <<'EOF'
[Unit]
Description=TraceBrake agent safety monitor
Documentation=https://github.com/aXL333/Foreman
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/lib/foreman/foreman-agent run
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.config/foreman %h/.local/state/foreman %h/.local/share/foreman
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true

[Install]
WantedBy=default.target
EOF
chmod 644 "$UNIT_DIR/foreman-agent.service"

cat > "$APPLICATIONS_DIR/foreman-desktop.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=TraceBrake
Comment=Safety oversight for local AI coding agents
Exec=$INSTALL_DIR/foreman-desktop
Icon=$ICON_DIR/foreman-agent-safety.png
Terminal=false
Categories=System;Security;
Keywords=AI;agent;safety;MCP;monitor;
StartupNotify=true
EOF
chmod 644 "$APPLICATIONS_DIR/foreman-desktop.desktop"

if $ENABLE_AUTOSTART; then
  install -d -m 755 "$AUTOSTART_DIR"
  cat > "$AUTOSTART_DIR/foreman-desktop.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=TraceBrake
Comment=Start the TraceBrake safety tray and dashboard
Exec=$INSTALL_DIR/foreman-desktop --background
Icon=$ICON_DIR/foreman-agent-safety.png
Terminal=false
X-GNOME-Autostart-enabled=true
NoDisplay=true
EOF
  chmod 644 "$AUTOSTART_DIR/foreman-desktop.desktop"
else
  rm -f -- "$AUTOSTART_DIR/foreman-desktop.desktop"
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$APPLICATIONS_DIR" >/dev/null 2>&1 || true
fi

# SSH shells often omit the user-bus environment even when the desktop's
# systemd user manager is running. Recover the conventional local paths.
if [[ -z "${XDG_RUNTIME_DIR:-}" && -d "/run/user/$(id -u)" ]]; then
  export XDG_RUNTIME_DIR="/run/user/$(id -u)"
fi
if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" && -S "${XDG_RUNTIME_DIR:-/nonexistent}/bus" ]]; then
  export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
fi

if $ENABLE_LINGER; then
  command -v loginctl >/dev/null || die "loginctl is required for --enable-linger"
  command -v sudo >/dev/null || die "sudo is required for --enable-linger"
  log "Enabling the opted-in persistent user service"
  sudo loginctl enable-linger "$USER"
fi

service_started=false
if command -v systemctl >/dev/null 2>&1 && systemctl --user daemon-reload 2>/dev/null; then
  systemctl --user enable foreman-agent.service
  if $START_SERVICE; then
    log "Starting the TraceBrake monitor"
    systemctl --user restart foreman-agent.service
    service_started=true
  fi
else
  warn "no systemd user session is reachable; the service is installed but was not started"
  warn "log into the Ubuntu desktop, then run: systemctl --user enable --now foreman-agent.service"
fi

if $service_started; then
  sleep 2
  log "Running TraceBrake Doctor"
  "$INSTALL_DIR/foreman-agent" doctor
fi

if $OPEN_GUI; then
  if [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]]; then
    log "Opening the native TraceBrake dashboard"
    systemctl --user stop foreman-desktop-session.service 2>/dev/null || true
    pkill -x foreman-desktop 2>/dev/null || true
    if command -v systemd-run >/dev/null 2>&1 && \
       systemd-run --user --unit=foreman-desktop-session --collect \
         "$INSTALL_DIR/foreman-desktop" >/dev/null 2>&1; then
      :
    else
      nohup "$INSTALL_DIR/foreman-desktop" >/dev/null 2>&1 < /dev/null &
    fi
  else
    warn "no graphical session is attached to this shell; open 'TraceBrake' from the Ubuntu application menu"
  fi
fi

cat <<EOF

Installation complete.

GUI:       $BIN_DIR/tracebrake-desktop
Monitor:   $BIN_DIR/tracebrake
Health:    $BIN_DIR/tracebrake doctor
Status:    $BIN_DIR/tracebrake status
Events:    $BIN_DIR/tracebrake events 25
Logs:      journalctl --user -u foreman-agent -f
Connect:   $BIN_DIR/tracebrake connect codex

If ~/.local/bin is not on PATH, open a new terminal or invoke the absolute
paths shown above. The GUI is also installed in Ubuntu's application menu.
EOF
