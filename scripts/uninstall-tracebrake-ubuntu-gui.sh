#!/usr/bin/env bash
# Remove the Ubuntu TraceBrake binaries and launchers while preserving evidence.

set -Eeuo pipefail

[[ $EUID -ne 0 ]] || {
  printf 'Run this uninstaller as the desktop user, not root.\n' >&2
  exit 1
}

if [[ -z "${XDG_RUNTIME_DIR:-}" && -d "/run/user/$(id -u)" ]]; then
  export XDG_RUNTIME_DIR="/run/user/$(id -u)"
fi
if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" && -S "${XDG_RUNTIME_DIR:-/nonexistent}/bus" ]]; then
  export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now foreman-agent.service 2>/dev/null || true
  systemctl --user stop foreman-desktop-session.service 2>/dev/null || true
fi
pkill -x foreman-desktop 2>/dev/null || true

for target in \
  "$HOME/.config/systemd/user/foreman-agent.service" \
  "$HOME/.local/bin/foreman-agent" \
  "$HOME/.local/bin/foreman-desktop" \
  "$HOME/.local/bin/tracebrake" \
  "$HOME/.local/bin/tracebrake-desktop" \
  "$HOME/.local/lib/foreman/foreman-agent" \
  "$HOME/.local/lib/foreman/foreman-desktop" \
  "$HOME/.local/share/applications/foreman-desktop.desktop" \
  "$HOME/.config/autostart/foreman-desktop.desktop" \
  "$HOME/.local/share/icons/hicolor/128x128/apps/foreman-agent-safety.png"
do
  if [[ -e "$target" || -L "$target" ]]; then
    rm -f -- "$target"
  fi
done

rmdir "$HOME/.local/lib/foreman" 2>/dev/null || true
systemctl --user daemon-reload 2>/dev/null || true

cat <<'EOF'
TraceBrake was removed.

Configuration and audit evidence were deliberately preserved in the legacy-compatible paths:
  ~/.config/foreman
  ~/.local/state/foreman
  ~/.local/share/foreman

Review and back up those directories before removing them manually.
If login lingering was enabled, it was not silently disabled; inspect it with:
  loginctl show-user "$USER" -p Linger
EOF
