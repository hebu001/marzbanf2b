#!/usr/bin/env bash
# uninstall-marzban-ipl.sh
# Remove Marzban "one-device" limiter (feeder + fail2ban bits)

set -euo pipefail

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
info() { printf "  - %s\n" "$*"; }
warn() { printf "\033[33m[WARN]\033[0m %s\n" "$*\n"; }
err()  { printf "\033[31m[ERROR]\033[0m %s\n" "$*\n"; }
ok()   { printf "\033[32m[OK]\033[0m %s\n" "$*\n"; }

require_root() {
  if [[ $EUID -ne 0 ]]; then err "Run as root"; exit 1; fi
}

PURGE_LOGS=0
NONINTERACTIVE=0

for arg in "$@"; do
  case "$arg" in
    --purge-logs) PURGE_LOGS=1 ;;
    --yes|-y) NONINTERACTIVE=1 ;;
    --help|-h)
      cat <<'HLP'
Usage: sudo bash uninstall-marzban-ipl.sh [--purge-logs] [--yes]

  --purge-logs  remove /var/log/marzban-ipl.log and /var/log/marzban-ipl-banned.log
  --yes         do not ask for confirmation
HLP
      exit 0
      ;;
    *)
      err "Unknown option: $arg"
      exit 1
      ;;
  esac
done

require_root
bold "Uninstall: Marzban IPL (feeder + Fail2ban rules)"

if [[ "$NONINTERACTIVE" -ne 1 ]]; then
  read -r -p "Proceed to remove service, feeder and Fail2ban configs? [y/N] " ans
  [[ "${ans:-N}" =~ ^[Yy]$ ]] || { warn "Cancelled"; exit 0; }
fi

# Stop & disable systemd service
if systemctl list-unit-files | grep -q '^marzban-ipl.service'; then
  info "Stopping service marzban-ipl..."
  systemctl disable --now marzban-ipl || true
  ok "Service disabled"
fi

# Try to cleanup iptables chain (if present)
if command -v iptables >/dev/null 2>&1; then
  if iptables -nL 2>/dev/null | grep -q '^Chain f2b-marzban-ipl'; then
    info "Cleaning iptables chain f2b-marzban-ipl..."
    # Try detach from INPUT
    iptables -D INPUT -p tcp -j f2b-marzban-ipl 2>/dev/null || true
    # Flush and delete chain
    iptables -F f2b-marzban-ipl 2>/dev/null || true
    iptables -X f2b-marzban-ipl 2>/dev/null || true
    ok "iptables chain removed (if existed)"
  fi
fi

# Remove files
FILES=(
  /etc/systemd/system/marzban-ipl.service
  /usr/local/bin/marzban-ipl-feeder.py
  /etc/fail2ban/filter.d/marzban-ipl.conf
  /etc/fail2ban/jail.d/marzban-ipl.conf
  /etc/fail2ban/action.d/marzban-ipl.conf
)

for f in "${FILES[@]}"; do
  if [[ -e "$f" ]]; then
    info "Removing $f"
    rm -f "$f"
  fi
done

# Purge logs (optional)
if [[ "$PURGE_LOGS" -eq 1 ]]; then
  for lf in /var/log/marzban-ipl.log /var/log/marzban-ipl-banned.log; do
    if [[ -e "$lf" ]]; then
      info "Removing log $lf"
      rm -f "$lf"
    fi
  done
fi

# Reload systemd & restart fail2ban
info "Reloading systemd daemons..."
systemctl daemon-reload || true

if systemctl is-active --quiet fail2ban; then
  info "Restarting fail2ban..."
  systemctl restart fail2ban || true
fi

ok "Uninstall completed"

echo
bold "Post-checks"
echo "  * systemctl status marzban-ipl (should be not-found)"
echo "  * fail2ban-client status (jail marzban-ipl should be absent)"
