#!/usr/bin/env bash
set -euo pipefail

echo "=== Marzban IPL (3x-ui style) installer ==="

# --- 0) sanity checks ---
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root"; exit 1
fi

# --- 1) defaults & prompts ---
detect_access_log() {
  # находим вероятные логи xray/marzban
  local candidates=(/var/lib/marzban/access.log /var/log/xray/access.log)
  for p in "${candidates[@]}"; do
    [[ -f "$p" ]] && { echo "$p"; return; }
  done
  # если не нашли — показываем дефолт (создастся после включения логов в xray)
  echo "/var/lib/marzban/access.log"
}

ACCESS_LOG_DEFAULT="$(detect_access_log)"
OUT_LOG_DEFAULT="/var/log/marzban-ipl.log"
IP_LIMIT_DEFAULT="1"
WINDOW_SEC_DEFAULT="90"
BANTIME_DEFAULT="1m"
FINDTIME_DEFAULT="32"
MAXRETRY_DEFAULT="1"

# автодетект фаервола
if command -v nft >/dev/null 2>&1; then
  FW_DEFAULT="nftables"
elif command -v iptables >/dev/null 2>&1; then
  FW_DEFAULT="iptables"
else
  FW_DEFAULT="iptables"
fi

read -rp "Path to ACCESS_LOG [${ACCESS_LOG_DEFAULT}]: " ACCESS_LOG || true
ACCESS_LOG="${ACCESS_LOG:-$ACCESS_LOG_DEFAULT}"

read -rp "Path to feeder OUT_LOG (Fail2ban reads this) [${OUT_LOG_DEFAULT}]: " OUT_LOG || true
OUT_LOG="${OUT_LOG:-$OUT_LOG_DEFAULT}"

read -rp "IP_LIMIT (unique IPs per user within window) [${IP_LIMIT_DEFAULT}]: " IP_LIMIT || true
IP_LIMIT="${IP_LIMIT:-$IP_LIMIT_DEFAULT}"

read -rp "WINDOW_SEC (concurrency window, seconds) [${WINDOW_SEC_DEFAULT}]: " WINDOW_SEC || true
WINDOW_SEC="${WINDOW_SEC:-$WINDOW_SEC_DEFAULT}"

read -rp "Fail2ban bantime (e.g. 1m, 120, 5m) [${BANTIME_DEFAULT}]: " BANTIME || true
BANTIME="${BANTIME:-$BANTIME_DEFAULT}"

read -rp "Fail2ban findtime (seconds) [${FINDTIME_DEFAULT}]: " FINDTIME || true
FINDTIME="${FINDTIME:-$FINDTIME_DEFAULT}"

read -rp "Fail2ban maxretry [${MAXRETRY_DEFAULT}]: " MAXRETRY || true
MAXRETRY="${MAXRETRY:-$MAXRETRY_DEFAULT}"

read -rp "Firewall backend (iptables/nftables) [${FW_DEFAULT}]: " FW || true
FW="${FW:-$FW_DEFAULT}"
FW_LOWER="$(echo "$FW" | tr '[:upper:]' '[:lower:]')"
if [[ "$FW_LOWER" != "iptables" && "$FW_LOWER" != "nftables" ]]; then
  echo "Unknown firewall backend '$FW'. Use iptables or nftables."; exit 1
fi

echo
echo "== Summary =="
echo "ACCESS_LOG  = $ACCESS_LOG"
echo "OUT_LOG     = $OUT_LOG"
echo "IP_LIMIT    = $IP_LIMIT"
echo "WINDOW_SEC  = $WINDOW_SEC"
echo "bantime     = $BANTIME"
echo "findtime    = $FINDTIME"
echo "maxretry    = $MAXRETRY"
echo "backend     = $FW_LOWER"
echo

# --- 2) deps ---
echo ">> Installing dependencies (python3, fail2ban)..."
if command -v apt >/dev/null 2>&1; then
  apt update -y
  apt install -y python3 fail2ban
else
  echo "Please install python3 and fail2ban with your package manager."; 
fi

# --- 3) feeder script ---
echo ">> Writing feeder /usr/local/bin/marzban-ipl-feeder.py"
install -d -m 0755 /usr/local/bin
cat >/usr/local/bin/marzban-ipl-feeder.py <<'PY'
#!/usr/bin/env python3
import re, time, os
from collections import defaultdict, deque
from datetime import datetime, timedelta

ACCESS_LOG = os.environ.get("ACCESS_LOG", "/var/lib/marzban/access.log")
OUT_LOG    = os.environ.get("OUT_LOG", "/var/log/marzban-ipl.log")

IP_LIMIT   = int(os.environ.get("IP_LIMIT", "1"))
WINDOW_SEC = int(os.environ.get("WINDOW_SEC", "90"))

LINE_RE = re.compile(
    r'^\s*(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+from\s+(?:tcp:)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):\d+\s+accepted\b.*?\bemail:\s*(?P<user>\S+)',
    re.IGNORECASE
)

user_hits = defaultdict(deque)  # user -> deque of (ip, ts)

def prune_old(now):
    cutoff = now - timedelta(seconds=WINDOW_SEC)
    for dq in user_hits.values():
        while dq and dq[0][1] < cutoff:
            dq.popleft()

def write_limit_event(ip, user):
    line = f"{datetime.utcnow().strftime('%Y/%m/%d %H:%M:%S')} [LIMIT_IP] Email = {user} || SRC = {ip}"
    os.makedirs(os.path.dirname(OUT_LOG), exist_ok=True)
    with open(OUT_LOG, "a", buffering=1) as f:
        f.write(line + "\n")

def follow(path):
    f = None
    inode = None
    while True:
        try:
            st = os.stat(path)
            if f is None or st.st_ino != inode:
                if f:
                    f.close()
                f = open(path, "r")
                inode = st.st_ino
                f.seek(0, os.SEEK_END)  # read new lines only
            line = f.readline()
            if line:
                yield line.rstrip("\n")
            else:
                time.sleep(0.5)
        except FileNotFoundError:
            time.sleep(1)

def main():
    os.makedirs(os.path.dirname(OUT_LOG), exist_ok=True)
    with open(OUT_LOG, "a", buffering=1) as f:
        f.write(f"{datetime.utcnow().strftime('%Y/%m/%d %H:%M:%S')} [START] marzban-ipl ip_limit={IP_LIMIT} window={WINDOW_SEC}s\n")

    for line in follow(ACCESS_LOG):
        m = LINE_RE.search(line)
        if not m:
            continue
        ip   = m.group("ip")
        user = m.group("user")
        now  = datetime.utcnow()

        prune_old(now)
        # set of IPs within window
        ips_now = {ip_ for (ip_, t_) in user_hits[user] if (now - t_).total_seconds() <= WINDOW_SEC}

        if ip not in ips_now:
            user_hits[user].append((ip, now))
            ips_now.add(ip)
            if len(ips_now) > IP_LIMIT:
                write_limit_event(ip, user)

if __name__ == "__main__":
    main()
PY
chmod +x /usr/local/bin/marzban-ipl-feeder.py

# --- 4) systemd unit ---
echo ">> Writing systemd unit /etc/systemd/system/marzban-ipl.service"
cat >/etc/systemd/system/marzban-ipl.service <<EOF
[Unit]
Description=Marzban IPL feeder (3x-ui style) for Fail2ban
After=network.target

[Service]
Type=simple
User=root
Environment=ACCESS_LOG=${ACCESS_LOG}
Environment=OUT_LOG=${OUT_LOG}
Environment=IP_LIMIT=${IP_LIMIT}
Environment=WINDOW_SEC=${WINDOW_SEC}
ExecStart=/usr/bin/python3 /usr/local/bin/marzban-ipl-feeder.py
Restart=always
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now marzban-ipl

# --- 5) fail2ban filter ---
echo ">> Writing Fail2ban filter /etc/fail2ban/filter.d/marzban-ipl.conf"
cat >/etc/fail2ban/filter.d/marzban-ipl.conf <<'EOF'
[Definition]
# Example:
# 2025/11/04 02:20:00 [LIMIT_IP] Email = NAME || SRC = 203.0.113.55
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
failregex   = ^\s*<DATETIME>\s+\[LIMIT_IP\]\s*Email\s*=\s*(?P<F-USER>\S+)\s*\|\|\s*SRC\s*=\s*<ADDR>\s*$
ignoreregex =
EOF

# --- 6) fail2ban jail ---
echo ">> Writing Fail2ban jail /etc/fail2ban/jail.d/marzban-ipl.conf"
if [[ "$FW_LOWER" == "iptables" ]]; then
  # собственный action, чтобы писать BAN/UNBAN лог
  echo ">> Using iptables and custom action with BAN/UNBAN log"
  cat >/etc/fail2ban/action.d/marzban-ipl.conf <<'EOF'
[INCLUDES]
before = iptables-allports.conf

[Definition]
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -j f2b-<name>

actionstop  = <iptables> -D <chain> -p <protocol> -j f2b-<name>
              <actionflush>
              <iptables> -X f2b-<name>

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

actionban   = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
              echo "$(date +'%Y/%m/%d %H:%M:%S')   BAN   [Email] = <F-USER>  [IP] = <ip>  banned for <bantime> seconds." >> /var/log/marzban-ipl-banned.log

actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>
              echo "$(date +'%Y/%m/%d %H:%M:%S')   UNBAN [Email] = <F-USER>  [IP] = <ip>  unbanned." >> /var/log/marzban-ipl-banned.log

[Init]
name     = marzban-ipl
protocol = tcp
chain    = INPUT
EOF

  cat >/etc/fail2ban/jail.d/marzban-ipl.conf <<EOF
[marzban-ipl]
enabled  = true
backend  = auto
filter   = marzban-ipl
action   = marzban-ipl
logpath  = ${OUT_LOG}
maxretry = ${MAXRETRY}
findtime = ${FINDTIME}
bantime  = ${BANTIME}
EOF

else
  # nftables — используем встроенный action без кастомного логирования
  echo ">> Using nftables (built-in action). BAN/UNBAN file will not be written by action."
  cat >/etc/fail2ban/jail.d/marzban-ipl.conf <<EOF
[marzban-ipl]
enabled  = true
backend  = auto
filter   = marzban-ipl
action   = nftables-allports[name=marzban-ipl]
logpath  = ${OUT_LOG}
maxretry = ${MAXRETRY}
findtime = ${FINDTIME}
bantime  = ${BANTIME}
EOF
fi

# --- 7) restart fail2ban ---
echo ">> Restarting fail2ban..."
systemctl restart fail2ban

# --- 8) show status & tips ---
echo
echo "=== Installation complete ==="
systemctl --no-pager status marzban-ipl | sed -n '1,12p' || true
echo
fail2ban-client status || true
echo
echo "Feeder env:"
systemctl show -p Environment marzban-ipl

cat <<'HINT'

--- Quick test ---
1) Make two lines for the same email with different IPs into ACCESS_LOG:
   LOG=<the ACCESS_LOG you chose>
   echo "2025/11/04 02:30:01 from tcp:198.51.100.10:12345 accepted udp:1.1.1.1:53 [VLESS TCP REALITY >> DIRECT] email: testuser" | tee -a "$LOG"
   echo "2025/11/04 02:30:10 from 203.0.113.55:54321 accepted tcp:www.google.com:443 [VLESS TCP REALITY >> DIRECT] email: testuser" | tee -a "$LOG"

2) Check:
   tail -n 10 /var/log/marzban-ipl.log                    # should see [LIMIT_IP] Email = testuser || SRC = 203.0.113.55
   fail2ban-client status marzban-ipl                      # should list 203.0.113.55 as banned

--- Useful ---
- Change window (concurrency strictness):
  systemctl edit marzban-ipl
  [Service]
  Environment=WINDOW_SEC=60
  systemctl daemon-reload && systemctl restart marzban-ipl

- Change ban time:
  edit /etc/fail2ban/jail.d/marzban-ipl.conf (bantime) && systemctl restart fail2ban

- Logs:
  tail -f /var/log/marzban-ipl.log
  tail -f /var/log/marzban-ipl-banned.log   (only with iptables custom action)
  journalctl -u marzban-ipl -n 100 --no-pager
HINT
