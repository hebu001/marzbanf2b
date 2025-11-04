# marzbanf2b
marzban fail2ban iplimit
# marzban-ipl (one-device limiter via Fail2ban)

**Задача:** запретить одновременные подключения по одной подписке в Marzban.  
Скрипт ставит фидер, который читает `access.log` Xray и при втором IP в коротком окне пишет в `/var/log/marzban-ipl.log` строки вида:
YYYY/MM/DD HH:MM:SS [LIMIT_IP] Email = USER || SRC = IP



Fail2ban ловит эти строки и банит IP на короткое время (iptables/nftables).

Установка
```
curl -fsSL https://raw.githubusercontent.com/hebu001/marzbanf2b/main/install-marzban-ipl.sh -o install-marzban-ipl.sh
less install-marzban-ipl.sh
sudo bash install-marzban-ipl.sh
```
##sudo bash install-marzban-ipl.sh
##(для non-interactive режима: задайте переменные окружения и NONINTERACTIVE=1)

Примеры:

```bash
sudo ACCESS_LOG=/var/lib/marzban/access.log \
     OUT_LOG=/var/log/marzban-ipl.log \
     IP_LIMIT=1 WINDOW_SEC=90 \
     BANTIME=120 FINDTIME=32 MAXRETRY=1 \
     FW=iptables NONINTERACTIVE=1 \
     bash install-marzban-ipl.sh
```
Тюнинг
Одновременность (строгость): WINDOW_SEC (60–120 сек обычно достаточно).

Длительность бана: bantime в jail.d/marzban-ipl.conf.

Мгновенный бан по событию: maxretry=1 (или по 2 событиям: maxretry=2).
```
```
Проверка
```
systemctl show -p Environment marzban-ipl
sudo fail2ban-client status marzban-ipl
tail -f /var/log/marzban-ipl.log
```
DELETE
```
bash curl -fsSL https://raw.githubusercontent.com/hebu001/marzbanf2b/main/uninstall-marzban-ipl.sh -o /tmp/uninstall-marzban-ipl.sh
sudo bash /tmp/uninstall-marzban-ipl.sh --purge-logs







