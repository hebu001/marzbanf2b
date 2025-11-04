# marzbanf2b
marzban fail2ban iplimit
# marzban-ipl (one-device limiter via Fail2ban)

**Задача:** запретить одновременные подключения по одной подписке в Marzban.  
Скрипт ставит фидер, который читает `access.log` Xray и при втором IP в коротком окне пишет в `/var/log/marzban-ipl.log` строки вида:
YYYY/MM/DD HH:MM:SS [LIMIT_IP] Email = USER || SRC = IP

bash
Копировать код
Fail2ban ловит эти строки и банит IP на короткое время (iptables/nftables).

Установка
```bash
sudo bash install-marzban-ipl.sh
(для non-interactive режима: задайте переменные окружения и NONINTERACTIVE=1)

Примеры:

bash
Копировать код
sudo ACCESS_LOG=/var/lib/marzban/access.log \
     OUT_LOG=/var/log/marzban-ipl.log \
     IP_LIMIT=1 WINDOW_SEC=90 \
     BANTIME=120 FINDTIME=32 MAXRETRY=1 \
     FW=iptables NONINTERACTIVE=1 \
     bash install-marzban-ipl.sh
Тюнинг
Одновременность (строгость): WINDOW_SEC (60–120 сек обычно достаточно).

Длительность бана: bantime в jail.d/marzban-ipl.conf.

Мгновенный бан по событию: maxretry=1 (или по 2 событиям: maxretry=2).

Проверка
bash
Копировать код
systemctl show -p Environment marzban-ipl
sudo fail2ban-client status marzban-ipl
tail -f /var/log/marzban-ipl.log
Удаление
bash
Копировать код
sudo systemctl disable --now marzban-ipl
sudo rm -f /etc/systemd/system/marzban-ipl.service /usr/local/bin/marzban-ipl-feeder.py
sudo rm -f /etc/fail2ban/filter.d/marzban-ipl.conf /etc/fail2ban/jail.d/marzban-ipl.conf /etc/fail2ban/action.d/marzban-ipl.conf
sudo systemctl daemon-reload
sudo systemctl restart fail2ban
perl
Копировать код

если хочешь, добавлю в репо ещё `uninstall.sh` и GitHub Actions (линт/шельчек), но для старта достаточно одного файла выше.
::contentReference[oaicite:0]{index=0}






