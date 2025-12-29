# Автоматизация сбора и формирования правил Suricata из внешних источников

```bash
devopsuser@ubuntu-jammy:~/suricata-ioc$ suricata-update list-sources | head -30
29/12/2025 -- 10:18:20 - <Warning> -- Source index does not exist, will use bundled one.
29/12/2025 -- 10:18:20 - <Warning> -- Please run suricata-update update-sources.
29/12/2025 -- 10:18:20 - <Info> -- Using data-directory /var/lib/suricata.
29/12/2025 -- 10:18:20 - <Info> -- Using /usr/share/suricata/rules for Suricata provided rules.
29/12/2025 -- 10:18:20 - <Info> -- Found Suricata version 8.0.2 at /usr/bin/suricata.
29/12/2025 -- 10:18:20 - <Warning> -- Source index does not exist, will use bundled one.
29/12/2025 -- 10:18:20 - <Warning> -- Please run suricata-update update-sources.
Name: abuse.ch/feodotracker
  Vendor: Abuse.ch
  Summary: Abuse.ch Feodo Tracker Botnet C2 IP ruleset
  License: CC0-1.0
Name: abuse.ch/sslbl-blacklist
  Vendor: Abuse.ch
  Summary: Abuse.ch SSL Blacklist
  License: CC0-1.0
  Replaces: sslbl/ssl-fp-blacklist
Name: abuse.ch/sslbl-c2
  Vendor: Abuse.ch
  Summary: Abuse.ch Suricata Botnet C2 IP Ruleset
  License: CC0-1.0
Name: abuse.ch/sslbl-ja3
  Vendor: Abuse.ch
  Summary: Abuse.ch Suricata JA3 Fingerprint Ruleset
  License: CC0-1.0
  Replaces: sslbl/ja3-fingerprints
Name: abuse.ch/urlhaus
  Vendor: abuse.ch
  Summary: Abuse.ch URLhaus Suricata Rules
  License: CC0-1.0
Name: aleksibovellan/nmap
  Vendor: aleksibovellan
  Summary: Suricata IDS/IPS Detection Rules Against NMAP Scans
devopsuser@ubuntu-jammy:~/suricata-ioc$ sudo suricata-update list-enabled-sources
29/12/2025 -- 10:18:30 - <Info> -- Using data-directory /var/lib/suricata.
29/12/2025 -- 10:18:30 - <Info> -- Using Suricata configuration /etc/suricata/suricata.yaml
29/12/2025 -- 10:18:30 - <Info> -- Using /usr/share/suricata/rules for Suricata provided rules.
29/12/2025 -- 10:18:30 - <Info> -- Found Suricata version 8.0.2 at /usr/bin/suricata.
Enabled sources:
  - ptresearch/attackdetection
  - et/open
```

Проверим работоспособность:

```bash
devopsuser@ubuntu-jammy:~/suricata-ioc$ sudo systemctl status suricata --no-pager
● suricata.service - Suricata IDS/IPS/NSM/FW daemon
     Loaded: loaded (/lib/systemd/system/suricata.service; enabled; vendor preset: enabled)
    Drop-In: /etc/systemd/system/suricata.service.d
             └─override.conf
     Active: active (running) since Mon 2025-12-29 10:19:17 UTC; 3s ago
       Docs: man:suricata(8)
             man:suricatasc(8)
             https://suricata.io/documentation/
    Process: 44968 ExecStartPre=/bin/rm -f /run/suricata.pid (code=exited, status=0/SUCCESS)
   Main PID: 44969 (Suricata-Main)
      Tasks: 1 (limit: 7059)
     Memory: 208.0M
        CPU: 3.436s
     CGroup: /system.slice/suricata.service
             └─44969 /usr/bin/suricata -c /etc/suricata/suricata.yaml -q 1 --pidfile /run/suricata.pid

Dec 29 10:19:17 ubuntu-jammy systemd[1]: Starting Suricata IDS/IPS/NSM/FW daemon...
Dec 29 10:19:17 ubuntu-jammy systemd[1]: Started Suricata IDS/IPS/NSM/FW daemon.
```

Создадим файлы для пайплайна:

Makefile

```bash
devopsuser@ubuntu-jammy:~/suricata-ioc$ cat Makefile 
.PHONY: all fetch generate test deploy clean

all: fetch generate test deploy

fetch:
        @echo "[*] Stage 1: Fetching external feeds..."
        @./fetch_feeds.sh

generate:
        @echo "[*] Stage 2: Generating custom_ioc.rules..."
        @sudo python3 generate_custom_ioc_rules.py

test:
        @echo "[*] Stage 3: Testing Suricata configuration..."
        @sudo suricata -T -c /etc/suricata/suricata.yaml

deploy:
        @echo "[*] Stage 4: Reloading Suricata..."
        @sudo systemctl reload suricata || sudo systemctl restart suricata
        @echo "[+] Pipeline completed successfully!"
        @echo "[*] Checking status..."
        @sudo systemctl status suricata --no-pager | head -n 10

clean:
        rm -rf feeds/
```
Создадим fetch_feeds.sh

```bash
cat << 'EOF' > ~/suricata-ioc/fetch_feeds.sh
#!/usr/bin/env bash
set -euo pipefail

FEEDS_DIR="$(dirname "$0")/feeds"
mkdir -p "$FEEDS_DIR"

# Добавляем User-Agent, чтобы abuse.ch не блокировал нас
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

echo "[*] Downloading Feodo Tracker (Botnets)..."
curl -A "$UA" -sS "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" -o "${FEEDS_DIR}/feodo_ips.txt"

echo "[*] Downloading URLhaus (Malware URLs)..."
curl -A "$UA" -sS "https://urlhaus.abuse.ch/downloads/text_ips/" -o "${FEEDS_DIR}/urlhaus_ips.txt"

echo "[*] Downloading Antifilter (RKN Blacklist)..."
curl -A "$UA" -sS "https://antifilter.download/list/allyouneed.lst" -o "${FEEDS_DIR}/antifilter_ips.txt"

echo "[*] Generating Public Services Blocklist..."
echo "8.8.8.8" > "${FEEDS_DIR}/public_services.txt"
echo "1.1.1.1" >> "${FEEDS_DIR}/public_services.txt"

echo "[*] Done. Feeds saved to: ${FEEDS_DIR}"
ls -lh "${FEEDS_DIR}"
EOF
chmod +x ~/suricata-ioc/fetch_feeds.sh
```

Создадим generate_custom_ioc_rules.py

```bash
cat << 'EOF' > ~/suricata-ioc/generate_custom_ioc_rules.py
#!/usr/bin/env python3
import sys
from pathlib import Path
from datetime import datetime

# Конфигурация источников
SOURCES = {
    "feodo": {
        "file": "feodo_ips.txt",
        "base_sid": 9000000,
        "msg_prefix": "[IPS] Feodo Tracker C&C",
        "classtype": "trojan-activity"
    },
    "urlhaus": {
        "file": "urlhaus_ips.txt",
        "base_sid": 9100000,
        "msg_prefix": "[IPS] URLhaus Malicious IP",
        "classtype": "trojan-activity"
    },
    "antifilter": {
        "file": "antifilter_ips.txt",
        "base_sid": 9200000,
        "msg_prefix": "[IPS] RKN Banned Resource",
        "classtype": "policy-violation"
    },
    "public_services": {
        "file": "public_services.txt",
        "base_sid": 9300000,
        "msg_prefix": "[IPS] Blocked Public Service",
        "classtype": "policy-violation"
    }
}

def load_ips(path: Path):
    ips = []
    if not path.exists():
        print(f"[!] WARNING: File {path} not found, skipping...")
        return ips
    
    with path.open(errors='ignore') as f:
        for line in f:
            line = line.strip()
            # Пропускаем комментарии и пустые строки
            if not line or line.startswith("#") or line.startswith("<"): 
                continue
            
            # Берем первое поле (если CSV)
            candidate = line.split(',')[0] if ',' in line else line.split()[0]
            
            # Валидация: разрешаем цифры, точки и слэш (для CIDR)
            # Убираем все допустимые символы и проверяем, не осталось ли мусора
            clean_check = candidate.replace('.', '').replace('/', '')
            
            if clean_check.isdigit() and '.' in candidate:
                 ips.append(candidate)
    return ips

def generate_drop_rules(source_name, config, ips):
    rules = []
    sid = config["base_sid"]
    max_rules = 3000 # Ограничим, чтобы не перегружать лабу
    
    for ip in ips[:max_rules]:
        # Для CIDR и IP синтаксис одинаковый: drop ip <net> ...
        rule = (
            f"drop ip {ip} any -> any any "
            f"(msg:\"{config['msg_prefix']} {ip}\"; "
            f"classtype:{config['classtype']}; "
            f"sid:{sid}; rev:1;)\n"
        )
        rules.append(rule)
        sid += 1
    return rules

def main():
    feeds_dir = Path(__file__).parent / "feeds"
    out_file = Path("/etc/suricata/rules/custom_ioc.rules")
    all_rules = []
    
    print("[*] Starting IoC rules generation...\n")
    
    for source_name, config in SOURCES.items():
        source_file = feeds_dir / config["file"]
        ips = load_ips(source_file)
        
        if not ips:
            print(f" [!] {source_name}: No IPs loaded (Check file content!)")
            continue
            
        rules = generate_drop_rules(source_name, config, ips)
        all_rules.extend(rules)
        print(f" [+] {source_name}: Generated {len(rules)} rules")

    if not all_rules:
        print("[!] No rules generated.")
        sys.exit(1)

    try:
        with out_file.open("w") as f:
            f.write(f"# Auto-generated IoC rules {datetime.now()}\n")
            for rule in all_rules:
                f.write(rule)
        print(f"\n[+] Successfully wrote {len(all_rules)} rules to {out_file}")
    except PermissionError:
        print(f"\n[!] ERROR: Permission denied writing to {out_file}. Run with sudo.")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF
```

Выполним скрипт

```bash
cd ~/suricata-ioc
devopsuser@ubuntu-jammy:~/suricata-ioc$ make all
[*] Stage 1: Fetching external feeds...
[*] Downloading Feodo Tracker (Botnets)...
[*] Downloading URLhaus (Malware URLs)...
[*] Downloading Antifilter (RKN Blacklist)...
[*] Generating Public Services Blocklist...
[*] Done. Feeds saved to: ./feeds
total 224K
-rw-rw-r-- 1 devopsuser devopsuser 210K Dec 29 08:14 antifilter_ips.txt
-rw-rw-r-- 1 devopsuser devopsuser  504 Dec 29 08:14 feodo_ips.txt
-rw-rw-r-- 1 devopsuser devopsuser   16 Dec 29 08:14 public_services.txt
-rw-rw-r-- 1 devopsuser devopsuser  263 Dec 29 08:14 urlhaus_ips.txt
[*] Stage 2: Generating custom_ioc.rules...
[*] Starting IoC rules generation (Safe Mode)...

 [+] antifilter: Generated 3000 rules
 [+] public_services: Generated 2 rules

[+] Successfully wrote 3002 rules to /etc/suricata/rules/custom_ioc.rules
[*] Stage 3: Testing Suricata configuration...
[*] Stage 4: Reloading Suricata...
[+] Pipeline completed successfully!
[*] Checking status...
● suricata.service - Suricata IDS/IPS/NSM/FW daemon
     Loaded: loaded (/lib/systemd/system/suricata.service; enabled; vendor preset: enabled)
    Drop-In: /etc/systemd/system/suricata.service.d
             └─override.conf
     Active: active (running) since Mon 2025-12-29 07:32:33 UTC; 42min ago
       Docs: man:suricata(8)
             man:suricatasc(8)
             https://suricata.io/documentation/
    Process: 52529 ExecStartPre=/bin/rm -f /run/suricata.pid (code=exited, status=0/SUCCESS)
    Process: 52824 ExecReload=/bin/kill -USR2 $MAINPID (code=exited, status=0/SUCCESS)
```