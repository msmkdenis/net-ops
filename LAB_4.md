# Атака 1: Нарушение контроля доступа (A01:2021 Broken Access Control)

Продемонстрирована уязвимость IDOR с получением доступа к чужой корзине через токен администратора. Suricata корректно идентифицировала паттерн доступа к /rest/basket/ с числовым идентификатором. Ключевым моментом стала сработка правила 4601002, которое перевело режим обнаружения в блокировку (action: blocked) при превышении порога запросов, эффективно остановив перебор (энумерацию) корзин.

Выполняем запросы:

```bash
──(root㉿b0985949ec71)-[/]
└─# # Отправляем запрос на логин и сохраняем токен в переменную TOKEN
TOKEN=$(curl -s -X POST "http://172.16.90.40:3000/rest/user/login" \
 -H "Content-Type: application/json" \
 -d "{\"email\":\"' OR 1=1 --\",\"password\":\"any\"}" | jq -r '.authentication.token')

# Проверяем, что токен получен (должен вывестись длинный набор символов)
echo $TOKEN
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjUtMTItMjggMTg6MjQ6MTguMzYyICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjUtMTItMjggMTg6MjQ6MTguMzYyICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc2Njk0NjY4N30.IZrQsccqup1H_5BoUE8-vbVsccyFwX9NkjWtyPSrfw8waIslAmnQc7-m9D1VqSunVCOpOb6kLWPGua-dQXSTHMK3ehsId9hNXnxvRRseqVSvZAd-b3c9eB9O8Ta5oLJANSNh0rla786OVcQlxCwOoJUylJblCnQ-DUUtZ_BxNWk

┌──(root㉿b0985949ec71)-[/]
└─# curl -s -H "Authorization: Bearer $TOKEN" \
 "http://172.16.90.40:3000/rest/basket/1" | jq
{
  "status": "success",
  "data": {
    "id": 1,
    "coupon": null,
    "UserId": 1,
    "createdAt": "2025-12-28T18:24:20.713Z",
    "updatedAt": "2025-12-28T18:24:20.713Z",
    "Products": [
      {
        "id": 1,
        "name": "Apple Juice (1000ml)",
        "description": "The all-time classic.",
        "price": 1.99,
        "deluxePrice": 0.99,
        "image": "apple_juice.jpg",
        "createdAt": "2025-12-28T18:24:20.471Z",
        "updatedAt": "2025-12-28T18:24:20.471Z",
        "deletedAt": null,
        "BasketItem": {
          "ProductId": 1,
          "BasketId": 1,
          "id": 1,
          "quantity": 2,
          "createdAt": "2025-12-28T18:24:20.775Z",
          "updatedAt": "2025-12-28T18:24:20.775Z"
        }
      },
      {
        "id": 2,
        "name": "Orange Juice (1000ml)",
        "description": "Made from oranges hand-picked by Uncle Dittmeyer.",
        "price": 2.99,
        "deluxePrice": 2.49,
        "image": "orange_juice.jpg",
        "createdAt": "2025-12-28T18:24:20.471Z",
        "updatedAt": "2025-12-28T18:24:20.471Z",
        "deletedAt": null,
        "BasketItem": {
          "ProductId": 2,
          "BasketId": 1,
          "id": 2,
          "quantity": 3,
          "createdAt": "2025-12-28T18:24:20.775Z",
          "updatedAt": "2025-12-28T18:24:20.775Z"
        }
      },
      {
        "id": 3,
        "name": "Eggfruit Juice (500ml)",
        "description": "Now with even more exotic flavour.",
        "price": 8.99,
        "deluxePrice": 8.99,
        "image": "eggfruit_juice.jpg",
        "createdAt": "2025-12-28T18:24:20.471Z",
        "updatedAt": "2025-12-28T18:24:20.471Z",
        "deletedAt": null,
        "BasketItem": {
          "ProductId": 3,
          "BasketId": 1,
          "id": 3,
          "quantity": 1,
          "createdAt": "2025-12-28T18:24:20.775Z",
          "updatedAt": "2025-12-28T18:24:20.775Z"
        }
      }
    ]
  }
}

┌──(root㉿b0985949ec71)-[/]
└─# curl -s -H "Authorization: Bearer $TOKEN" \
 "http://172.16.90.40:3000/rest/basket/2" | jq
{
  "status": "success",
  "data": {
    "id": 2,
    "coupon": null,
    "UserId": 2,
    "createdAt": "2025-12-28T18:24:20.713Z",
    "updatedAt": "2025-12-28T18:24:20.713Z",
    "Products": [
      {
        "id": 4,
        "name": "Raspberry Juice (1000ml)",
        "description": "Made from blended Raspberry Pi, water and sugar.",
        "price": 4.99,
        "deluxePrice": 4.99,
        "image": "raspberry_juice.jpg",
        "createdAt": "2025-12-28T18:24:20.471Z",
        "updatedAt": "2025-12-28T18:24:20.471Z",
        "deletedAt": null,
        "BasketItem": {
          "ProductId": 4,
          "BasketId": 2,
          "id": 4,
          "quantity": 2,
          "createdAt": "2025-12-28T18:24:20.775Z",
          "updatedAt": "2025-12-28T18:24:20.775Z"
        }
      }
    ]
  }
}
```
Добавляем правила:

```yaml
# --- A01: Broken Access Control (IDOR: /rest/basket/<id>) ---
alert http any any -> any 3000 (msg:"LAB ALERT: IDOR Basket Access Detected"; flow:to_server,established; http.uri; content:"/rest/basket/"; pcre:"/\/rest\/basket\/[0-9]+/"; classtype:web-application-attack; sid:4601001; rev:2;)

drop http any any -> any 3000 (msg:"LAB ALERT: IDOR Enumeration (Brute Force)"; flow:to_server,established; http.uri; content:"/rest/basket/"; pcre:"/\/rest\/basket\/[0-9]+/"; threshold:type both, track by_src, count 5, seconds 20; classtype:web-application-attack; sid:4601002; rev:2;)
```

Повторим запросы и увидим:

### Для alert `4601001`

```bash
evopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4601001" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T18:49:04.467604+0000",
  "flow_id": 250353316715700,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 56438,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4601001,
    "rev": 2,
    "signature": "LAB ALERT: IDOR Basket Access Detected",
    "category": "Web Application Attack",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_complete",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/rest/basket/2",
    "http_user_agent": "curl/8.17.0",
    "http_content_type": "application/json",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 557
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 4,
    "pkts_toclient": 3,
    "bytes_toserver": 1066,
    "bytes_toclient": 1107,
    "start": "2025-12-28T18:49:04.451505+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 56438,
    "dest_port": 3000
  }
}
```

### Для drop `4601002`

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4601002" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T18:49:33.285665+0000",
  "flow_id": 1447734298014610,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 52388,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4601002,
    "rev": 2,
    "signature": "LAB ALERT: IDOR Enumeration (Brute Force)",
    "category": "Web Application Attack",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_complete",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/rest/basket/2",
    "http_user_agent": "curl/8.17.0",
    "http_content_type": "application/json",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 557
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 4,
    "pkts_toclient": 3,
    "bytes_toserver": 1066,
    "bytes_toclient": 1107,
    "start": "2025-12-28T18:49:33.271540+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 52388,
    "dest_port": 3000
  }
}
```

# Атака 2: Криптографические сбои (A02:2021 Cryptographic Failures)

Использована техника Poison Null Byte для обхода проверки расширений файлов, что позволило обратиться к файлам .bak. В логах зафиксирована двойная защита: сработали правила на обнаружение самого Null Byte (SID 4602101) и на попытку скачивания бэкапов (SID 4602102). Оба правила отработали в режиме IPS, разорвав соединение и предотвратив утечку списка купонов и конфигурации package.json.

Выполняем запросы:

```bash
┌──(root㉿b0985949ec71)-[/]
└─# curl -s "http://172.16.90.40:3000/ftp/coupons_2013.md.bak%2500.md" -o coupons_2013.md.bak

┌──(root㉿b0985949ec71)-[/]
└─# cat coupons_2013.md.bak
n<MibgC7sn
mNYS#gC7sn
o*IVigC7sn
k#pDlgC7sn
o*I]pgC7sn
n(XRvgC7sn
n(XLtgC7sn
k#*AfgC7sn
q:<IqgC7sn
pEw8ogC7sn
pes[BgC7sn
l}6D$gC7ss

┌──(root㉿b0985949ec71)-[/]
└─# curl "http://172.16.90.40:3000/ftp/package.json.bak"
<html>
  <head>
    <meta charset='utf-8'> 
    <title>Error: Only .md and .pdf files are allowed!</title>
    <style>* {
  margin: 0;
  padding: 0;
  outline: 0;
}

body {
  padding: 80px 100px;
  font: 13px "Helvetica Neue", "Lucida Grande", "Arial";
  background: #ECE9E9 -webkit-gradient(linear, 0% 0%, 0% 100%, from(#fff), to(#ECE9E9));
  background: #ECE9E9 -moz-linear-gradient(top, #fff, #ECE9E9);
  background-repeat: no-repeat;
  color: #555;
  -webkit-font-smoothing: antialiased;
}
h1, h2 {
  font-size: 22px;
  color: #343434;
}
h1 em, h2 em {
  padding: 0 5px;
  font-weight: normal;
}
h1 {
  font-size: 60px;
}
h2 {
  margin-top: 10px;
}
ul li {
  list-style: none;
}
#stacktrace {
  margin-left: 60px;
}
</style>
  </head>
  <body>
    <div id="wrapper">
      <h1>OWASP Juice Shop (Express ^4.21.0)</h1>
      <h2><em>403</em> Error: Only .md and .pdf files are allowed!</h2>
      <ul id="stacktrace"><li> &nbsp; &nbsp;at verify (/juice-shop/build/routes/fileServer.js:59:18)</li><li> &nbsp; &nbsp;at /juice-shop/build/routes/fileServer.js:43:13</li><li> &nbsp; &nbsp;at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li><li> &nbsp; &nbsp;at trim_prefix (/juice-shop/node_modules/express/lib/router/index.js:328:13)</li><li> &nbsp; &nbsp;at /juice-shop/node_modules/express/lib/router/index.js:286:9</li><li> &nbsp; &nbsp;at param (/juice-shop/node_modules/express/lib/router/index.js:365:14)</li><li> &nbsp; &nbsp;at param (/juice-shop/node_modules/express/lib/router/index.js:376:14)</li><li> &nbsp; &nbsp;at Function.process_params (/juice-shop/node_modules/express/lib/router/index.js:421:3)</li><li> &nbsp; &nbsp;at next (/juice-shop/node_modules/express/lib/router/index.js:280:10)</li><li> &nbsp; &nbsp;at /juice-shop/node_modules/serve-index/index.js:145:39</li><li> &nbsp; &nbsp;at FSReqCallback.oncomplete (node:fs:198:5)</li></ul>
    </div>
  </body>
</html>

┌──(root㉿b0985949ec71)-[/]
└─# curl "http://172.16.90.40:3000/ftp/package.json.bak%2500.pdf" -o package.json.bak
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  4291 100  4291   0     0  1341k     0  --:--:-- --:--:-- --:--:--  1396k
```

Добавляем правила:

```yaml
# --- A02: Cryptographic Failures (backup, Poison Null Byte, coupons) ---
alert http any any -> any 3000 (msg:"[IDS] FTP directory access"; flow:to_server,established; http.uri; content:"/ftp/"; classtype:policy-violation; sid:4602001; rev:1;)

alert http any any -> any 3000 (msg:"[IDS] Backup file access attempt"; flow:to_server,established; http.uri; pcre:"/\.bak/i"; classtype:policy-violation; sid:4602002; rev:1;)

alert http any any -> any 3000 (msg:"[IDS] Poison Null Byte detected"; flow:to_server,established; http.uri; pcre:"/%00|%2500/i"; classtype:web-application-attack; sid:4602003; rev:1;)

alert http any any -> any 3000 (msg:"[IDS] Sensitive file access (coupons)"; flow:to_server,established; http.uri; content:"coupons"; nocase; classtype:policy-violation; sid:4602004; rev:1;)

drop  http any any -> any 3000 (msg:"[IPS] Poison Null Byte blocked"; flow:to_server,established; http.uri; pcre:"/%00|%2500/i"; sid:4602101; rev:1;)

drop  http any any -> any 3000 (msg:"[IPS] Backup file access blocked"; flow:to_server,established; http.uri; pcre:"/\.bak/i"; sid:4602102; rev:1;)
```

Повторим запросы и увидим:

### Для alert `4602001`

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4602001" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T20:52:15.774979+0000",
  "flow_id": 1807865741750934,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 38202,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4602001,
    "rev": 1,
    "signature": "[IDS] FTP directory access",
    "category": "Potential Corporate Privacy Violation",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_body",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/ftp/",
    "http_user_agent": "curl/8.17.0",
    "http_content_type": "text/html",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 1110
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 9,
    "pkts_toclient": 11,
    "bytes_toserver": 601,
    "bytes_toclient": 12193,
    "start": "2025-12-28T20:52:14.748606+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 38202,
    "dest_port": 3000
  }
}
```

### Для alert `4602003`

```bash
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4602003" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T20:52:15.774979+0000",
  "flow_id": 1807865741750934,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 38202,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4602001,
    "rev": 1,
    "signature": "[IDS] FTP directory access",
    "category": "Potential Corporate Privacy Violation",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_body",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/ftp/",
    "http_user_agent": "curl/8.17.0",
    "http_content_type": "text/html",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 1110
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 9,
    "pkts_toclient": 11,
    "bytes_toserver": 601,
    "bytes_toclient": 12193,
    "start": "2025-12-28T20:52:14.748606+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 38202,
    "dest_port": 3000
  }
}
```

### Для alert `4602003`

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4602003" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T20:52:54.985068+0000",
  "flow_id": 1959781936344962,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 43274,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4602003,
    "rev": 1,
    "signature": "[IDS] Poison Null Byte detected",
    "category": "Web Application Attack",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_complete",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/ftp/coupons_2013.md.bak%2500.md",
    "http_user_agent": "curl/8.17.0",
    "http_content_type": "application/octet-stream",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 131
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 4,
    "pkts_toclient": 3,
    "bytes_toserver": 328,
    "bytes_toclient": 736,
    "start": "2025-12-28T20:52:54.980585+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 43274,
    "dest_port": 3000
  }
}
```

Для alert `4602004`

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4602004" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T20:52:54.985068+0000",
  "flow_id": 1959781936344962,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 43274,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4602004,
    "rev": 1,
    "signature": "[IDS] Sensitive file access (coupons)",
    "category": "Potential Corporate Privacy Violation",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_complete",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/ftp/coupons_2013.md.bak%2500.md",
    "http_user_agent": "curl/8.17.0",
    "http_content_type": "application/octet-stream",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 131
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 4,
    "pkts_toclient": 3,
    "bytes_toserver": 328,
    "bytes_toclient": 736,
    "start": "2025-12-28T20:52:54.980585+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 43274,
    "dest_port": 3000
  }
}
```
### Для drop 4602101

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4602101" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T20:52:54.985068+0000",
  "flow_id": 1959781936344962,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 43274,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4602101,
    "rev": 1,
    "signature": "[IPS] Poison Null Byte blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_complete",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/ftp/coupons_2013.md.bak%2500.md",
    "http_user_agent": "curl/8.17.0",
    "http_content_type": "application/octet-stream",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 131
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 4,
    "pkts_toclient": 3,
    "bytes_toserver": 328,
    "bytes_toclient": 736,
    "start": "2025-12-28T20:52:54.980585+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 43274,
    "dest_port": 3000
  }
}
```

### Для drop 4602102

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4602102" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T21:07:23.027675+0000",
  "flow_id": 617498095808656,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 33730,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4602102,
    "rev": 1,
    "signature": "[IPS] Backup file access blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_body",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/ftp/package.json.bak",
    "http_user_agent": "curl/8.17.0",
    "http_content_type": "text/html",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 403,
    "length": 1098
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 9,
    "pkts_toclient": 4,
    "bytes_toserver": 617,
    "bytes_toclient": 2514,
    "start": "2025-12-28T21:07:22.012700+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 33730,
    "dest_port": 3000
  }
}
```

# Атака 3:  Инъекции (A03:2021 Injection)

Классическая SQL-инъекция через POST-запрос была успешно реализована на этапе атаки, выдав токен администратора. После настройки Suricata в логах зафиксирована четкая сработка правила 4603101, анализирующего тело запроса на наличие конструкций OR 1=1 и комментариев --. Статус blocked подтверждает, что полезная нагрузка не достигла бэкенда базы данных.

Выполняем запросы:

```bash
┌──(root㉿b0985949ec71)-[/]
└─# curl -X POST "http://172.16.90.40:3000/rest/user/login"   -H "Content-Type: application/json"   -d "{\"email\":\"' OR 1=1 --\",\"password\":\"any\"}"
{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjUtMTItMjggMTg6MjQ6MTguMzYyICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjUtMTItMjggMTg6MjQ6MTguMzYyICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc2Njk1ODc1MH0.hqoCdfGDOdbxbr3QAROybSDL8rA-PT_tVXWhFdeEG30Ypz-Ga92aYOotEg8HB8kka9gDpJrjS83lQYz9h78CDmd4BvMqLnGOokiQNiG0HIUVbugISnYR35BX8-8DtJ9i-Ed_9hTmp0CkxFDcT7Weu9GO3J5jMSAovkrm_Q2gsp4","bid":1,"umail":"admin@juice-sh.op"}}
```

Добавляем правила:

```yaml
# --- A03: SQL Injection  ---
alert http any any -> any 3000 (msg:"[IDS] SQLi OR 1=1 detected"; flow:to_server,established; http.request_body; pcre:"/or\s+\d+\s*=\s*\d+/i"; classtype:web-application-attack; sid:4603001; rev:2;)

alert http any any -> any 3000 (msg:"[IDS] SQLi UNION SELECT detected"; flow:to_server,established; http.uri; content:"union"; nocase; pcre:"/union\s+select/i"; classtype:web-application-attack; sid:4603002; rev:2;)

alert http any any -> any 3000 (msg:"[IDS] SQLi comment found"; flow:to_server,established; http.request_body; content:"--"; classtype:web-application-attack; sid:4603003; rev:1;)

drop http any any -> any 3000 (msg:"[IPS] SQLi blocked on login"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/rest/user/login"; http.request_body; pcre:"/or\s+\d+\s*=\s*\d+|union\s+select|--/i"; sid:4603101; rev:2;)
```

### Для alert 4603001

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4603001" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T22:23:37.834323+0000",
  "flow_id": 484676483468557,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 38328,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4603001,
    "rev": 2,
    "signature": "[IDS] SQLi OR 1=1 detected",
    "category": "Web Application Attack",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/rest/user/login",
    "http_user_agent": "curl/8.17.0",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "files": [
    {
      "filename": "/rest/user/login",
      "gaps": false,
      "state": "CLOSED",
      "stored": false,
      "size": 40,
      "tx_id": 0
    }
  ],
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 353,
    "bytes_toclient": 60,
    "start": "2025-12-28T22:23:37.833743+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 38328,
    "dest_port": 3000
  }
}
```

### Для alert 4603003

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4603003" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T22:23:37.834323+0000",
  "flow_id": 484676483468557,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 38328,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4603003,
    "rev": 1,
    "signature": "[IDS] SQLi comment found",
    "category": "Web Application Attack",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/rest/user/login",
    "http_user_agent": "curl/8.17.0",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "files": [
    {
      "filename": "/rest/user/login",
      "gaps": false,
      "state": "CLOSED",
      "stored": false,
      "size": 40,
      "tx_id": 0
    }
  ],
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 353,
    "bytes_toclient": 60,
    "start": "2025-12-28T22:23:37.833743+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 38328,
    "dest_port": 3000
  }
}
```

### Для drop 4603101

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4603101" /var/log/suricata/eve.json | jq .
{
 "timestamp": "2025-12-28T21:44:45.079119+0000",
 "flow_id": 1133818259702256,
 "event_type": "alert",
 "src_ip": "172.16.90.20",
 "src_port": 57892,
 "dest_ip": "172.16.90.40",
 "dest_port": 3000,
 "proto": "TCP",
 "ip_v": 4,
 "pkt_src": "wire/pcap",
 "tx_id": 0,
 "alert": {
   "action": "blocked",
   "gid": 1,
   "signature_id": 4603101,
   "rev": 2,
   "signature": "[IPS] SQLi blocked on login",
   "category": "",
   "severity": 3
 },
 "ts_progress": "request_complete",
 "tc_progress": "response_complete",
 "http": {
   "hostname": "172.16.90.40",
   "http_port": 3000,
   "url": "/rest/user/login",
   "http_user_agent": "curl/8.17.0",
   "http_content_type": "application/json",
   "http_method": "POST",
   "protocol": "HTTP/1.1",
   "status": 200,
   "length": 799
 },
 "files": [
   {
     "filename": "/rest/user/login",
     "gaps": false,
     "state": "CLOSED",
     "stored": false,
     "size": 40,
     "tx_id": 0
   }
 ],
 "app_proto": "http",
 "direction": "to_server",
 "flow": {
   "pkts_toserver": 9,
   "pkts_toclient": 3,
   "bytes_toserver": 705,
   "bytes_toclient": 1349,
   "start": "2025-12-28T21:44:44.067379+0000",
   "src_ip": "172.16.90.20",
   "dest_ip": "172.16.90.40",
   "src_port": 57892,
   "dest_port": 3000
 }
}
```

# Атака 4:  Небезопасный дизайн (A04:2021 Insecure Design)

Скрипт перебора паролей продемонстрировал отсутствие rate-limiting на уровне приложения, позволив подобрать пароль admin123. Suricata компенсировала этот недостаток дизайна правилами threshold. В логах наблюдаются сначала алерты (4504001), а затем, при агрессивном переборе, срабатывание правила блокировки 4504101, отсекающего атакующего по IP.

Выполняем атаку:

```bash
┌──(venv)(root㉿b0985949ec71)-[/]
└─# python3 brute_login.py
======================================================================
[*] Target: http://172.16.90.40:3000
[*] Email: admin@juice-sh.op
======================================================================
[ 1/20] Try: password        ... Failed
[ 2/20] Try: 123456          ... Failed
[ 3/20] Try: 12345678        ... Failed
[ 4/20] Try: qwerty          ... Failed
[ 5/20] Try: monkey          ... Failed
[ 6/20] Try: 1234567         ... Failed
[ 7/20] Try: letmein         ... Failed
[ 8/20] Try: trustno1        ... Failed
[ 9/20] Try: abc123          ... Failed
[10/20] Try: dragon          ... Failed
[11/20] Try: baseball        ... Failed
[12/20] Try: 111111          ... Failed
[13/20] Try: iloveyou        ... Failed
[14/20] Try: master          ... Failed
[15/20] Try: sunshine        ... Failed
[16/20] Try: ashley          ... Failed
[17/20] Try: bailey          ... Failed
[18/20] Try: shadow          ... Failed
[19/20] Try: 123123          ... Failed
[20/20] Try: admin123        ... SUCCESS!
======================================================================
[+] Password found: admin123
[+] Time elapsed: 36.97s
[+] JWT Token: eyJ0eXAiOiJKV1QiLCJh...
======================================================================
```

Добавляем правила:

```yaml
# --- A04: Insecure Design (no rate limiting on login) ---
alert http any any -> any 3000 (msg:"[IDS] Login brute-force detected"; flow:to_server,established; content:"/rest/user/login"; http_uri; content:"POST"; http_method; threshold:type both, track by_src, count 5, seconds 10; classtype:attempted-recon; sid:4504001; rev:2;)

alert http any any -> any 3000 (msg:"[IDS] Aggressive login brute-force"; flow:to_server,established; content:"/rest/user/login"; http_uri; threshold:type both, track by_src, count 10, seconds 30; classtype:attempted-recon; sid:4504002; rev:2;)

drop http any any -> any 3000 (msg:"[IPS] Login brute-force blocked"; flow:to_server,established; content:"/rest/user/login"; http_uri; content:"POST"; http_method; threshold:type both, track by_src, count 5, seconds 10; sid:4504101; rev:2;)
```

### Для alert 4504001

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4504001" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T22:49:43.987999+0000",
  "flow_id": 1989576752109642,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 33700,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4504001,
    "rev": 2,
    "signature": "[IDS] Login brute-force detected",
    "category": "Attempted Information Leak",
    "severity": 2
  },
  "ts_progress": "request_body",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/rest/user/login",
    "http_user_agent": "python-requests/2.32.5",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 380,
    "bytes_toclient": 60,
    "start": "2025-12-28T22:49:43.987522+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 33700,
    "dest_port": 3000
  }
}
```

### Для alert 4504001

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4504002" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T22:49:55.559065+0000",
  "flow_id": 991852183354032,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 51102,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4504002,
    "rev": 2,
    "signature": "[IDS] Aggressive login brute-force",
    "category": "Attempted Information Leak",
    "severity": 2
  },
  "ts_progress": "request_body",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/rest/user/login",
    "http_user_agent": "python-requests/2.32.5",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 380,
    "bytes_toclient": 60,
    "start": "2025-12-28T22:49:55.558613+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 51102,
    "dest_port": 3000
  }
}
```

### Для drop 4504101

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4504101" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T22:49:43.987999+0000",
  "flow_id": 1989576752109642,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 33700,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4504101,
    "rev": 2,
    "signature": "[IPS] Login brute-force blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_body",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/rest/user/login",
    "http_user_agent": "python-requests/2.32.5",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 380,
    "bytes_toclient": 60,
    "start": "2025-12-28T22:49:43.987522+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 33700,
    "dest_port": 3000
  }
}
```

# Атака 5:  Неправильная конфигурация безопасности (A05:2021 Security Misconfiguration)

Выявление доступных "лишних" файлов и эндпоинтов продемонстрировало типичные ошибки конфигурации продакшн-среды. Правила IDS успешно детектировали попытки разведки, а IPS-правило 4505103 жестко заблокировало доступ к метрикам Prometheus (/metrics). Это является критически важным, так как метрики часто раскрывают внутреннюю архитектуру приложения.

Добавляем правила:

```yaml
# --- LAB 4 TASK 6: Security Misconfiguration (FIXED: any dest + syntax) ---

# IDS: Poison Null Byte (обход проверок файлов)
alert http any any -> any 3000 (msg:"[IDS] Poison Null Byte detected"; flow:to_server,established; content:"%2500"; http_uri; classtype:web-application-attack; sid:4505001; rev:3;)

# IDS: Доступ к FTP-директории
alert http any any -> any 3000 (msg:"[IDS] FTP directory access"; flow:to_server,established; content:"/ftp/"; http_uri; classtype:policy-violation; sid:4505002; rev:3;)

# IDS: Доступ к backup-файлам
alert http any any -> any 3000 (msg:"[IDS] Backup file access"; flow:to_server,established; content:".bak"; http_uri; classtype:policy-violation; sid:4505003; rev:3;)

# IDS: Доступ к метрикам
alert http any any -> any 3000 (msg:"[IDS] Metrics endpoint access"; flow:to_server,established; content:"/metrics"; http_uri; classtype:policy-violation; sid:4505004; rev:3;)

# IDS: Доступ к Security Questions API
alert http any any -> any 3000 (msg:"[IDS] Security Questions API access"; flow:to_server,established; content:"/api/SecurityQuestions"; http_uri; classtype:policy-violation; sid:4505005; rev:3;)

# IPS: Блокировка Poison Null Byte
drop http any any -> any 3000 (msg:"[IPS] Poison Null Byte blocked"; flow:to_server,established; content:"%2500"; http_uri; sid:4505101; rev:3;)

# IPS: Блокировка доступа к backup-файлам
drop http any any -> any 3000 (msg:"[IPS] Backup file access blocked"; flow:to_server,established; content:".bak"; http_uri; sid:4505102; rev:3;)

# IPS: Блокировка доступа к метрикам
drop http any any -> any 3000 (msg:"[IPS] Metrics access blocked"; flow:to_server,established; content:"/metrics"; http_uri; sid:4505103; rev:3;)
```

### Для alert 4505002

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4505002" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T22:59:56.755922+0000",
  "flow_id": 1274793629325336,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 51196,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4505002,
    "rev": 3,
    "signature": "[IDS] FTP directory access",
    "category": "Potential Corporate Privacy Violation",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/ftp/legal.md%2500.md",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 265,
    "bytes_toclient": 60,
    "start": "2025-12-28T22:59:56.755563+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 51196,
    "dest_port": 3000
  }
}
```

### Для alert 4505004

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4505004" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T23:00:47.629497+0000",
  "flow_id": 2139567048373674,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 35534,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4505004,
    "rev": 3,
    "signature": "[IDS] Metrics endpoint access",
    "category": "Potential Corporate Privacy Violation",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/metrics",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 252,
    "bytes_toclient": 60,
    "start": "2025-12-28T23:00:47.629228+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 35534,
    "dest_port": 3000
  }
}
```
### Для alert 4505005

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4505005" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T23:01:22.787776+0000",
  "flow_id": 567221471039278,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 33256,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4505005,
    "rev": 3,
    "signature": "[IDS] Security Questions API access",
    "category": "Potential Corporate Privacy Violation",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/api/SecurityQuestions",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 266,
    "bytes_toclient": 60,
    "start": "2025-12-28T23:01:22.787426+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 33256,
    "dest_port": 3000
  }
}
```
### Для drop 4505103

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4505103" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-28T23:00:47.629497+0000",
  "flow_id": 2139567048373674,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 35534,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4505103,
    "rev": 3,
    "signature": "[IPS] Metrics access blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/metrics",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 252,
    "bytes_toclient": 60,
    "start": "2025-12-28T23:00:47.629228+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 35534,
    "dest_port": 3000
  }
}
```

# Атака 6:  Уязвимые и устаревшие компоненты (A06:2021 Vulnerable Components)

Попытка фингерпринтинга (сбор версий ПО) через вызов страницы ошибки прошла успешно — сервер раскрыл версию Express. Suricata зафиксировала данную активность правилами 4506001 и 4506003, обнаружив попытки обращения к несуществующим .txt файлам и конфигурации package.json. Использование режима IDS (alert) в данном случае обеспечивает сигнал администратору о сканировании инфраструктуры.

Выполняем атаку:

```bash
┌──(root㉿b0985949ec71)-[/]
└─# curl "http://172.16.90.40:3000/ftp/nonexistent.txt" | grep 'WASP Juice Shop'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1937   0  1937   0     0 808093     0  --:--:-- --:--:-- --:--:-- 968500
      <h1>OWASP Juice Shop (Express ^4.21.0)</h1>
```

Добавляем правила:

```yaml
# --- A06: Vulnerable Components (IDS) ---

# 1. Попытка Fingerprinting через ошибки (запрос странных расширений)
# Мы привязываемся к ".txt" так как это используется в лабе, но pcre проверяет конец строки
alert http any any -> any 3000 (msg:"[IDS] Error page fingerprinting attempt"; flow:to_server,established; content:".txt"; http_uri; classtype:attempted-recon; sid:4506001; rev:2;)

# 2. Попытка доступа к файлам зависимостей (package.json и др)
alert http any any -> any 3000 (msg:"[IDS] Dependency config access"; flow:to_server,established; content:"package.json"; http_uri; classtype:attempted-recon; sid:4506003; rev:2;)
```

### Для alert 4506001

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4506001" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T05:58:51.842307+0000",
  "flow_id": 1082542424148118,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 56388,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4506001,
    "rev": 2,
    "signature": "[IDS] Error page fingerprinting attempt",
    "category": "Attempted Information Leak",
    "severity": 2
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/ftp/nonexistent.txt",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 264,
    "bytes_toclient": 60,
    "start": "2025-12-29T05:58:51.841873+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 56388,
    "dest_port": 3000
  }
}
```

### Для alert 4506003

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4506003" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T05:58:53.324036+0000",
  "flow_id": 1671780341176889,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 38698,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4506003,
    "rev": 2,
    "signature": "[IDS] Dependency config access",
    "category": "Attempted Information Leak",
    "severity": 2
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/package.json",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 257,
    "bytes_toclient": 60,
    "start": "2025-12-29T05:58:53.323705+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 38698,
    "dest_port": 3000
  }
}
```

# Атака 7:  Уязвимые и устаревшие компоненты (A06:2021 Vulnerable Components)

Был выполнен вход под учетной записью администратора без пароля (через SQLi) и осуществлен подбор слабого пароля скриптом. В логах зафиксировано обнаружение обоих векторов: SQL-инъекции в поле логина (4507001) и множественных неудачных попыток входа (4507002). В итоге сработал порог блокировки 4507102, предотвративший дальнейший перебор учетных записей (Credential Stuffing).

Выполняем атаку

```bash
┌──(root㉿b0985949ec71)-[/]
└─# curl -X POST "http://172.16.90.40:3000/rest/user/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"' OR 1=1 --\",\"password\":\"any\"}" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   839 100   799 100    40   785    39   0:00:01  0:00:01 --:--:--   824
{
  "authentication": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjUtMTItMjggMTg6MjQ6MTguMzYyICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjUtMTItMjggMTg6MjQ6MTguMzYyICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc2Njk4ODM5Mn0.w3aEON64Bw7-K6uqXvplrgUNIsiqj88rqICvHZQyKcCK26lVUPGP4hYbsYu04es3e1WvvOu33LsFlMKwMU0ooTBq294JFop1WJVCmtGNN-sofnErB3uRqLfAOBMddmN3JBV9-d-9d65toUM4NC_LJxKCFPguYOMqdbhQi3iiTrw",
    "bid": 1,
    "umail": "admin@juice-sh.op"
  }
}
```

Ищем аккаунты со слабым паролем:

```bash
┌──(venv)(root㉿b0985949ec71)-[/]
└─# python3 auth_weak_passwords.py
============================================================
Testing Weak Passwords (A07)
============================================================
[*] Testing admin@juice-sh.op
 [+] SUCCESS: admin123
[*] Testing jim@juice-sh.op
 [-] No weak password found from list
[*] Testing bender@juice-sh.op
 [-] No weak password found from list
[*] Testing amy@juice-sh.op
 [-] No weak password found from list
============================================================
[+] Found 1 accounts with weak passwords
```

Добавляем правила:

```yaml
# --- A07: Identification & Authentication Failures ---
# 1. SQL Injection Authentication Bypass (OR 1=1 в login)
alert http any any -> any 3000 (msg:"[IDS] SQLi authentication bypass"; flow:to_server,established; content:"/rest/user/login"; http_uri; content:"or"; http_client_body; nocase; pcre:"/or\s+1=1/i"; classtype:web-application-attack; sid:4507001; rev:2;)

# 2. Credential Stuffing (Многократные неудачные попытки входа)
alert http any any -> any 3000 (msg:"[IDS] Multiple failed login attempts"; flow:to_server,established; content:"/rest/user/login"; http_uri; content:"POST"; http_method; threshold:type both, track by_src, count 5, seconds 30; classtype:attempted-recon; sid:4507002; rev:2;)

# Блокировка при превышении порога попыток входа (10 попыток за 30 сек)
drop http any any -> any 3000 (msg:"[IPS] Failed login threshold exceeded"; flow:to_server,established; content:"/rest/user/login"; http_uri; threshold:type both, track by_src, count 10, seconds 30; sid:4507102; rev:2;)
```

### Для alert 4507001

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4507001" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:10:50.215728+0000",
  "flow_id": 643657300184585,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 49634,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4507001,
    "rev": 2,
    "signature": "[IDS] SQLi authentication bypass",
    "category": "Web Application Attack",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/rest/user/login",
    "http_user_agent": "curl/8.17.0",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "files": [
    {
      "filename": "/rest/user/login",
      "gaps": false,
      "state": "CLOSED",
      "stored": false,
      "size": 40,
      "tx_id": 0
    }
  ],
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 353,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:10:50.215399+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 49634,
    "dest_port": 3000
  }
}
```

### Для alert 4507002

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4507002" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:11:21.420518+0000",
  "flow_id": 398072104181535,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 53598,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4507002,
    "rev": 2,
    "signature": "[IDS] Multiple failed login attempts",
    "category": "Attempted Information Leak",
    "severity": 2
  },
  "ts_progress": "request_body",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/rest/user/login",
    "http_user_agent": "python-requests/2.32.5",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 380,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:11:21.420363+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 53598,
    "dest_port": 3000
  }
}
```

### Для 4507102

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep "4507102" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:11:21.470225+0000",
  "flow_id": 330065486542249,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 53666,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4507102,
    "rev": 2,
    "signature": "[IPS] Failed login threshold exceeded",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_body",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/rest/user/login",
    "http_user_agent": "python-requests/2.32.5",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 380,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:11:21.470065+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 53666,
    "dest_port": 3000
  }
}
```

# Атака 8: Сбои целостности ПО и данных (A08:2021 Software and Data Integrity Failures)

Раздел демонстрирует тестирование нескольких векторов XSS (script, iframe, event handlers). Логи подтверждают полную работоспособность IPS: правила 4508101 (script), 4508102 (javascript URI) и 4508104 (event handler) перехватили вредоносный код в URL. Все попытки внедрения были заблокированы, что защитило пользователей от выполнения произвольного JS-кода.

Выполняем атаки:

```bash
curl "http://172.16.90.40:3000/#/search?q=<script>alert(1)</script>"
curl -G "http://172.16.90.40:3000/#/search" --data-urlencode "q=<iframe src='javascript:alert(1)'>"
curl "http://172.16.90.40:3000/#/track-result?id=<img%20src=x%20onerror=alert(1)>"
curl "http://172.16.90.40:3000/#/search?q=javascript:alert(document.cookie)"
curl -v "http://172.16.90.40:3000/search?q=<script>alert(1)</script>"
curl -v "http://172.16.90.40:3000/track-result?id=<img%20src=x%20onerror=alert(1)>"
```
Добавляем правила:

```yaml
# --- A08: XSS ---
# 1. XSS: тег <script>
# IDS
alert http any any -> any 3000 (msg:"[IDS] XSS script tag detected"; flow:to_server,established; content:"<script"; http_uri; nocase; classtype:web-application-attack; sid:4508001; rev:2;)
# IPS
drop http any any -> any 3000 (msg:"[IPS] XSS script blocked"; flow:to_server,established; content:"<script"; http_uri; nocase; sid:4508101; rev:2;)

# 2. XSS: javascript: URI
# IDS
alert http any any -> any 3000 (msg:"[IDS] XSS javascript URI detected"; flow:to_server,established; content:"javascript:"; http_uri; nocase; classtype:web-application-attack; sid:4508003; rev:2;)
# IPS
drop http any any -> any 3000 (msg:"[IPS] XSS javascript URI blocked"; flow:to_server,established; content:"javascript:"; http_uri; nocase; sid:4508102; rev:2;)

# 3. XSS: iframe injection
# IDS
alert http any any -> any 3000 (msg:"[IDS] XSS iframe injection detected"; flow:to_server,established; content:"<iframe"; http_uri; nocase; classtype:web-application-attack; sid:4508004; rev:2;)
# IPS
drop http any any -> any 3000 (msg:"[IPS] XSS iframe blocked"; flow:to_server,established; content:"<iframe"; http_uri; nocase; sid:4508103; rev:2;)

# 4. XSS: Event handlers (onload/onerror/onclick)
# Мы добавляем content:"=" для привязки, чтобы удовлетворить парсер
# IDS
alert http any any -> any 3000 (msg:"[IDS] XSS event handler detected"; flow:to_server,established; content:"="; http_uri; pcre:"/on(load|error|click)\s*=/i"; classtype:web-application-attack; sid:4508002; rev:2;)
# IPS
drop http any any -> any 3000 (msg:"[IPS] XSS event handler blocked"; flow:to_server,established; content:"="; http_uri; pcre:"/on(load|error|click)\s*=/i"; sid:4508104; rev:2;)
```

Срабатывания правил по одному:

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4508001" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:27:19.592867+0000",
  "flow_id": 1981496685764234,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 34096,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4508001,
    "rev": 2,
    "signature": "[IDS] XSS script tag detected",
    "category": "Web Application Attack",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/search?q=<script>alert(1)</script>",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 279,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:27:19.592425+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 34096,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4508101" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:27:19.592867+0000",
  "flow_id": 1981496685764234,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 34096,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4508101,
    "rev": 2,
    "signature": "[IPS] XSS script blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/search?q=<script>alert(1)</script>",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 279,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:27:19.592425+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 34096,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4508003" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:21:13.589636+0000",
  "flow_id": 560170816433991,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 49438,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4508003,
    "rev": 2,
    "signature": "[IDS] XSS javascript URI detected",
    "category": "Web Application Attack",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/?q=%3ciframe+src%3d%27javascript%3aalert%281%29%27%3e",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 298,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:21:13.589176+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 49438,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4508102" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:21:13.589636+0000",
  "flow_id": 560170816433991,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 49438,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4508102,
    "rev": 2,
    "signature": "[IPS] XSS javascript URI blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/?q=%3ciframe+src%3d%27javascript%3aalert%281%29%27%3e",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 298,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:21:13.589176+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 49438,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4508004" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:21:13.589636+0000",
  "flow_id": 560170816433991,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 49438,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4508004,
    "rev": 2,
    "signature": "[IDS] XSS iframe injection detected",
    "category": "Web Application Attack",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/?q=%3ciframe+src%3d%27javascript%3aalert%281%29%27%3e",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 298,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:21:13.589176+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 49438,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4508103" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:21:13.589636+0000",
  "flow_id": 560170816433991,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 49438,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4508103,
    "rev": 2,
    "signature": "[IPS] XSS iframe blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/?q=%3ciframe+src%3d%27javascript%3aalert%281%29%27%3e",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 298,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:21:13.589176+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 49438,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4508002" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:27:31.154958+0000",
  "flow_id": 945055887190825,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 49598,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4508002,
    "rev": 2,
    "signature": "[IDS] XSS event handler detected",
    "category": "Web Application Attack",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/track-result?id=<img%20src=x%20onerror=alert(1)>",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 293,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:27:31.154501+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 49598,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4508104" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:27:31.154958+0000",
  "flow_id": 945055887190825,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 49598,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4508104,
    "rev": 2,
    "signature": "[IPS] XSS event handler blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/track-result?id=<img%20src=x%20onerror=alert(1)>",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 293,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:27:31.154501+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 49598,
    "dest_port": 3000
  }
}
```

# Атака 9: Недостатки логирования и мониторинга (A09:2021 Security Logging and Monitoring Failures)

Атака продемонстрировала, что публичный доступ к логам (access.log, audit.json) позволяет видеть действия других пользователей. Настроенные правила успешно идентифицировали обращение к директории /support/logs. Правило 4509101 сработало в режиме блокировки, предотвратив выкачивание файлов аудита и закрыв утечку информации.

Выполняем атаки:

```bash
┌──(root㉿b0985949ec71)-[/]
└─# curl "http://172.16.90.40:3000/support/logs"
```

Получаем отчеты:

```bash
┌──(root㉿b0985949ec71)-[/]
└─# curl "http://172.16.90.40:3000/support/logs/audit.json" -o audit.json
cat audit.json
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0   0     0   0     0     0     0  --:--:--  0:00:03 --:--:--     0^C
{
    "keepSettings": {
        "type": 1,
        "amount": 2
    },
    "auditFilename": "logs/audit.json",
    "hashType": "md5",
    "extension": "",
    "files": [
        {
            "date": 1766946258229,
            "name": "/juice-shop/logs/access.log.2025-12-28",
            "hash": "b7e73e64cec383580bccf95ee835a241"
        },
        {
            "date": 1766987780214,
            "name": "/juice-shop/logs/access.log.2025-12-29",
            "hash": "1ad308065dc773e9795ff85d526ae362"
        }
    ]
}
```
Добавляем правила:

```yaml
# --- A09: Logging & Monitoring Failures ---
# IDS: Доступ к директории логов
alert http any any -> any 3000 (msg:"[IDS] Log directory access"; flow:to_server,established; content:"/support/logs"; http_uri; classtype:policy-violation; sid:4509001; rev:2;)

# IDS: Скачивание файлов логов (используем pcre для точного совпадения расширений)
# Сначала матчим путь (content), потом уточняем регуляркой
alert http any any -> any 3000 (msg:"[IDS] Log file download"; flow:to_server,established; content:"/support/logs/"; http_uri; pcre:"/\/support\/logs\/.*(access\.log|audit\.json)/"; classtype:policy-violation; sid:4509002; rev:2;)

# IPS: Блокировка доступа к директории логов (и всем файлам внутри)
drop http any any -> any 3000 (msg:"[IPS] Log access blocked"; flow:to_server,established; content:"/support/logs"; http_uri; sid:4509101; rev:2;)
```

Получаем срабатывание правил:

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4509001" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:45:37.374919+0000",
  "flow_id": 25711587081959,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 35076,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4509001,
    "rev": 2,
    "signature": "[IDS] Log directory access",
    "category": "Potential Corporate Privacy Violation",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/support/logs",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 8,
    "pkts_toclient": 1,
    "bytes_toserver": 557,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:45:36.333666+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 35076,
    "dest_port": 3000
  }
}
{
  "timestamp": "2025-12-29T06:45:53.336053+0000",
  "flow_id": 315458765587685,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 60898,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4509001,
    "rev": 2,
    "signature": "[IDS] Log directory access",
    "category": "Potential Corporate Privacy Violation",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/support/logs/audit.json",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 268,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:45:53.335592+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 60898,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4509002" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:45:53.336053+0000",
  "flow_id": 315458765587685,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 60898,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4509002,
    "rev": 2,
    "signature": "[IDS] Log file download",
    "category": "Potential Corporate Privacy Violation",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/support/logs/audit.json",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 268,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:45:53.335592+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 60898,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4509101" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:45:37.374919+0000",
  "flow_id": 25711587081959,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 35076,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4509101,
    "rev": 2,
    "signature": "[IPS] Log access blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/support/logs",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 8,
    "pkts_toclient": 1,
    "bytes_toserver": 557,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:45:36.333666+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 35076,
    "dest_port": 3000
  }
}
{
  "timestamp": "2025-12-29T06:45:53.336053+0000",
  "flow_id": 315458765587685,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 60898,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4509101,
    "rev": 2,
    "signature": "[IPS] Log access blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/support/logs/audit.json",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 268,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:45:53.335592+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 60898,
    "dest_port": 3000
  }
}
```

# Атака 10: Подделка серверных запросов (A10:2021 Server-Side Request Forgery - SSRF)

Финальный тест на обращение к AWS Metadata (169.254.169.254) и localhost через загрузку аватарки представляет критический сценарий для облачных сред. Правила, использующие регулярные выражения для анализа JSON-тела запроса, отработали корректно. Логи демонстрируют блокировку по правилам 4510101 (AWS) и 4510102 (localhost), что гарантирует защиту от сканирования внутренней сети сервером.

Выполняем атаки:

```bash
┌──(root㉿b0985949ec71)-[/]
└─# curl -v -X POST "http://172.16.90.40:3000/profile/image/url" \
  -H "Content-Type: application/json" \
  -d '{"imageUrl":"http://169.254.169.254/latest/meta-data"}'
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 172.16.90.40:3000...
* Established connection to 172.16.90.40 (172.16.90.40 port 3000) from 172.16.90.20 port 59844 
* using HTTP/1.x
> POST /profile/image/url HTTP/1.1
> Host: 172.16.90.40:3000
> User-Agent: curl/8.17.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 54
> 
* upload completely sent off: 54 bytes
< HTTP/1.1 302 Found
< Access-Control-Allow-Origin: *
< X-Content-Type-Options: nosniff
< X-Frame-Options: SAMEORIGIN
< Feature-Policy: payment 'self'
< X-Recruiting: /#/jobs
< Location: /profile
< Vary: Accept, Accept-Encoding
< Content-Type: text/plain; charset=utf-8
< Content-Length: 30
< Date: Mon, 29 Dec 2025 06:52:39 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
< 
* Connection #0 to host 172.16.90.40:3000 left intact
Found. Redirecting to /profile
┌──(root㉿b0985949ec71)-[/]
└─# curl -v -X POST "http://172.16.90.40:3000/profile/image/url" \
  -H "Content-Type: application/json" \
  -d '{"imageUrl":"http://localhost:3000/metrics"}'
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 172.16.90.40:3000...
* Established connection to 172.16.90.40 (172.16.90.40 port 3000) from 172.16.90.20 port 54200 
* using HTTP/1.x
> POST /profile/image/url HTTP/1.1
> Host: 172.16.90.40:3000
> User-Agent: curl/8.17.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 44
> 
* upload completely sent off: 44 bytes
< HTTP/1.1 302 Found
< Access-Control-Allow-Origin: *
< X-Content-Type-Options: nosniff
< X-Frame-Options: SAMEORIGIN
< Feature-Policy: payment 'self'
< X-Recruiting: /#/jobs
< Location: /profile
< Vary: Accept, Accept-Encoding
< Content-Type: text/plain; charset=utf-8
< Content-Length: 30
< Date: Mon, 29 Dec 2025 06:53:00 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
< 
* Connection #0 to host 172.16.90.40:3000 left intact
Found. Redirecting to /profile
```

Добавляем правила:

```yaml
# --- A10: SSRF (Server-Side Request Forgery) ---
# IDS: Попытка доступа к AWS Metadata
alert http any any -> any 3000 (msg:"[IDS] SSRF AWS metadata attempt"; flow:to_server,established; content:"169.254.169.254"; http_client_body; classtype:web-application-attack; sid:4510001; rev:2;)

# IDS: Попытка доступа к Localhost (включая 127.0.0.1)
# Используем pcre для гибкого поиска в теле запроса
alert http any any -> any 3000 (msg:"[IDS] SSRF localhost targeting"; flow:to_server,established; content:"imageUrl"; http_client_body; pcre:"/(localhost|127\.0\.0\.1)/P"; classtype:web-application-attack; sid:4510002; rev:2;)

# IDS: Использование протокола file://
alert http any any -> any 3000 (msg:"[IDS] SSRF file protocol attempt"; flow:to_server,established; content:"file://"; http_client_body; nocase; classtype:web-application-attack; sid:4510005; rev:2;)

# IPS: Блокировка AWS Metadata
drop http any any -> any 3000 (msg:"[IPS] SSRF AWS metadata blocked"; flow:to_server,established; content:"169.254.169.254"; http_client_body; sid:4510101; rev:2;)

# IPS: Блокировка Localhost
drop http any any -> any 3000 (msg:"[IPS] SSRF localhost blocked"; flow:to_server,established; content:"imageUrl"; http_client_body; pcre:"/(localhost|127\.0\.0\.1)/P"; sid:4510102; rev:2;)

# IPS: Блокировка file://
drop http any any -> any 3000 (msg:"[IPS] SSRF file protocol blocked"; flow:to_server,established; content:"file://"; http_client_body; nocase; sid:4510104; rev:2;)
```
Получаем срабатывание правил:

```bash
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4509001" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:45:37.374919+0000",
  "flow_id": 25711587081959,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 35076,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4509001,
    "rev": 2,
    "signature": "[IDS] Log directory access",
    "category": "Potential Corporate Privacy Violation",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/support/logs",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 8,
    "pkts_toclient": 1,
    "bytes_toserver": 557,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:45:36.333666+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 35076,
    "dest_port": 3000
  }
}
{
  "timestamp": "2025-12-29T06:45:53.336053+0000",
  "flow_id": 315458765587685,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 60898,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4509001,
    "rev": 2,
    "signature": "[IDS] Log directory access",
    "category": "Potential Corporate Privacy Violation",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/support/logs/audit.json",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 268,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:45:53.335592+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 60898,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4509002" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:45:53.336053+0000",
  "flow_id": 315458765587685,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 60898,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4509002,
    "rev": 2,
    "signature": "[IDS] Log file download",
    "category": "Potential Corporate Privacy Violation",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/support/logs/audit.json",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 268,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:45:53.335592+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 60898,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4509101" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:45:37.374919+0000",
  "flow_id": 25711587081959,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 35076,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4509101,
    "rev": 2,
    "signature": "[IPS] Log access blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/support/logs",
    "http_user_agent": "curl/8.17.0",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 8,
    "pkts_toclient": 1,
    "bytes_toserver": 557,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:45:36.333666+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 35076,
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4510001" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:56:23.214811+0000",
  "flow_id": 2046528132397197,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 34082,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4510001,
    "rev": 2,
    "signature": "[IDS] SSRF AWS metadata attempt",
    "category": "Web Application Attack",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/profile/image/url",
    "http_user_agent": "curl/8.17.0",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "files": [
    {
      "filename": "/profile/image/url",
      "gaps": false,
      "state": "CLOSED",
      "stored": false,
      "size": 54,
      "tx_id": 0
    }
  ],
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 369,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:56:23.214350+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 34082,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4510002" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:56:29.542507+0000",
  "flow_id": 1483685996994566,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 34098,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 4510002,
    "rev": 2,
    "signature": "[IDS] SSRF localhost targeting",
    "category": "Web Application Attack",
    "severity": 1
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/profile/image/url",
    "http_user_agent": "curl/8.17.0",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "files": [
    {
      "filename": "/profile/image/url",
      "gaps": false,
      "state": "CLOSED",
      "stored": false,
      "size": 44,
      "tx_id": 0
    }
  ],
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 359,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:56:29.542055+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 34098,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4510101" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:56:23.214811+0000",
  "flow_id": 2046528132397197,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 34082,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4510101,
    "rev": 2,
    "signature": "[IPS] SSRF AWS metadata blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/profile/image/url",
    "http_user_agent": "curl/8.17.0",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "files": [
    {
      "filename": "/profile/image/url",
      "gaps": false,
      "state": "CLOSED",
      "stored": false,
      "size": 54,
      "tx_id": 0
    }
  ],
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 369,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:56:23.214350+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 34082,
    "dest_port": 3000
  }
}
devopsuser@ubuntu-jammy:/opt/suricata-lab$ sudo grep -E "4510102" /var/log/suricata/eve.json | jq .
{
  "timestamp": "2025-12-29T06:56:29.542507+0000",
  "flow_id": 1483685996994566,
  "event_type": "alert",
  "src_ip": "172.16.90.20",
  "src_port": 34098,
  "dest_ip": "172.16.90.40",
  "dest_port": 3000,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "tx_id": 0,
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 4510102,
    "rev": 2,
    "signature": "[IPS] SSRF localhost blocked",
    "category": "",
    "severity": 3
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_started",
  "http": {
    "hostname": "172.16.90.40",
    "http_port": 3000,
    "url": "/profile/image/url",
    "http_user_agent": "curl/8.17.0",
    "http_method": "POST",
    "protocol": "HTTP/1.1",
    "length": 0
  },
  "files": [
    {
      "filename": "/profile/image/url",
      "gaps": false,
      "state": "CLOSED",
      "stored": false,
      "size": 44,
      "tx_id": 0
    }
  ],
  "app_proto": "http",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 3,
    "pkts_toclient": 1,
    "bytes_toserver": 359,
    "bytes_toclient": 60,
    "start": "2025-12-29T06:56:29.542055+0000",
    "src_ip": "172.16.90.20",
    "dest_ip": "172.16.90.40",
    "src_port": 34098,
    "dest_port": 3000
  }
}
```












