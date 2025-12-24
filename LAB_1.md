# Lab_1

### Очищаем файл eve.json (становится пустым)

```bash
sudo truncate -s 0 /var/log/suricata/eve.json
```

### Визуализация в EveBox

URL: http://127.0.0.1:5636

Ищем атаки от конкретной машины: `src_ip:"172.16.90.20"`

### Мониторинг логов в консоли

```bash
sudo grep "1001001" /var/log/suricata/eve.json | jq .
```

### Проведение атак

Все атаки проводятся из контейнера attacker. IP-адрес жертвы (victim) в нашей сети: 172.16.90.10.

**Тест А: Проверка IPS (Блокировка ICMP)**
Согласно правилу drop icmp, Suricata должна блокировать пинг.

```bash
docker exec -it attacker ping -c 4 172.16.90.10
```
Что мы должны увидеть:

В консоли атаки: 100% packet loss. Пинг не должен проходить.

В логах Suricata: Появятся события "event_type": "drop" с сообщением [IPS] BLOCK ICMP.

```bash
sudo grep "100007" /var/log/suricata/eve.json | jq .
```

**Тест Б: Проверка IDS (Детектирование HTTP)**

Согласно правилу alert, Suricata должна записать лог, но пропустить трафик.

```bash
docker exec -it attacker curl http://172.16.90.10
```
В консоли атаки: HTML-код страницы "Victim container".

В логах Suricata: Появится событие "event_type": "alert" с сообщением [IDS] HTTP Request Detected.

```bash
sudo grep "100002" /var/log/suricata/eve.json | jq .
```