# Sniffer
## Описание
Анализатор трафика, или сниффер — программа или устройство для перехвата и анализа сетевого трафика (своего и/или чужого).

Автор: Сибирцев Иван КН-202

## Примеры запуска

- sudo python3 sniffer.py -- вывод всего трафика на консоль
- sudo python3 sniffer.py -f FILENAME -с 10 -- запись 10 пакетов в pcap файл
- sudo python3 sniffer.py -c 10 -- выведет на консоль 10 пакетов
- sudo python3 sniffer.py -i eth and ipv4 and tcp -- выведет на консоль только те пакеты, которые удовлетворяют описанию
- sudo python3 sniffer.py -s port 80 -- выведет на консоль http пакеты
- sudo python3 sniffer.py -b -- выведет оставшиеся данные в hex формате 
- sudo python3 sniffer.py -c 10 -p 'eth and ipv4 and (tcp or udp)' -s port 80
