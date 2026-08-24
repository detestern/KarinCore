#!/bin/bash
# Извлекаем данные из конфига с помощью Python
SERVER_ADDR=$(python3 -c "import json; print(json.load(open('/etc/karin-proxy/config.json'))['outbounds'][0]['settings']['vnext'][0]['address'])" 2>/dev/null)
DNS_IP=$(python3 -c "import json; d=json.load(open('/etc/karin-proxy/config.json')).get('dns', {}).get('servers', []); print(d[0] if d else '')" 2>/dev/null)

# Если вместо IP указан домен, резолвим его в чистый IP
if [[ ! "$SERVER_ADDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SERVER_IP=$(getent ahosts "$SERVER_ADDR" | awk '{print $1}' | head -n 1)
else
    SERVER_IP="$SERVER_ADDR"
fi

case "$1" in
    up)
        # Ждём, пока Xray реально создаст интерфейс tun0 — systemd запускает
        # ExecStartPost сразу после старта процесса, а не после того, как
        # Xray закончит поднимать TUN. Без этой паузы `ip route add ... dev
        # tun0 table 100` мог молча зафейлиться, и трафик на первом
        # подключении не шёл в туннель, хотя сервис был формально Active
        # (отсюда — необходимость второго клика "Подключить").
        for i in $(seq 1 20); do
            [ -d "/sys/class/net/tun0" ] && break
            sleep 0.25
        done

        # 1. Отключаем rp_filter (защита от асимметричного роутинга)
        sysctl -w net.ipv4.conf.all.rp_filter=0
        sysctl -w net.ipv4.conf.default.rp_filter=0
        sysctl -w net.ipv4.conf.tun0.rp_filter=0 2>/dev/null

        # 2. Поднимаем интерфейс и кастомную таблицу 100
        ip addr add 172.19.0.2/30 dev tun0 2>/dev/null
        ip link set tun0 up 2>/dev/null
        ip route add default dev tun0 table 100 2>/dev/null

        # 3. Базовые правила-исключения локальной сети
        ip rule add to 127.0.0.0/8 table main pref 10 2>/dev/null
        ip rule add to 10.0.0.0/8 table main pref 10 2>/dev/null
        ip rule add to 192.168.0.0/16 table main pref 10 2>/dev/null

        # Исключаем IP сервера и DNS из проксирования, чтобы не было петли
        if [ ! -z "$SERVER_IP" ]; then
            ip rule add to "$SERVER_IP" table main pref 10 2>/dev/null
        fi
        if [ ! -z "$DNS_IP" ]; then
            ip rule add to "$DNS_IP" table main pref 10 2>/dev/null
        fi

        # 4. Главное правило: весь остальной трафик — в туннель
        ip rule add not fwmark 255 table 100 pref 20 2>/dev/null
        ;;
    down)
        # Полная и чистая уборка за собой при остановке
        ip rule del not fwmark 255 table 100 pref 20 2>/dev/null
        if [ ! -z "$SERVER_IP" ]; then
            ip rule del to "$SERVER_IP" table main pref 10 2>/dev/null
        fi
        if [ ! -z "$DNS_IP" ]; then
            ip rule del to "$DNS_IP" table main pref 10 2>/dev/null
        fi
        ip route flush table 100 2>/dev/null
        ;;
esac

# ExecStartPost/ExecStopPost должны завершаться успешно независимо от того,
# какие именно правила уже существовали/отсутствовали к этому моменту —
# иначе systemd может пометить запуск или остановку сервиса как неудачные.
exit 0
