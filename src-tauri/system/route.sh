#!/bin/bash
RP_FILTER_BAK="/etc/karin-proxy/rp_filter.bak"
LOCAL_BYPASS_NETS="127.0.0.0/8 10.0.0.0/8 192.168.0.0/16"

# Извлекаем данные из конфига с помощью Python
SERVER_ADDR=$(python3 -c "import json; print(json.load(open('/etc/karin-proxy/config.json'))['outbounds'][0]['settings']['vnext'][0]['address'])" 2>/dev/null)

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

        # 1. Отключаем rp_filter (защита от асимметричного роутинга), сохранив исходные значения
        if [ ! -f "$RP_FILTER_BAK" ]; then
            {
                echo "ALL_RP=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null)"
                echo "DEFAULT_RP=$(cat /proc/sys/net/ipv4/conf/default/rp_filter 2>/dev/null)"
            } > "$RP_FILTER_BAK"
        fi
        sysctl -w net.ipv4.conf.all.rp_filter=0
        sysctl -w net.ipv4.conf.default.rp_filter=0
        sysctl -w net.ipv4.conf.tun0.rp_filter=0 2>/dev/null

        # 2. Поднимаем интерфейс и кастомную таблицу 100
        ip addr add 172.19.0.2/30 dev tun0 2>/dev/null
        ip link set tun0 up 2>/dev/null
        ip route add default dev tun0 table 100 2>/dev/null

        # 3. Базовые правила-исключения локальной сети
        for net in $LOCAL_BYPASS_NETS; do
            ip rule add to "$net" table main pref 10 2>/dev/null
        done

        # Исключаем IP сервера из проксирования, чтобы не было петли
        if [ ! -z "$SERVER_IP" ]; then
            ip rule add to "$SERVER_IP" table main pref 10 2>/dev/null
        fi

        # 4. Главное правило: весь остальной трафик — в туннель
        ip rule add not fwmark 255 table 100 pref 20 2>/dev/null

        # **********************************
        # DNS
        # **********************************
        if command -v resolvectl >/dev/null 2>&1; then
            resolvectl dns tun0 127.0.0.1 2>/dev/null
            resolvectl domain tun0 "~." 2>/dev/null
        else
            if [ ! -f /etc/karin-proxy/resolv.conf.bak ]; then
                cp /etc/resolv.conf /etc/karin-proxy/resolv.conf.bak 2>/dev/null
            fi
            printf "nameserver 127.0.0.1\n" > /etc/resolv.conf
        fi
        ;;
    down)
        # Полная и чистая уборка за собой при остановке
        ip rule del not fwmark 255 table 100 pref 20 2>/dev/null
        if [ ! -z "$SERVER_IP" ]; then
            ip rule del to "$SERVER_IP" table main pref 10 2>/dev/null
        fi
        for net in $LOCAL_BYPASS_NETS; do
            ip rule del to "$net" table main pref 10 2>/dev/null
        done
        ip route flush table 100 2>/dev/null

        # Восстанавливаем исходные значения rp_filter
        if [ -f "$RP_FILTER_BAK" ]; then
            . "$RP_FILTER_BAK"
            sysctl -w net.ipv4.conf.all.rp_filter="${ALL_RP:-1}" 2>/dev/null
            sysctl -w net.ipv4.conf.default.rp_filter="${DEFAULT_RP:-1}" 2>/dev/null
            rm -f "$RP_FILTER_BAK"
        fi

        # **********************************
        # DNS
        # **********************************
        if command -v resolvectl >/dev/null 2>&1; then
            resolvectl revert tun0 2>/dev/null
        elif [ -f /etc/karin-proxy/resolv.conf.bak ]; then
            cp /etc/karin-proxy/resolv.conf.bak /etc/resolv.conf 2>/dev/null
            rm -f /etc/karin-proxy/resolv.conf.bak
        fi
        ;;
esac

# ExecStartPost/ExecStopPost должны завершаться успешно независимо от того,
# какие именно правила уже существовали/отсутствовали к этому моменту —
# иначе systemd может пометить запуск или остановку сервиса как неудачные.
exit 0
