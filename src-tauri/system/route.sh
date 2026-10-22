#!/bin/bash
RP_FILTER_BAK="/etc/karin-proxy/rp_filter.bak"
LOCAL_BYPASS_NETS="127.0.0.0/8 10.0.0.0/8 192.168.0.0/16"
LOCAL_BYPASS_NETS6="fc00::/7 fe80::/10"
DNS_LINKS_BAK="/run/karin-proxy/dns-domains.bak"

# systemd-resolved отправляет запрос ВО ВСЕ интерфейсы с самым подходящим доменом. Если у другого
# интерфейса (провайдер, локальная сеть, корпоративный VPN) тоже есть корневой домен "~.", он получает
# те же запросы параллельно с туннелем: имена сайтов утекают к чужому DNS. Поэтому на время работы
# туннеля "~." снимается с остальных интерфейсов, а при остановке возвращается как было.
# Остальные домены интерфейсов (например, корпоративный поиск) не трогаем.
dns_take_root_route() {
    mkdir -p /run/karin-proxy 2>/dev/null
    : > "$DNS_LINKS_BAK"
    local line name doms rest d
    resolvectl domain 2>/dev/null | while IFS= read -r line; do
        case "$line" in "Link "*) ;; *) continue ;; esac
        name=${line#*\(}; name=${name%%\)*}
        [ "$name" = "tun0" ] && continue
        doms=${line#*\):}
        rest=""
        case " $doms " in *" ~. "*) ;; *) continue ;; esac
        for d in $doms; do [ "$d" = "~." ] || rest="$rest $d"; done
        printf '%s\t%s\n' "$name" "$doms" >> "$DNS_LINKS_BAK"
        # Пустой список передаётся как "": без аргументов resolvectl только показывает значение.
        if [ -n "$rest" ]; then resolvectl domain "$name" $rest 2>/dev/null; else resolvectl domain "$name" "" 2>/dev/null; fi
    done
}

dns_return_root_route() {
    [ -f "$DNS_LINKS_BAK" ] || return 0
    local name doms
    while IFS=$'\t' read -r name doms; do
        [ -n "$name" ] && resolvectl domain "$name" $doms 2>/dev/null
    done < "$DNS_LINKS_BAK"
    rm -f "$DNS_LINKS_BAK"
}

# Адрес сервера берём из первого outbound'а: vless/vmess хранят его в settings.vnext[0],
# trojan и shadowsocks — в settings.servers[0]. В режимах OpenVPN/WireGuard такого поля нет — тогда пусто.
SERVER_ADDR=$(python3 - <<'PY' 2>/dev/null
import json
cfg = json.load(open('/etc/karin-proxy/config.json'))
settings = cfg['outbounds'][0].get('settings', {})
entry = (settings.get('vnext') or settings.get('servers') or [{}])[0]
print(entry.get('address', ''))
PY
)

# Если вместо IP указан домен, резолвим его в чистый IP (IPv4 или IPv6)
if [[ "$SERVER_ADDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$SERVER_ADDR" == *:* ]]; then
    SERVER_IP="$SERVER_ADDR"
elif [ -n "$SERVER_ADDR" ]; then
    SERVER_IP=$(getent ahosts "$SERVER_ADDR" | awk '{print $1}' | head -n 1)
else
    SERVER_IP=""
fi

# Для адреса сервера выбираем нужное семейство `ip`
if [[ "$SERVER_IP" == *:* ]]; then
    SERVER_IP_CMD="ip -6"
else
    SERVER_IP_CMD="ip"
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

        # IPv6 внутри туннеля: приватный адрес /126 и свой default в той же таблице 100
        ip -6 addr add fd00:19::2/126 dev tun0 2>/dev/null
        ip -6 route add default dev tun0 table 100 2>/dev/null

        # 3. Базовые правила-исключения локальной сети
        for net in $LOCAL_BYPASS_NETS; do
            ip rule add to "$net" table main pref 10 2>/dev/null
        done

        for net in $LOCAL_BYPASS_NETS6; do
            ip -6 rule add to "$net" table main pref 10 2>/dev/null
        done

        # Исключаем IP сервера из проксирования, чтобы не было петли
        if [ ! -z "$SERVER_IP" ]; then
            $SERVER_IP_CMD rule add to "$SERVER_IP" table main pref 10 2>/dev/null
        fi

        # 4. Главное правило: весь остальной трафик — в туннель (оба семейства адресов)
        ip rule add not fwmark 255 table 100 pref 20 2>/dev/null
        ip -6 rule add not fwmark 255 table 100 pref 20 2>/dev/null

        # **********************************
        # DNS
        # **********************************
        if command -v resolvectl >/dev/null 2>&1; then
            resolvectl dns tun0 127.0.0.1 2>/dev/null
            resolvectl domain tun0 "~." 2>/dev/null
            resolvectl default-route tun0 yes 2>/dev/null
            # Имена из одного слова не должны уходить мультикастом в туннель.
            resolvectl llmnr tun0 no 2>/dev/null
            resolvectl mdns tun0 no 2>/dev/null
            dns_take_root_route
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
        ip -6 rule del not fwmark 255 table 100 pref 20 2>/dev/null
        if [ ! -z "$SERVER_IP" ]; then
            $SERVER_IP_CMD rule del to "$SERVER_IP" table main pref 10 2>/dev/null
        fi
        for net in $LOCAL_BYPASS_NETS; do
            ip rule del to "$net" table main pref 10 2>/dev/null
        done
        for net in $LOCAL_BYPASS_NETS6; do
            ip -6 rule del to "$net" table main pref 10 2>/dev/null
        done
        ip route flush table 100 2>/dev/null
        ip -6 route flush table 100 2>/dev/null

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
            dns_return_root_route
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
