#!/usr/bin/env bash
# Скачивает то, что установщик Windows кладёт рядом со службой KarinCore:
# xray.exe и wintun.dll из официального релиза Xray-core и geo-базы Loyalsoldier
# (те же, что качает Linux-версия). Версии и SHA-256 закреплены: при несовпадении сборка падает.
#
# Результат: src-tauri/windows/core/ (в git не попадает). Запуск из корня репозитория:
#   ./scripts/fetch-windows-core.sh
set -euo pipefail

XRAY_VERSION="26.10.21"
XRAY_ZIP_SHA256="fc58c39ee2f2717b4c54d28d374362389e5319b20ae44aea76ea45a5243ec827"
GEO_RELEASE="202610212206"
GEOIP_SHA256="4a1b1eddabf5614fa51dd93ac0498856cb82dd65933cd6d6d5890d8c7bb5e902"
GEOSITE_SHA256="77cc7cc99d8a6f606a8c266308501e26fd7038b9c0508db0e551b933c41cdedf"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/src-tauri/windows/core"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PY="$(command -v python3 || command -v python)"

fetch() { # url file sha256
    curl -fsSL --retry 3 -o "$2" "$1"
    local got
    got="$("$PY" -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$2")"
    if [ "$got" != "$3" ]; then
        echo "SHA-256 не совпадает для $1: $got (ожидался $3)" >&2
        exit 1
    fi
}

fetch "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-windows-64.zip" "$TMP/xray.zip" "$XRAY_ZIP_SHA256"
fetch "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${GEO_RELEASE}/geoip.dat" "$TMP/geoip.dat" "$GEOIP_SHA256"
fetch "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${GEO_RELEASE}/geosite.dat" "$TMP/geosite.dat" "$GEOSITE_SHA256"

rm -rf "$OUT"
mkdir -p "$OUT"
"$PY" - "$TMP/xray.zip" "$OUT" <<'PYEOF'
import sys, zipfile
src, out = sys.argv[1], sys.argv[2]
want = {"xray.exe": "xray.exe", "wintun.dll": "wintun.dll", "LICENSE": "LICENSE-Xray", "LICENSE-Wintun": "LICENSE-Wintun"}
with zipfile.ZipFile(src) as z:
    for name, target in want.items():
        with z.open(name) as f, open(f"{out}/{target}", "wb") as o:
            o.write(f.read())
PYEOF
cp "$TMP/geoip.dat" "$TMP/geosite.dat" "$OUT/"
echo "Xray ${XRAY_VERSION} и geo-базы ${GEO_RELEASE}: $OUT"
ls -l "$OUT"
