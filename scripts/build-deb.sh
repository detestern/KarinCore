#!/usr/bin/env bash
set -euo pipefail

# Tauri v2 пока не умеет добавлять postinst/postrm в .deb (см.
# https://github.com/tauri-apps/tauri/issues/8993). Этот скрипт запускается
# ПОСЛЕ `npm run tauri build -- --bundles deb` и дошивает maintainer-скрипты
# в уже собранный пакет через dpkg-deb -R / -b.
#
# Использование:
#   npm run tauri build -- --bundles deb
#   ./scripts/build-deb.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEB_DIR="$REPO_ROOT/src-tauri/target/release/bundle/deb"

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "Не найден dpkg-deb. Скрипт нужно запускать на Debian/Ubuntu-подобной системе." >&2
    exit 1
fi

DEB_FILE="$(ls "$DEB_DIR"/*.deb 2>/dev/null | head -n1 || true)"
if [ -z "$DEB_FILE" ]; then
    echo "Не найден .deb в $DEB_DIR — сначала выполни: npm run tauri build -- --bundles deb" >&2
    exit 1
fi

echo "Патчу: $DEB_FILE"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

dpkg-deb -R "$DEB_FILE" "$WORKDIR"

install -m 0755 "$REPO_ROOT/src-tauri/system/postinst" "$WORKDIR/DEBIAN/postinst"
install -m 0755 "$REPO_ROOT/src-tauri/system/postrm" "$WORKDIR/DEBIAN/postrm"

# Сохраняем владельца root:root у файлов пакета — иначе без fakeroot
# systemd-юнит и sudoers-файл упакуются с uid текущего пользователя.
if command -v fakeroot >/dev/null 2>&1; then
    fakeroot dpkg-deb -b "$WORKDIR" "$DEB_FILE"
else
    echo "ВНИМАНИЕ: fakeroot не найден, владелец файлов в пакете может быть некорректным." >&2
    echo "Установи fakeroot (sudo apt install fakeroot) для чистой сборки." >&2
    dpkg-deb -b "$WORKDIR" "$DEB_FILE"
fi

echo "Готово: $DEB_FILE теперь содержит postinst/postrm"
