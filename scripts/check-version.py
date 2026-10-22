#!/usr/bin/env python3
"""Проверяет, что номер версии Windows-сборки один и тот же во всех файлах.

Источник истины — файл VERSION. Скрипт запускает CI (windows-build.yml);
локально: python3 scripts/check-version.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


expected = read("VERSION").strip()
if not re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?", expected):
    raise SystemExit(f"VERSION is not a semver version: {expected!r}")

found: dict[str, list[str]] = {}

found["package.json"] = [json.loads(read("package.json"))["version"]]
lock = json.loads(read("package-lock.json"))
found["package-lock.json"] = [lock.get("version", ""), lock.get("packages", {}).get("", {}).get("version", "")]
found["src-tauri/tauri.conf.json"] = [json.loads(read("src-tauri/tauri.conf.json"))["version"]]

cargo = re.search(r'(?ms)^\[package\].*?^version\s*=\s*"([^"]+)"', read("src-tauri/Cargo.toml"))
found["src-tauri/Cargo.toml"] = [cargo.group(1) if cargo else ""]
cargo_lock = re.search(r'name = "karin-proxy"\nversion = "([^"]+)"', read("src-tauri/Cargo.lock"))
found["src-tauri/Cargo.lock"] = [cargo_lock.group(1) if cargo_lock else ""]

found["index.html"] = re.findall(r'<div class="app-version-text">v ([^<]+)</div>', read("index.html")) or [""]
found["src/main.ts"] = re.findall(r'const CURRENT_VERSION = "([^"]+)";', read("src/main.ts")) or [""]

# about_version во всех локалях содержит номер версии.
about = re.findall(r'about_version: "([^"]*)"', read("src/i18n.ts"))
found["src/i18n.ts about_version"] = [
    m.group(0) if (m := re.search(r"\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?", a)) else "" for a in about
] or [""]

if f"## [{expected}]" not in read("CHANGELOG-windows.md"):
    found["CHANGELOG-windows.md"] = ["(no section)"]

bad = {path: vals for path, vals in found.items() if any(v != expected for v in vals)}
if bad:
    print(f"Expected version: {expected}", file=sys.stderr)
    for path, vals in bad.items():
        print(f"  {path}: {', '.join(vals)}", file=sys.stderr)
    raise SystemExit(1)

print(f"Version OK: {expected}")
