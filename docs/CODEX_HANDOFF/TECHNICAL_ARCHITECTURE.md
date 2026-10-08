# KarinCore Android: technical architecture

## 1. Общая схема

    TypeScript / Vite UI
            |
            | Tauri invoke
            v
    Rust shared application core
            |
            +-------------------- Linux --------------------+
            | systemd / sudo / route.sh / system Xray      |
            | wg-quick / OpenVPN                            |
            +-----------------------------------------------+
            |
            +------------------- Android -------------------+
              tauri-plugin-karin-vpn (Rust bridge)
                            |
                     KarinVpnPlugin.kt
                            |
                     KarinVpnService.kt
                            |
                       Android TUN
                            |
                  AndroidLibXrayLite
                            |
                       Xray-core

Shared Rust отвечает за:

- parsing proxy links
- subscription parsing
- routing conversion
- DNS config
- Xray config generation
- WireGuard payload parsing on Android
- diagnostics
- proxy-path probes

Kotlin отвечает за Android platform integration:

- VPN permission
- foreground service
- TUN creation
- package routing
- underlying network tracking
- Always-on state
- notification
- document picker
- installed apps
- native subscription HTTP
- device information
- native log storage

## 2. Основные файлы

`src/main.ts`

Главный frontend controller. Содержит UI state, profiles/groups, subscriptions, routing editor, per-app settings, updater, diagnostics/self-test и Android state monitor.

`src/i18n.ts`

UI translations.

`src/styles.css`

Desktop + Android responsive styles.

`src-tauri/src/lib.rs`

Главный Rust application core. Содержит shared proxy parsing/config generation, desktop implementation и Android cfg implementation.

`src-tauri/src/main.rs`

Desktop binary entry calling library `run()`.

`src-tauri/tauri-plugin-karin-vpn/src/lib.rs`

Rust API bridge для Android plugin.

`src-tauri/tauri-plugin-karin-vpn/src/models.rs`

Serializable request/result models между Rust и Kotlin.

`src-tauri/tauri-plugin-karin-vpn/android/src/main/java/KarinVpnPlugin.kt`

Tauri mobile plugin entry. Commands: prepare/start/stop/status, list apps, fetch text, document save, logs, settings, device info.

`src-tauri/tauri-plugin-karin-vpn/android/src/main/java/KarinVpnService.kt`

Android VPN runtime.

`scripts/fetch-libv2ray.sh`

Скачивает pinned AAR и проверяет SHA-256.

`scripts/check-version.py`

Проверяет согласованность версии.

`.github/workflows/android-build.yml`

Android APK + GitHub release pipeline.

## 3. Connect flow на Android

1. Frontend выбирает profile и собирает UI routing/DNS/per-app state.
2. `invoke('start_proxy', ...)` вызывает Android Rust command.
3. Rust отклоняет `ovpn://`, пока Android OpenVPN не реализован.
4. Rust вызывает native VPN prepare.
5. Rust создаёт proxy outbound:
   - VLESS/VMess/Trojan/SS через shared `build_proxy_outbound`
   - WireGuard через `build_android_wireguard_outbound`
6. Rust строит DNS config.
7. Rust строит Xray routing rules.
8. Rust создаёт Android Xray config с `tun-in` + `ping-in`.
9. Rust вызывает plugin `start(StartRequest)`.
10. Kotlin запускает foreground `KarinVpnService`.
11. Service создаёт TUN через `VpnService.Builder`.
12. Service применяет per-app routing.
13. Service вызывает `controller.startLoop(configJson, pfd.fd)`.
14. Plugin ждёт до 12 seconds состояния `running && coreRunning`.
15. Успешный native config сохраняется для Always-on restore.
16. Frontend получает success и обновляет state.

## 4. Disconnect flow

Обычный режим:

1. Frontend вызывает `stop_proxy`.
2. Kotlin plugin отправляет ACTION_STOP.
3. Service останавливает Xray.
4. Service закрывает TUN.
5. Сбрасывается runtime state.
6. Persisted connection очищается.

Always-on:

- manual stop отклоняется
- frontend показывает необходимость отключить Always-on в Android VPN Settings
- notification вместо Disconnect показывает VPN Settings

## 5. Android TUN

Builder:

    setSession("KarinCore")
    setMtu(mtu)
    addAddress("172.19.0.2", 30)
    addRoute("0.0.0.0", 0)
    addAddress("fc00::172:19:0:2", 126)
    addRoute("::", 0)
    addDnsServer("1.1.1.1")

Android Q+ дополнительно может mark network as not metered.

Сам KarinCore package исключается из VPN, кроме allowlist semantics, где он просто никогда не добавляется в allowed apps.

## 6. Xray config на Android

Основные inbound:

`tun-in`

- protocol `tun`
- name `xray0`
- MTU соответствует Android TUN

`ping-in`

- protocol `mixed`
- localhost:2082
- account with generated token
- routing rule всегда отправляет traffic в `proxy`

Это позволяет self-test и IP probes гарантированно проверять именно proxy outbound, а не default routing.

Основные outbound:

- `proxy`
- `direct`
- `block`
- `dns-out`

## 7. WireGuard design

Android WireGuard использует Xray outbound. Это позволяет сохранить один Android TUN.

Input:

`wg://?payload=<base64 wg-quick config>`

Parser:

- декодирует standard/base64url, padded/unpadded
- удаляет executable directives
- парсит Interface/Peer
- валидирует обязательные fields
- поддерживает multiple peers

Xray settings:

- secretKey
- address
- peers
- noKernelTun = true
- mtu
- remoteDNS
- optional reserved

Не следует переносить Linux `wg-quick` implementation на Android.

## 8. Subscription architecture

Desktop:

Rust reqwest.

Android:

Kotlin native HTTP -> Rust parser.

Причина разделения: реальный Android runtime показал бесконечный Loading при Rust HTTP path, даже после timeout configuration. Native Android HTTP исправил проблему.

Kotlin fetch bridge не должен блокировать UI thread.

Frontend дополнительно использует 25 second watchdog, чтобы кнопка не могла навсегда остаться в Loading.

TLS verification обязательна.

## 9. Network handover

Service регистрирует `ConnectivityManager.NetworkCallback`.

При появлении нового underlying network:

- обновляет `setUnderlyingNetworks`
- debounce
- останавливает Xray loop
- не закрывает TUN
- запускает Xray снова на прежнем fd
- до 3 attempts

При loss current upstream state отмечается, чтобы восстановить break-before-make case.

## 10. Always-on persistence

App-private SharedPreferences сохраняют:

- generated config JSON
- MTU
- app routing mode
- app packages

Persist выполняется только после успешного start.

При user-requested profile change старый persisted config очищается до запуска нового, чтобы system restart не воскресил старый profile после failed switch.

При revoke VPN permission persistence очищается.

## 11. Per-app semantics

`all`

- KarinCore package disallowed
- остальные apps идут в VPN

`allowlist`

- выбранные apps добавляются allowed
- KarinCore не добавляется
- пустой allowlist запрещён

`denylist`

- KarinCore disallowed
- selected apps disallowed

Package names проверяются через PackageManager.

## 12. Frontend profile/subscription model

ProxyGroup:

- id
- name
- pinned
- isOpen
- optional sourceUrl

ProxyLink:

- id
- url
- pinned
- groupId

alpha.20 refresh сохраняет identity существующего profile по URL.

Важно: profile ID используется UI. Нельзя при refresh без необходимости пересоздавать ID всех links, иначе pin/selection state будет прыгать.

## 13. Runtime state model

Native status:

- running
- starting
- coreRunning
- reconnecting
- alwaysOn
- lockdown
- appRoutingMode
- appPackageCount
- tunFd
- coreVersion
- lastError

Frontend опрашивает status каждые 2.5 seconds только когда visible.

Native status является authoritative.

## 14. Diagnostics security

Diagnostic exporter должен считать любые proxy URI и subscription URLs секретными.

Нельзя добавлять в export:

- VLESS UUID
- WireGuard PrivateKey
- Trojan password
- Shadowsocks credentials
- subscription token/URL
- generated Xray config

При расширении logs необходимо учитывать последующий export.

## 15. Update/release design

Updater не использует upstream.

Source:

`detestern/KarinCore/android/VERSION`

Version comparator поддерживает prerelease.

Release URL:

`detestern/KarinCore/releases/tag/android-v<version>`

CI публикует release только для commit message, начинающегося с `release:`.

Следующий push может отменить предыдущий Android workflow из-за concurrency. Поэтому после release commit необходимо дождаться публикации release before next push.

## 16. APK size

До alpha.19 debug APK был около 230.7 MB.

alpha.19:

- Cargo dev debug info = 0
- strip = symbols
- debug signing сохранён
- libkarin_proxy_lib.so уменьшился примерно 170.5 -> 20.7 MB
- APK уменьшился примерно 230.7 -> 73.7 MB
- libgojni.so около 34.3 MB и остаётся крупнейшей native library

Не следует возвращать native debug symbols в обычные test APK без причины.

## 17. Platform separation

При Android изменениях desktop/Linux behavior должен оставаться неизменным.

Используются:

- `#[cfg(target_os = "android")]`
- `#[cfg(not(target_os = "android"))]`

Android `reqwest` использует rustls.

Desktop `reqwest` использует native-tls/system-proxy.

`rfd` desktop-only.

## 18. Текущий technical debt

`src-tauri/src/lib.rs` и `src/main.ts` стали крупными монолитными файлами.

Рекомендуется постепенная модульная декомпозиция после стабилизации behavior, с тестами до рефакторинга.

Возможное разделение Rust:

- protocols/
- subscriptions/
- routing/
- dns/
- android/
- desktop/
- diagnostics/

Frontend:

- state/
- profiles/
- subscriptions/
- routing/
- android/
- diagnostics/
- updater/

Не выполнять большой рефакторинг одновременно с новым transport feature.
