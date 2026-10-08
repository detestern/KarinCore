# KarinCore Android: project state

## 1. Идентификация проекта

KarinCore Android является Android-портом проекта `detestern/KarinCore`.

Текущий репозиторий:

- GitHub: `detestern/KarinCore` (ветка `android`)
- Основная ветка: `main`
- Текущая версия: `0.1.0-alpha.31`
- Android `versionCode`: `31`
- Release code baseline: tag `v0.1.0-alpha.31`
- База upstream: KarinCore 1.3.7
- Upstream commit: `b7fea2e2ff5e1492fd863381985fdebb4da7a57e`
- Package ID: `com.nikitahya.karincore`
- Android minSdk: 24
- Выпускаемые ABI: `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`

Версия `v0.1.0-alpha.31` опубликована как GitHub prerelease. Release содержит отдельный debug APK для каждого поддерживаемого ABI, устойчивое определение Android/version metadata и исправленную однопанельную страницу «О проекте».

## 2. Технологический стек

Frontend:

- TypeScript
- Vite
- HTML/CSS
- Tauri API

Shared/backend:

- Rust 2021
- Tauri 2
- serde / serde_json
- url
- tokio
- base64
- reqwest

Android:

- Kotlin
- Android `VpnService`
- foreground service
- Tauri Android plugin `tauri-plugin-karin-vpn`
- AndroidLibXrayLite
- Xray-core

Закреплённая библиотека Xray:

- Project: `2dust/AndroidLibXrayLite`
- Version: `v26.9.30`
- SHA-256: `cf71680b776b9ca583747ba652f816b047a655eab875d8951e6141636d88bbd6`
- License: LGPL-3.0
- `libv2ray.aar` не хранится в Git и скачивается `scripts/fetch-libv2ray.sh`.

Upstream KarinCore распространяется по MIT. Оригинальное уведомление сохранено в `LICENSE`.

## 3. Поддерживаемые прокси и транспорты

Android:

- VLESS
- VLESS + Reality
- VMess
- Trojan
- Shadowsocks
- WireGuard через встроенный userspace outbound Xray

Linux upstream path сохранён отдельно через cfg и продолжает использовать существующие desktop-механизмы, включая native WireGuard/OpenVPN/systemd/route scripts.

OpenVPN на Android пока не реализован.

## 4. Android VPN architecture

Android использует ровно один системный `VpnService` и один системный TUN.

Текущая TUN-конфигурация:

- IPv4 address: `172.19.0.2/30`
- IPv4 route: `0.0.0.0/0`
- IPv6 address: `fc00::172:19:0:2/126`
- IPv6 route: `::/0`
- Android DNS server: `1.1.1.1`
- MTU обычно 1500
- Для Android WireGuard profile TUN MTU снижается до 1420

После `VpnService.Builder.establish()` file descriptor передаётся в:

`CoreController.startLoop(configJson, pfd.fd)`

AndroidLibXrayLite сам устанавливает `xray.tun.fd` для Xray-core.

Собственный пакет KarinCore должен оставаться вне VPN. Иначе Xray outbound sockets будут снова захвачены тем же TUN и возникнет routing loop.

## 5. Routing и DNS

Сохранена модель KarinCore:

- Direct
- Proxy
- Block
- configurable default outbound
- configurable zone priority

Android Xray config включает:

- `tun-in` для системного TUN
- `ping-in` на localhost:2082 для принудительной проверки proxy path
- `proxy`
- `direct`
- `block`
- `dns-out`

DNS traffic из `tun-in` на port 53 направляется в `dns-out`.

Локальные адреса направляются в direct. При выключенном Proxy LAN дополнительно исключаются:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `fc00::/7`
- `fe80::/10`

Далее применяются dynamic routing rules и fallback на выбранный default outbound.

## 6. WireGuard на Android

WireGuard не создаёт второй Android VPN и не запускает kernel `wg0`.

Формат профиля:

`wg://?payload=<base64 wg-quick config>`

Android parser поддерживает:

Interface:

- PrivateKey
- Address
- DNS
- MTU
- Reserved

Peer:

- PublicKey
- PresharedKey
- Endpoint
- AllowedIPs
- PersistentKeepalive
- Reserved

Опасные wg-quick directives `PreUp`, `PostUp`, `PreDown`, `PostDown` удаляются.

Для Xray создаётся outbound:

- protocol: `wireguard`
- `noKernelTun: true`
- default AllowedIPs при отсутствии: IPv4 + IPv6 default routes

Это критичный архитектурный инвариант. Нельзя добавлять второй `VpnService` или отдельный системный WireGuard TUN.

## 7. Подписки

Подписки умеют содержать:

- VLESS
- VMess
- Trojan
- Shadowsocks
- WireGuard
- JSON
- plain link list
- Base64 encoded link list
- imported routing
- imported DNS

На Android HTTP transport вынесен в Kotlin `HttpURLConnection`, потому что Rust reqwest path на реальном Android зависал на загрузке одной из подписок.

Native Android subscription transport:

- background executor
- connect timeout до 8 seconds
- read timeout 20 seconds
- UI watchdog 25 seconds
- максимум 5 redirects
- gzip
- response limit 8 MiB
- TLS validation не отключается

Rust после получения текста отвечает за parsing/Base64/routing/DNS.

Начиная с alpha.20 группы подписок сохраняют `sourceUrl` и могут обновляться. При refresh:

- профили сопоставляются по URL
- сохраняются ID существующих профилей
- сохраняется pin state
- новые профили добавляются
- удалённые на сервере профили удаляются из группы
- routing/DNS импортируется повторно
- активный VPN не принудительно разрывается, даже если текущий profile исчез из обновлённой подписки
- неактивный selected profile очищается, если его больше нет

Старые группы без `sourceUrl` продолжают работать, но refresh для них недоступен до повторного добавления подписки.

## 8. Per-app routing

Поддерживаются режимы:

- `all`
- `allowlist` / Only selected
- `denylist` / Bypass selected

Список launcher applications получается через Android PackageManager.

При allowlist используются `addAllowedApplication`.

При denylist используются `addDisallowedApplication`.

KarinCore package нельзя включать в VPN.

Missing/uninstalled package names фильтруются перед establish.

## 9. Lifecycle, handover и Always-on

VpnService работает как foreground service и не зависит от жизни WebView/Activity.

Android P+ отслеживает underlying network через ConnectivityManager.

Поддерживаются:

- Wi-Fi -> cellular handover
- cellular -> Wi-Fi handover
- make-before-break
- break-before-make
- network loss / recovery

При смене upstream network:

- TUN сохраняется
- Xray core перезапускается на том же TUN fd
- debounce 1 second
- до 3 restart attempts
- состояние `reconnecting` доступно frontend

Always-on VPN:

- manifest объявляет `SUPPORTS_ALWAYS_ON=true`
- последний успешно запущенный config сохраняется в app-private SharedPreferences
- Android system start может восстановить VPN после process death/reboot
- Always-on и lockdown считываются из VpnService
- frontend открывает системные VPN Settings
- programmatic enable lockdown не используется
- manual disconnect блокируется, пока system Always-on включён

## 10. Logs, diagnostics и self-test

Android service держит bounded ring buffer на 500 log lines.

Логи включают:

- start/stop
- Xray initialization
- Xray callbacks
- app routing state
- handover
- reconnect
- errors

Logs page умеет:

- показывать native logs
- очищать native logs
- export diagnostics через Android document picker
- запускать VPN self-test

Diagnostic report включает:

- app version
- architecture
- Android version / SDK
- manufacturer / brand / model / device
- Xray version
- running / starting / reconnecting
- Always-on / lockdown
- TUN state
- per-app mode и count
- last error
- native logs

Diagnostic report не должен включать:

- subscription URL
- generated Xray config
- proxy URI
- private keys
- список выбранных package names

Proxy URI log lines редактируются.

Self-test проверяет:

- native service
- Xray
- TUN fd
- reconnect state
- Always-on / lockdown
- per-app mode
- forced HTTPS proxy path
- IPv4 через `https://api4.ipify.org`
- IPv6 через `https://api6.ipify.org`

IPv6 unavailable является warning, а не fail. IPv4 + proxy path обязательны для PASS.

## 11. Foreground notification

Foreground VPN notification:

- использует отдельную monochrome shield icon
- локализованные Android resources
- показывает connection/reconnect/error state
- при выключенном Always-on содержит Disconnect
- при включённом Always-on содержит переход в Android VPN Settings

Service-level ACTION_STOP игнорируется при active Always-on.

## 12. UI state synchronization

Frontend восстанавливает VPN state из native service при запуске Activity/WebView.

Пока Android app visible, native state опрашивается каждые 2.5 seconds.

Polling:

- не запускается параллельно
- выключается, когда app hidden
- UI обновляется только при изменении status signature

Native service является источником истины. Stale frontend marker очищается, если VPN больше не работает.

## 13. Frontend persistent storage

Ключевые localStorage/sessionStorage keys:

- `karin_theme`
- `karin_lang`
- `karin_active_link`
- `karin_selected_profile`
- `karin_allow_server_proxy`
- `karin_allow_proxy_lan`
- `karin_app_routing_mode`
- `karin_app_packages`
- `karin_zone_priority`
- `karin_default_outbound`
- `karin_groups`
- `karin_links`
- `karin_routing`
- `karin_route_profiles`
- `karin_dns_dom`
- `karin_dns_rem`
- `karin_kill_switch` только для desktop semantics
- `karin_show_assistant`

Data models:

- ProxyGroup: id, name, pinned, isOpen, optional sourceUrl
- ProxyLink: id, url, pinned, groupId
- RouteProfile: defaultOutbound, rules, DNS, zonePriority
- RoutingRule: type + value

## 14. Update channel и releases

Android fork обновляется только из:

`detestern/KarinCore` (ветка `android`)

Updater читает `VERSION` из main и сравнивает SemVer с установленной версией, включая alpha/beta.

Ссылка ведёт на exact tag:

`releases/tag/v<version>`

Release automation:

- release commit должен начинаться с `release:`
- Android CI собирает отдельные debug APK для всех четырёх Android ABI
- создаёт tag
- создаёт GitHub prerelease для prerelease SemVer
- берёт release notes из CHANGELOG
- прикладывает APK

Не следует делать новый push, пока release workflow предыдущего release commit не опубликовал release. Workflow имеет `cancel-in-progress: true`.

## 15. CI и build

Repository checks:

- version consistency
- JSON validation

Android build:

- Ubuntu runner
- Java 17
- Node 22
- Android app target API 37; plugin compile API 36
- Build Tools 36.0.0
- NDK 27.0.12077973
- stable Rust
- targets `aarch64-linux-android`, `armv7-linux-androideabi`, `i686-linux-android`, `x86_64-linux-android`
- npm cache
- Rust cache
- Gradle cache
- download pinned Xray AAR
- Tauri Android init
- split debug APKs for all four Android ABIs
- artifact upload
- release publication for release commits

Основные команды:

    npm ci
    npm run android:core
    npm run version:check
    npm run build
    npm run tauri -- android init --ci --skip-targets-install
    npm run tauri -- android build --apk --target aarch64 armv7 i686 x86_64 --split-per-abi --debug --ci

## 16. Versioning

Android port имеет независимую SemVer ветку.

Текущая версия:

`0.1.0-alpha.31`

Следующий обычный prerelease:

`0.1.0-alpha.32`

Следующий versionCode:

`32`

Release bump должен синхронно менять:

1. `VERSION`
2. `package.json`
3. `src-tauri/Cargo.toml`
4. `src-tauri/tauri-plugin-karin-vpn/Cargo.toml`
5. `src-tauri/tauri.conf.json`
6. Android `versionCode`
7. `CHANGELOG.md`
8. README version references при необходимости

Перед release:

`npm run version:check`

## 17. История Android-порта

Краткая карта версий:

- alpha.1: первая Android architecture integration
- alpha.2: первый CI-validated APK
- alpha.3: network handover
- alpha.4: per-app split tunneling
- alpha.5: native Android logs
- alpha.6: mobile UI + Android document export
- alpha.7: runtime hardening / package visibility / break-before-make
- alpha.8: UI state restoration
- alpha.9: Always-on + lockdown integration
- alpha.10: subscription timeouts
- alpha.11: native Android subscription HTTP + UI watchdog
- alpha.12: Android fork updater + automatic GitHub releases
- alpha.13: privacy-safe diagnostics
- alpha.14: foreground notification actions
- alpha.15: VPN self-test
- alpha.16: live UI/native state synchronization
- alpha.17: separate IPv4/IPv6 tests + notification polish
- alpha.18: embedded Xray WireGuard outbound
- alpha.19: APK size reduction from about 230.7 MB to about 73.7 MB
- alpha.20: refreshable subscription groups

Полная история находится в `CHANGELOG.md`.

## 18. Что реально проверено

Проверено CI:

- TypeScript/Vite build
- Rust Android compilation
- Kotlin/Gradle compilation
- Android SDK/NDK path
- Xray AAR download + hash
- complete split debug APKs for all four Android ABIs
- release pipeline

На реальном устройстве подтверждено:

- проблема бесконечного Loading при добавлении подписки была воспроизведена
- после перехода на native Android HTTP в alpha.11 загрузка подписки заработала

Не следует утверждать, что остальные runtime-сценарии проверены на реальном устройстве, пока нет фактического теста.

## 19. Не завершено / риски

Основные незакрытые области:

- OpenVPN transport/chaining на Android
- полная real-device regression matrix
- WireGuard real-device validation
- Always-on + lockdown + reboot на разных OEM
- IPv6 real-device leak/route validation
- per-app routing на разных Android/OEM
- release signing
- production/release APK/AAB
- additional ABI runtime validation
- store readiness
- automated unit/integration tests
- крупные файлы `src-tauri/src/lib.rs` и `src/main.ts` требуют постепенной модульной декомпозиции

## 20. Критичные инварианты

Эти правила нельзя менять без отдельного архитектурного решения:

1. На Android только один системный `VpnService`.
2. На Android только один системный TUN.
3. Xray получает существующий TUN fd.
4. Собственный package KarinCore не должен попадать в TUN.
5. WireGuard на Android работает как Xray userspace outbound с `noKernelTun=true`.
6. Не отключать TLS certificate validation для подписок.
7. Не возвращать Android subscription download обратно на Rust reqwest без доказанного runtime-теста.
8. Не коммитить `libv2ray.aar`.
9. Не ломать Linux path при Android изменениях. Использовать platform cfg.
10. Не писать private keys, subscription URLs и proxy URIs в diagnostics/log exports.
11. Не утверждать real-device validation без фактической проверки.
12. Документация репозитория должна быть обезличенной и написана от лица проекта.
