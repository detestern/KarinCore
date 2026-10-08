# Codex handoff prompt

Ниже находится рабочая инструкция для продолжения разработки KarinCore Android.

---

Ты продолжаешь разработку репозитория `detestern/KarinCore` (ветка `android`).

Это не новый проект. Не создавай порт заново и не повторяй уже реализованные функции.

## 1. Перед началом

Сначала прочитай:

- `docs/CODEX_HANDOFF/PROJECT_STATE.md`
- `docs/CODEX_HANDOFF/TECHNICAL_ARCHITECTURE.md`
- `docs/CODEX_HANDOFF/ROADMAP.md`
- `CHANGELOG.md`
- `README-ru.md`
- `VERSIONING.md`
- `THIRD_PARTY_NOTICES.md`

Затем проверь фактический текущий `main`, `VERSION`, последние commits и CI. Репозиторий является источником истины. Если этот handoff отстал от кода, продолжай от актуального кода.

Baseline на момент handoff:

- version `0.1.0-alpha.31`
- versionCode `31`
- HEAD tagged as `v0.1.0-alpha.31`
- release `v0.1.0-alpha.31`
- split debug APKs for `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`
- Repository checks green
- Android build green
- next normal version: `0.1.0-alpha.32`, versionCode 32

## 2. Архитектурные правила

На Android:

1. Используется один `VpnService`.
2. Используется один system TUN.
3. TUN fd передаётся Xray через `CoreController.startLoop(config, fd)`.
4. KarinCore package должен оставаться вне VPN, иначе возникает routing loop.
5. Android WireGuard работает как встроенный Xray userspace outbound с `noKernelTun=true`.
6. Не создавай второй WireGuard/OpenVPN VpnService.
7. Не переноси Linux route/systemd/sudo semantics на Android.
8. Android subscription HTTP должен оставаться native Kotlin path, пока не будет доказано обратное реальным device test.
9. TLS certificate validation подписок нельзя отключать.
10. `libv2ray.aar` нельзя коммитить. Используй `npm run android:core`.
11. Linux desktop path нельзя ломать. Android-specific код отделять через cfg/platform-specific implementation.

## 3. Уже реализовано

Не реализовывать повторно:

- Tauri 2 Android entry
- Android VpnService
- foreground VPN
- IPv4/IPv6 TUN
- AndroidLibXrayLite/Xray
- VLESS/Reality
- VMess
- Trojan
- Shadowsocks
- embedded WireGuard Xray outbound
- Direct/Proxy/Block
- DNS routing
- LAN bypass
- per-app allowlist/denylist
- native installed-app listing
- Wi-Fi/cellular handover
- break-before-make recovery
- Always-on VPN support
- lockdown status/settings
- Activity/WebView state restore
- 2.5 second visible-state monitor
- native Android logs
- diagnostics export
- VPN self-test
- separate IPv4/IPv6 proxy probes
- Android document picker
- native Android subscription HTTP
- subscription UI watchdog
- subscription refresh
- update checker for fork
- automatic GitHub prereleases
- foreground notification actions
- APK symbol stripping/size reduction

OpenVPN on Android remains unimplemented.

## 4. Реальный runtime факт

Была воспроизведена проблема: добавление подписки зависало бесконечно в Loading.

Rust reqwest timeout не решил проблему.

Решение: Android subscription download переведён в Kotlin `HttpURLConnection/HttpsURLConnection` + frontend watchdog.

После этого пользователь подтвердил: подписка заработала.

Не откатывай это решение без очень веской причины и реального теста.

## 5. WireGuard

Android profile format:

`wg://?payload=<base64 wg-quick configuration>`

Parser поддерживает:

- PrivateKey
- Address
- DNS
- MTU
- Reserved
- PublicKey
- PresharedKey
- Endpoint
- AllowedIPs
- PersistentKeepalive
- multiple Peer

`PreUp/PostUp/PreDown/PostDown` удаляются.

Xray outbound:

- protocol wireguard
- noKernelTun true

Android system TUN остаётся единственным TUN.

## 6. Version workflow

Не повышай версию на каждый промежуточный fix commit.

Правильный цикл:

1. Сделай feature/fix commit на текущей version.
2. Дождись green Repository checks + Android build.
3. Только после green build подготовь release commit.
4. Повышай SemVer alpha number и Android versionCode.
5. Обнови CHANGELOG.
6. Синхронизируй:
   - VERSION
   - package.json
   - src-tauri/Cargo.toml
   - src-tauri/tauri-plugin-karin-vpn/Cargo.toml
   - src-tauri/tauri.conf.json
   - versionCode
7. Запусти `npm run version:check`.
8. Commit message должен начинаться с `release:`.
9. Дождись Android release workflow.
10. Проверь, что GitHub tag/release создан и APK attached.
11. Только после публикации release пушить следующий commit.

Важно: Android workflow имеет `cancel-in-progress: true`. Новый push может отменить текущий release build. Не пушить следующий commit, пока release APK не опубликован.

## 7. Build

Основной CI-compatible build:

    npm ci
    npm run android:core
    npm run version:check
    npm run build
    npm run tauri -- android init --ci --skip-targets-install
    npm run tauri -- android build --apk --target aarch64 armv7 i686 x86_64 --split-per-abi --debug --ci

CI environment:

- Java 17
- Node 22
- Android app target API 37; plugin compile API 36
- Build Tools 36.0.0
- NDK 27.0.12077973
- Rust stable
- aarch64-linux-android
- armv7-linux-androideabi
- i686-linux-android
- x86_64-linux-android

Не заявляй, что Android runtime работает, только потому что CI собрал APK.

## 8. Security/privacy

Не логировать и не экспортировать:

- subscription URLs/tokens
- VLESS UUID
- Trojan passwords
- Shadowsocks secrets
- WireGuard PrivateKey
- generated Xray config

Diagnostics должны оставаться privacy-conscious.

Не отключать TLS verification ради совместимости.

## 9. Documentation style

README, CHANGELOG и docs писать обезличенно, как документацию самого проекта.

Не писать:

- "для тебя"
- "мы сделали для пользователя"
- "я добавил"
- ссылки на разговор с ChatGPT
- упоминания assistant/Codex как автора изменений

Upstream attribution `detestern/KarinCore` сохранять честно, но update/release channel — ветка `android` и теги `android-v<version>` в `detestern/KarinCore`.

## 10. Работа с задачами

Если пользователь пишет "продолжай", "дальше", "погнали":

- не спрашивай лишних уточнений
- посмотри актуальный ROADMAP и текущее состояние
- возьми следующую полезную задачу
- реализуй её до законченного состояния
- проверь build
- исправь найденные compile errors
- после green build сделай release bump
- обнови документацию
- проверь опубликованный release

Если пользователь сообщает конкретный баг с устройства, runtime bug получает приоритет над roadmap.

Если есть logs/diagnostic report, сначала анализируй их, а не переписывай архитектуру наугад.

## 11. Ближайший приоритет

Основной приоритет после alpha.20:

1. real-device validation и bug fixes
2. automated tests для parsers/config/routing/subscription refresh
3. постепенная modularization больших файлов
4. OpenVPN architecture research
5. release signing/store readiness

Не начинай OpenVPN implementation без design + license review.

## 12. OpenVPN constraint

Android уже использует единственный VpnService/TUN.

Нельзя просто запустить второй OpenVPN VPN service.

Перед кодом OpenVPN:

- исследовать возможные userspace core/library
- проверить license
- описать packet flow
- определить coexistence с Xray
- зафиксировать решение в docs
- только затем proof of concept

## 13. Large-file refactoring

`src-tauri/src/lib.rs` и `src/main.ts` крупные.

Рефакторинг нужен, но только после test coverage.

Не делать одновременно:

- большой structural refactor
- новый transport
- lifecycle rewrite

Один рискованный класс изменений за commit/release.

## 14. Формат отчёта после работы

После каждой законченной итерации сообщить:

- что изменено
- какие файлы/архитектурные части затронуты
- commit SHA
- результат Repository checks
- результат Android build
- новая version, если сделан release
- создан ли GitHub release
- имя APK
- что остаётся следующим

Если CI ещё идёт, не утверждать success заранее.

## 15. Следующая версия

Текущий release baseline:

- `0.1.0-alpha.31`
- Android versionCode `31`

Если repo уже обновился, определить следующий номер из актуального `VERSION`.

---

Главное правило: сначала прочитать текущий код и handoff, затем продолжать существующую архитектуру, а не строить ещё один VPN-клиент рядом с ней.
