<div align="center">
<img src="src-tauri/icons/icon.png" alt="KarinCore" width="160"/>
<h1>KarinCore Android</h1>
<p><strong>Прокси-клиент KarinCore для телефона — красивый, приватный, на нативном VPN Android</strong></p>
<p>
<a href="README.md">🇬🇧 English</a> | <a href="README-ru.md">🇷🇺 Русский</a>
</p>

<p>
<img src="https://img.shields.io/badge/version-0.1.0--alpha.32-dc8add?style=flat-square&labelColor=11111b" alt="Version"/>
<img src="https://img.shields.io/badge/platform-android-dc8add?style=flat-square&labelColor=11111b&logo=android&logoColor=dc8add" alt="Platform"/>
<img src="https://img.shields.io/badge/built_with-rust-dc8add?style=flat-square&labelColor=11111b&logo=rust&logoColor=dc8add" alt="Built with Rust"/>
<img src="https://img.shields.io/badge/framework-tauri-dc8add?style=flat-square&labelColor=11111b&logo=tauri&logoColor=dc8add" alt="Tauri"/>
<img src="https://img.shields.io/badge/license-MIT-dc8add?style=flat-square&labelColor=11111b" alt="License"/>
</p>
</div>

<br/>

> **Альфа.** Это Android-ветка [KarinCore](https://github.com/detestern/KarinCore); десктопный клиент для Linux находится в [`main`](https://github.com/detestern/KarinCore). Android-сборки — ранние тестовые, они публикуются как пре-релизы с тегами `android-v…`.

## Что это

KarinCore Android переносит на Android тот же интерфейс и ту же модель маршрутизации Direct / Proxy / Block, что и в клиенте для Linux. Внутри работает [Xray-core](https://github.com/XTLS/Xray-core) поверх нативного `VpnService` Android, поэтому VPN действует на всё устройство и не требует root.

## Возможности

- **VPN на всё устройство** через `VpnService`, в foreground-сервисе, который переживает закрытие приложения; при переключении Wi-Fi ↔ мобильная сеть ядро перезапускается на месте.
- **Протоколы:** VLESS (Reality), VMess, Trojan, Shadowsocks и WireGuard (`wg://`).
- **Подписки:** добавь URL — серверы появятся группой, обновить её можно одним нажатием.
- **Профили маршрутизации из подписок:** маршрутизация, которую отдаёт подписка (заголовки Happ / V2RayTun, полные JSON-подписки), сохраняется отдельным профилем с именем провайдера. Выбери его кнопкой **«Выбрать»** — твои правила и DNS сами никогда не заменяются.
- **Зоны Direct / Proxy / Block** с правилами по доменам, `geosite` и `geoip`, приоритетом зон и своим DNS (DoH или обычный). `geoip.dat` и `geosite.dat` уже внутри, отдельно качать не нужно.
- **Раздельное туннелирование по приложениям:** все приложения, только выбранные или все, кроме выбранных.
- **Виджет на рабочем столе** — включает и выключает последний рабочий профиль одним нажатием.
- **Always-on VPN**, встроенная самопроверка VPN и живая диагностика разрешений и ограничений батареи.
- **Приватность:** никакой телеметрии разработчика; профили и URL подписок шифруются ключом из Android Keystore.

## Установка

1. Открой [Releases](https://github.com/detestern/KarinCore/releases) и выбери свежий релиз с тегом `android-v…` (он помечен *Pre-release*; «Latest» остаётся за релизами Linux-версии).
2. Скачай APK под своё устройство:

| APK | Для чего |
|---|---|
| `…-arm64-v8a-debug.apk` | Почти все современные телефоны и планшеты — **начни с него** |
| `…-armeabi-v7a-debug.apk` | Старые 32-битные ARM-устройства |
| `…-x86_64-debug.apk` / `…-x86-debug.apk` | Эмуляторы, Chromebook, устройства на Intel |

3. Открой файл и разреши установку из браузера или файлового менеджера, когда Android спросит.
4. Запусти KarinCore, добавь ссылку или подписку, нажми на ядро и разреши запрос VPN.

Альфа-сборки подписаны debug-ключом, поэтому Android или Play Protect могут показать предупреждение, а обновления ставятся вручную: страница **«О программе»** подскажет, что вышла новая версия. Если ты ставил прошлые тестовые сборки Android-порта, сначала удали их — это отдельное приложение, поверх оно не обновится.

## Советы для стабильной работы

- Разреши уведомления: Android держит VPN живым только при уведомлении foreground-сервиса.
- Исключи KarinCore из оптимизации батареи (Настройки → *Разрешения и стабильность*: приложение само проверяет это и открывает нужные экраны).
- Чтобы добавить виджет, сначала один раз нормально подключись, затем выбери **KarinCore VPN switch** в списке виджетов лаунчера.

## Сборка из исходников

Нужны Rust, Node.js 22, Android Studio (SDK, Build Tools, NDK 27) и JDK 17.

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

git clone -b android https://github.com/detestern/KarinCore.git
cd KarinCore

npm ci
npm run android:core    # скачивает закреплённую библиотеку Xray и проверяет SHA-256
npm run android:init
npm run android:dev     # или: npm run tauri -- android build --apk --debug
```

Подробности — архитектура, подпись, версии, процесс релиза — в [заметках разработчика](docs/DEVELOPMENT-ru.md).

## Документация

- [Политика конфиденциальности](PRIVACY.md)
- [Совместимость и известные ограничения](docs/COMPATIBILITY.md)
- [Обновление и переход на постоянную подпись](docs/UPGRADING.md)
- [Заметки разработчика](docs/DEVELOPMENT-ru.md)
- [История изменений](CHANGELOG.md)

## Лицензия и сторонний код

Интеграция Xray использует [`2dust/AndroidLibXrayLite`](https://github.com/2dust/AndroidLibXrayLite) (см. [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).

MIT — см. [LICENSE](LICENSE).
