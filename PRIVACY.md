# KarinCore Android Privacy Policy

Effective date: 2026-10-07

## Summary

KarinCore Android is a local VPN and proxy client. It has no developer-operated account system, analytics, advertising SDK, telemetry backend or remote profile storage. The application does not sell personal data.

Network services selected by the user and the diagnostic services described below receive ordinary network requests. Their operators may observe connection metadata under their own privacy policies.

## Data stored on the device

KarinCore stores the information required to operate the configured connection:

- proxy profiles and credentials;
- subscription URLs and subscription group metadata;
- the selected profile and the last successful Always-on VPN configuration;
- routing, DNS, language, theme and interface settings;
- selected application package names for per-app routing;
- local VPN and Xray diagnostic logs.

On Android, profiles, subscription URLs, the selected profile and reconnect configuration are encrypted with AES-GCM using a key held by Android Keystore. Application backup is disabled. Interface preferences that do not contain proxy credentials remain in the application WebView storage.

The project does not operate a server that receives this stored configuration.

## Network requests

Normal VPN operation necessarily sends traffic to the proxy or VPN server configured by the user. Depending on the selected settings, KarinCore may also contact:

- the subscription provider specified by the user, to download or refresh a subscription;
- configured DNS resolvers, including the default Yandex DNS and Cloudflare DNS endpoints;
- `raw.githubusercontent.com`, to check the current project version;
- `api.ipify.org`, `api4.ipify.org` and `api6.ipify.org`, to display or test the public exit IP;
- `cp.cloudflare.com`, to perform the proxy-path latency and connectivity check;
- GitHub-hosted Loyalsoldier releases, when geo routing databases are downloaded or updated.

The public-IP and connectivity probes use the active forced proxy path. The contacted service can observe the proxy exit address, request time and ordinary HTTP/TLS metadata. KarinCore does not send profiles, subscription URLs or encryption keys to these diagnostic services.

## Diagnostics

Diagnostic reports are created only after an explicit export action and are written through the Android system document picker. They contain application and device version information, VPN state, TUN/Xray state, routing mode and redacted logs. Subscription URLs and supported secret-bearing profile links are removed from exported log content.

Reports are not uploaded automatically. Sharing an exported report is controlled by the user. A report should still be reviewed before publication because server-generated error messages can contain unexpected data.

## Data deletion

Profiles can be removed in the application. Diagnostic logs can be cleared from the Logs page. Uninstalling KarinCore removes its Android application-private storage and Keystore entries according to Android platform behavior.

## Permissions

KarinCore uses Internet and network-state permissions to provide VPN connectivity. The foreground-service and `BIND_VPN_SERVICE` declarations are used for the Android VPN service. Package visibility is limited to launchable applications needed by the per-app routing selector.

## Changes and contact

Material policy changes are recorded in the repository history and release notes. Privacy and security reports can be submitted through the repository issue tracker. Sensitive information, credentials and unredacted diagnostic reports must not be posted in a public issue.

Repository: <https://github.com/detestern/KarinCore/tree/android>

---

# Политика конфиденциальности KarinCore Android

Дата вступления в силу: 7 октября 2026 года

## Кратко

KarinCore Android — локальный VPN- и прокси-клиент. В приложении нет системы учётных записей разработчика, рекламных SDK, аналитики, телеметрии или удалённого хранилища профилей. Персональные данные не продаются.

Выбранные сетевые сервисы и перечисленные ниже диагностические сервисы получают обычные сетевые запросы. Их операторы могут видеть метаданные соединения в соответствии со своими политиками конфиденциальности.

## Данные на устройстве

KarinCore хранит данные, необходимые для работы настроенного подключения:

- прокси-профили и данные доступа;
- URL подписок и сведения о группах подписок;
- выбранный профиль и последнюю успешную конфигурацию Always-on VPN;
- настройки маршрутизации, DNS, языка, темы и интерфейса;
- имена пакетов приложений, выбранных для раздельной маршрутизации;
- локальные диагностические журналы VPN и Xray.

На Android профили, URL подписок, выбранный профиль и конфигурация переподключения защищены AES-GCM с ключом в Android Keystore. Резервное копирование приложения отключено. Настройки интерфейса без прокси-учётных данных остаются в локальном хранилище WebView.

У проекта нет собственного сервера, на который отправляется сохранённая конфигурация.

## Сетевые запросы

Обычная работа VPN требует передачи трафика на настроенный пользователем прокси- или VPN-сервер. В зависимости от настроек KarinCore также может обращаться к следующим сервисам:

- указанному пользователем провайдеру подписки — для загрузки и обновления подписки;
- настроенным DNS-резолверам, включая используемые по умолчанию Yandex DNS и Cloudflare DNS;
- `raw.githubusercontent.com` — для проверки версии проекта;
- `api.ipify.org`, `api4.ipify.org` и `api6.ipify.org` — для показа и проверки публичного выходного IP;
- `cp.cloudflare.com` — для проверки задержки и доступности через прокси;
- релизам Loyalsoldier на GitHub — при загрузке или обновлении баз геомаршрутизации.

Проверки публичного IP и соединения выполняются через принудительный прокси-маршрут. Сервис может видеть выходной IP прокси, время запроса и обычные метаданные HTTP/TLS. Профили, URL подписок и ключи шифрования этим диагностическим сервисам не отправляются.

## Диагностика

Диагностический отчёт создаётся только после явной команды экспорта и сохраняется через системный Android document picker. Он содержит сведения о версии приложения и устройства, состоянии VPN, TUN/Xray, режиме маршрутизации и очищенные журналы. URL подписок и поддерживаемые ссылки профилей с секретами удаляются из экспортируемых логов.

Автоматической отправки отчётов нет. Передача экспортированного файла выполняется только вручную. Перед публикацией отчёт всё равно следует просмотреть: сообщения об ошибках удалённых серверов могут содержать непредвиденные данные.

## Удаление данных

Профили удаляются в приложении, диагностические журналы очищаются на странице «Логи». При удалении KarinCore Android удаляет закрытое хранилище приложения и записи Keystore в соответствии с поведением платформы Android.

## Разрешения

Разрешения Internet и состояния сети используются для VPN-подключения. Foreground service и `BIND_VPN_SERVICE` необходимы системному VPN-сервису Android. Видимость пакетов ограничена запускаемыми приложениями, которые отображаются в настройках раздельной маршрутизации.

## Изменения и связь

Существенные изменения политики фиксируются в истории репозитория и примечаниях к релизам. Сообщения о конфиденциальности и безопасности принимаются через Issues репозитория. Секреты, данные доступа и неочищенные диагностические отчёты нельзя публиковать в открытом Issue.

Репозиторий: <https://github.com/detestern/KarinCore/tree/android>
