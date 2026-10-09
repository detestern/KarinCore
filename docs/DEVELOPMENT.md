<div align="center">
  <img src="../src-tauri/icons/icon.png" alt="KarinCore" width="160"/>
  <h1>KarinCore Android · development notes</h1>
  <p>Android port of KarinCore powered by Tauri 2, Rust, Android VpnService and Xray-core.</p>
  <p><strong>Current version: 0.1.0-alpha.32</strong></p>
  <p><a href="README-ru.md">Русская версия</a></p>
</div>

## Status

> This is the `android` branch of [detestern/KarinCore](https://github.com/detestern/KarinCore). The Linux desktop client lives on `main`; Android builds are published as pre-releases tagged `android-v<version>`.

This repository is an experimental Android port of [detestern/KarinCore](https://github.com/detestern/KarinCore), based on upstream KarinCore 1.3.7 at commit `b7fea2e2ff5e1492fd863381985fdebb4da7a57e`.

The shared KarinCore TypeScript UI and Rust parsing/routing logic are retained. Linux-specific tunnel setup is replaced on Android by a native `VpnService` bridge and Xray TUN integration.

Version `0.1.0-alpha.32` is distributed as separate debug APKs for `arm64-v8a`, `armeabi-v7a`, `x86` and `x86_64` through GitHub prereleases. Real-device runtime validation is the next verification step.

## Implemented through 0.1.0-alpha.32

- Tauri 2 mobile entry point.
- Native Android `VpnService`.
- Foreground VPN service for modern Android.
- Android TUN interface with IPv4 and IPv6 routes.
- Xray-core integration through pinned `2dust/AndroidLibXrayLite v26.9.30`.
- `geoip.dat` and `geosite.dat` are bundled in the APK and atomically installed into the app-private directory before Xray starts, allowing `geoip:*` and `geosite:*` rules without a separate download.
- TUN file descriptor passed directly to `CoreController.startLoop(...)`.
- Existing KarinCore VLESS/Reality, VMess, Trojan and Shadowsocks parsing reused.
- Existing Direct / Proxy / Block routing model reused.
- DNS packets from the TUN routed to the Xray DNS outbound.
- KarinCore's own package excluded from the VPN to prevent an Xray routing loop.
- VPN permission preparation, start, stop and status bridge.
- VPN service survives WebView/activity closure.
- Underlying network changes are monitored on Android P+; Wi-Fi/cellular handovers trigger an in-place Xray restart while keeping the TUN interface active.
- Per-app split tunneling with All apps, Only selected and Bypass selected modes.
- Installed launchable Android applications are discovered natively and can be searched and selected in Settings.
- Android-native VPN/Xray event log buffer is exposed through the existing Logs tab, including startup, errors, app-routing state, handovers and Xray status callbacks.
- Android document picker export for routing profiles.
- Android-specific mobile layout with desktop titlebar removed, safe-area handling and narrow-screen routing layout.
- The mobile interface keeps the configuration drawer control above the system navigation area, adapts forms, profile cards, logs and the About page to narrow or short screens, and shows an explicit idle core state instead of a technical `null` value.
- Android routing and settings use separated cards and one page-level scroll area; release history is rendered as distinct version blocks with readable change items.
- Android layout and packaged version detection no longer depend on a successful native runtime-metadata call. The desktop titlebar cannot cover the Android status bar, Settings remains scrollable, and About uses one continuous panel on mobile and desktop.
- The Android system Back button closes the active dialog or drawer first, returns every secondary section to the main screen, and requires a second press on the main screen to exit.
- The About page embeds this repository's own `CHANGELOG.md`, so its release history follows KarinCore Android releases instead of inherited upstream notes.
- A compact Android home-screen widget connects or disconnects the last successfully used VPN profile with one tap. Its power icon is gray while disconnected, pink while connecting and green while connected.
- Widget reconnect data is encrypted with Android Keystore. Initial use requires granting VPN permission and completing one successful connection in the application. Android Always-on VPN remains controlled through system VPN settings.
- Every prerelease contains split APKs for `arm64-v8a`, `armeabi-v7a`, `x86` and `x86_64`; CI verifies that each artifact contains the matching KarinCore and Xray native libraries.
- Runtime version/update metadata comes from the Rust package version instead of frontend hardcoded values.
- Android package-visibility query explicitly exposes launcher applications to the per-app selector on Android 11+.
- Network recovery handles both make-before-break and break-before-make transitions.
- UI connection state is restored from the native VPN service after Activity/WebView recreation; stale frontend state is discarded when the service is no longer active.
- Android Always-on VPN is supported with persisted last-successful native connection state for system restarts and reboot recovery.
- Android Settings integration exposes the system VPN screen for Always-on VPN and Block connections without VPN (lockdown) configuration.
- Android reports Always-on/lockdown state in Settings and prevents misleading manual disconnect attempts while Always-on mode is active.
- Settings includes live Android permission and stability diagnostics for VPN permission, foreground-service notifications, battery optimization, background restrictions, Data Saver, network availability/validation and Always-on/lockdown state. Every actionable warning opens the matching system screen, while OEM-specific background controls are identified separately because Android does not expose their state through a standard API.
- Subscription loading on Android uses a native Kotlin HTTP path instead of Rust reqwest, with bounded connect/read timeouts, redirect limits and explicit TLS/network errors.
- V2RayTun subscription routing is supported: a Base64 profile from the HTTP or body `routing` header may contain either a `{"rules":[...]}` object or a top-level `[...]` array; it is validated, stored with its subscription group and automatically applied to that group's servers with its original rule order, `port`, `domainStrategy` and `domainMatcher` fields. The Routing page displays the effective provider route, source, server, application state and full ordered rule list, while Direct / Proxy / Block switch to the subscription data in read-only mode.
- Happ routing links (`happ://routing/add/…`) and routing from full-JSON subscriptions are saved as a separate route profile named after the provider. The profile is never applied automatically and never touches your own rules or DNS; pick it with "Select" on the Routing page.
- Rust CI installs system dependencies without restarting GitHub runner services, preventing the checks from being interrupted after `apt` completes.
- The frontend has an independent 25 second subscription watchdog, so the UI cannot remain stuck in Loading even if the native bridge fails to return.
- Android uses Rustls for `reqwest`; the desktop path keeps the upstream native TLS setup.
- Logs page includes a VPN self-test that checks native service state, Xray state, TUN presence, forced proxy-path HTTPS/DNS and external IP through the active proxy.

Not implemented yet on Android: OpenVPN chaining and additional real-device runtime validation. Always-on/lockdown, IPv6 and OEM-specific behavior still require real-device validation.

## Home-screen widget

The 1×1 `KarinCore VPN switch` widget uses the last profile that connected successfully in the application. Complete one normal connection first, then add the widget from the Android launcher widget picker.

A tap connects or disconnects the VPN. Gray means disconnected, pink means connecting and green means connected. If VPN permission has not been granted or no successful profile is stored, the widget opens KarinCore to finish setup. When Android Always-on VPN is enabled, a disconnect tap opens system VPN settings because applications are not allowed to disable that mode directly.

## Permissions and stability diagnostics

The Android Settings page checks the operating-system conditions that affect a long-running VPN. Green items are ready, warning items need attention and informational items are optional or cannot be queried through a standard Android API.

The diagnostic does not change system policy silently. VPN consent is requested through the standard Android dialog; notification, battery, background-data, application and Always-on settings open their corresponding Android screens. Battery exemption uses the regular optimization list instead of requesting the sensitive direct-exemption permission.

## APK architecture

- `arm64-v8a`: almost all current Android phones and tablets.
- `armeabi-v7a`: older 32-bit ARM devices.
- `x86_64`: 64-bit Intel/AMD Android emulators and compatible devices.
- `x86`: older 32-bit x86 emulators and devices.

Installing the APK for the wrong architecture is rejected by Android without replacing the installed application.

## Release documentation

- [Privacy policy](../PRIVACY.md)
- [Compatibility and known limitations](COMPATIBILITY.md)
- [Upgrade and signing transition](UPGRADING.md)
- [Production release checklist](RELEASE_CHECKLIST.md)

The privacy description in the application and repository distinguishes zero developer-operated telemetry from the third-party network services used for subscriptions, DNS, update checks and connectivity diagnostics.

## Build prerequisites

Install the normal Tauri Android prerequisites: Rust, Node.js, Android Studio, Android SDK/Platform Tools, Build Tools, NDK and Command-line Tools. Add the Android Rust targets:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

Set `JAVA_HOME`, `ANDROID_HOME` and `NDK_HOME` in the build environment.

## First build

```bash
git clone -b android https://github.com/detestern/KarinCore.git
cd KarinCore

npm install
npm run android:core
npm run android:init
npm run android:dev
```

`npm run android:core` downloads the pinned `libv2ray.aar` and verifies its SHA-256 digest. The AAR is intentionally not committed to Git.

After `tauri android init`, Tauri generates `src-tauri/gen/android`. Commit-worthy generated Android project files can be added after the first successful build, while machine-specific `local.properties` remains ignored.

## Versioning

The Android port uses its own SemVer sequence, independent of the upstream Linux version. Run:

```bash
npm run version:check
```

before committing a release. The same version must exist in `VERSION`, `package.json`, `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json`. Android `versionCode` increases monotonically for distributable builds.

Debug prerelease publication requires an explicit repository opt-in or the `[publish-debug]` marker in a `release:` commit. This prevents an ordinary version commit from publishing a test-signed APK accidentally.

See [CHANGELOG.md](../CHANGELOG.md).

## Architecture

```text
TypeScript / Vite UI
        |
        v
Tauri commands + shared Rust KarinCore logic
        |
        +---------------- Linux ----------------+
        | systemd / route.sh / system Xray      |
        +----------------------------------------+
        |
        +--------------- Android ---------------+
          Tauri Android plugin
                 |
          Kotlin VpnService
                 |
             Android TUN
                 |
         AndroidLibXrayLite
                 |
              Xray-core
```

## Third-party code

The original KarinCore MIT license and copyright notice are preserved in [LICENSE](../LICENSE).

Android Xray integration uses `2dust/AndroidLibXrayLite`, currently pinned to `v26.9.30`. See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## License

MIT, following the upstream KarinCore project. See [LICENSE](../LICENSE).
