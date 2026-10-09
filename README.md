<div align="center">
<img src="src-tauri/icons/icon.png" alt="KarinCore" width="160"/>
<h1>KarinCore Android</h1>
<p><strong>The KarinCore proxy client for your phone — aesthetic, private, and built on native Android VPN</strong></p>
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

> **Alpha.** This is the Android branch of [KarinCore](https://github.com/detestern/KarinCore); the Linux desktop client lives on [`main`](https://github.com/detestern/KarinCore). Android builds are early test builds published as pre-releases tagged `android-v…`.

## What it is

KarinCore Android brings the same interface and the same Direct / Proxy / Block routing model of the Linux client to Android. It runs [Xray-core](https://github.com/XTLS/Xray-core) behind Android's native `VpnService`, so it works for the whole device without root.

## Features

- **Whole-device VPN** through `VpnService`, in a foreground service that survives closing the app; Wi-Fi ↔ mobile handovers restart the core in place.
- **Protocols:** VLESS (Reality), VMess, Trojan, Shadowsocks and WireGuard (`wg://`) profiles.
- **Subscriptions:** add a URL, the servers appear grouped under it and can be refreshed in one tap.
- **Routing profiles from subscriptions:** routing delivered with a subscription (Happ / V2RayTun headers, full-JSON subscriptions) is saved as a separate profile named after the provider. Pick it with **Select** — your own rules and DNS are never replaced automatically.
- **Direct / Proxy / Block zones** with domain, `geosite` and `geoip` rules, zone priority and custom DNS (DoH or plain). `geoip.dat` and `geosite.dat` are bundled, no extra download.
- **Per-app split tunneling:** all apps, only selected, or bypass selected.
- **Home-screen widget** that connects and disconnects the last working profile in one tap.
- **Always-on VPN** support, a built-in VPN self-test and live diagnostics for permissions and battery restrictions.
- **Private by design:** no developer telemetry; profiles and subscription URLs are encrypted with a key held by the Android Keystore.

## Install

1. Open [Releases](https://github.com/detestern/KarinCore/releases) and take the newest entry tagged `android-v…` (marked *Pre-release*; the Linux releases stay "Latest").
2. Download the APK that matches your device:

| APK | For |
|---|---|
| `…-arm64-v8a-debug.apk` | Almost every modern phone and tablet — **start here** |
| `…-armeabi-v7a-debug.apk` | Older 32-bit ARM devices |
| `…-x86_64-debug.apk` / `…-x86-debug.apk` | Emulators, Chromebooks, Intel devices |

3. Open the file and allow installing from your browser or file manager when Android asks.
4. Launch KarinCore, add a link or subscription, tap the core and allow the VPN request.

These alpha builds are signed with a debug key, so Android or Play Protect may show a warning, and updates are manual: **About** tells you when a newer version exists. If you tested earlier builds of the Android port, uninstall them first — this is a separate app and cannot be updated in place.

## Tips for a stable connection

- Allow notifications — Android needs the foreground-service notification to keep the VPN alive.
- Exclude KarinCore from battery optimization (Settings → *Permissions and stability*; the app checks and links you to the right screens).
- To add the widget, connect once normally first, then pick **KarinCore VPN switch** in the launcher's widget list.

## Build from source

You need Rust, Node.js 22, Android Studio (SDK, Build Tools, NDK 27) and JDK 17.

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

git clone -b android https://github.com/detestern/KarinCore.git
cd KarinCore

npm ci
npm run android:core    # downloads the pinned Xray library and checks its SHA-256
npm run android:init
npm run android:dev     # or: npm run tauri -- android build --apk --debug
```

More details — architecture, signing, versioning, release process — are in the [development notes](docs/DEVELOPMENT.md).

## Documentation

- [Privacy policy](PRIVACY.md)
- [Compatibility and known limitations](docs/COMPATIBILITY.md)
- [Upgrade and signing transition](docs/UPGRADING.md)
- [Development notes](docs/DEVELOPMENT.md)
- [Changelog](CHANGELOG.md)

## Credits and license

The Android port was created by [VivaGushter](https://github.com/VivaGushter) on top of KarinCore by [detestern](https://github.com/detestern). The Xray integration uses [`2dust/AndroidLibXrayLite`](https://github.com/2dust/AndroidLibXrayLite) (see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).

MIT — see [LICENSE](LICENSE).
