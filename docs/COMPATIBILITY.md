# Compatibility and known limitations

## Supported baseline

| Item | Current status |
| --- | --- |
| Android | Minimum API 24 (Android 7.0); target API 37 |
| Distributed ABI | Separate `arm64-v8a`, `armeabi-v7a`, `x86` and `x86_64` APKs |
| Package ID | `com.nikitahya.karincore` |
| VPN engine | Android `VpnService` with embedded Xray |
| Distribution | GitHub prerelease APK |
| Signing | Current prereleases are debug-signed test builds |

The Android version range is a build-time compatibility target, not a completed device certification matrix. Stable support claims will be narrowed or expanded after real-device testing.

## Protocols

| Protocol or source | Import | Android connection | Real-device release validation |
| --- | --- | --- | --- |
| VLESS / Reality | Supported | Supported | Pending full matrix |
| VMess | Supported | Supported | Pending |
| Trojan | Supported | Supported | Pending |
| Shadowsocks | Supported | Supported | Pending |
| WireGuard `wg://` | Supported | Xray userspace outbound | Pending |
| HTTPS subscriptions | Supported | Native Android HTTP transport | Basic subscription loading confirmed; full matrix pending |
| V2RayTun `routing` header | Supported | Applied per subscription group | Pending |
| OpenVPN chaining | Import paths retained | Not implemented on Android | Not applicable |

## Features requiring device validation

- IPv4 and IPv6 routing and leak behavior;
- DNS routing with the default and custom resolvers;
- Wi-Fi/mobile make-before-break and break-before-make handover;
- Always-on VPN, lockdown and reboot recovery;
- per-app allowlist and denylist behavior across OEM Android variants;
- subscription refresh and provider routing replacement;
- activity recreation, process pressure and foreground notification actions;
- phones, tablets, rotation, small displays, keyboard and Android back behavior.

## Known limitations

- ABI packaging is compile- and contents-validated in CI; runtime validation on representative 32-bit ARM and x86 environments is still pending.
- The published prerelease APK is debug-signed and is intended for testing, not production distribution.
- A debug APK produced on a different build machine may use a different signing certificate. Android can require uninstalling the previous build before installation, which removes application data.
- OpenVPN chaining is unavailable on Android.
- There is no automatic in-app APK installer. The update checker opens the matching GitHub release.
- No claim is made yet for Google Play readiness, managed-device compatibility or unrestricted operation under aggressive OEM battery policies.
- IPv6 availability depends on the device network, proxy server and selected routing configuration.

## Stable support policy

The first stable release requires a permanent production signing key, a signed release APK or AAB, a documented upgrade path and a completed real-device regression matrix. The current authoritative checklist is [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
