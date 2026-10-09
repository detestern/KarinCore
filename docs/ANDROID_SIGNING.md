# Android signing

Android installs a new APK over an installed app only when both are signed with the **same key**. KarinCore therefore signs every CI build with one permanent key kept in GitHub Actions secrets.

## One-time setup

```bash
scripts/android-keystore.sh --upload
```

The script (needs a JDK and, for `--upload`, an authenticated `gh`) creates `~/.karincore-signing/karincore-release.p12` and stores four repository secrets:

| Secret | Content |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | the keystore, base64-encoded |
| `ANDROID_KEYSTORE_PASSWORD` | store password |
| `ANDROID_KEY_PASSWORD` | key password (the same value for PKCS12) |
| `ANDROID_KEY_ALIAS` | `karincore` |

**Back up `~/.karincore-signing/` outside the repository** (password manager, encrypted drive). If the key is lost, installed apps can only be replaced by uninstalling first. The key must never be committed; `.gitignore` blocks `*.jks`, `*.keystore` and `*.p12`.

## How CI uses it

`android-build.yml` signs every APK with `apksigner` after the Gradle build, verifies each signature and checks that all four ABI builds carry the same certificate. The fingerprint is printed in the job log; compare it with the one printed by the script. Without the secrets the step only warns and the APKs stay debug-signed.

## Checking an APK locally

```bash
apksigner verify --print-certs KarinCore-Android-v0.1.0-alpha.33-arm64-v8a-debug.apk
```

The fingerprint must stay identical in every release.

## Notes

- The builds are still Gradle *debug* builds (the name keeps `-debug`); only the signing key changed. Moving to minified release builds needs R8 rules for the Xray/gomobile classes and a device test first.
- Versions signed with the old temporary key (alpha.32 and earlier) cannot be updated: uninstall them once.
