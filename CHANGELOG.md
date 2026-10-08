# Changelog

All notable Android-port changes are tracked here.

## Unreleased

Repository move: the Android port now lives on the `android` branch of `detestern/KarinCore`.

### Changed
- Application identifier and plugin namespace changed from `com.vivagushter.karincore` to `com.nikitahya.karincore`. Android treats this as a different app: earlier alpha builds must be uninstalled, they cannot be updated in place.
- Update check reads `VERSION` from the `android` branch of `detestern/KarinCore`; release links point to `android-v<version>` tags.
- CI workflows run on the `android` branch; Android GitHub releases use `android-v<version>` tags and are never marked as "Latest", so desktop releases stay the default.

### Fixed
- Routing: domain rules and IP rules of one zone are emitted as separate Xray rules. Fields inside a single rule are AND-ed, so a zone with `domain:.pro` and `geoip:ru` previously matched only domains that also resolved to a Russian IP.

## [0.1.0-alpha.31] - 2026-10-08

Android runtime metadata and mobile layout recovery.

### Fixed
- Prevented a failed `get_runtime_info` call from leaving the Android WebView in desktop mode with the titlebar drawn under the system clock.
- Replaced the `0.0.0` runtime fallback with the version bundled from `package.json`, preventing a permanent false update notification.
- Made the Settings page scroll independently of native runtime detection.
- Rebuilt the About page as one continuous panel instead of two competing desktop columns.

### Tests
- Added regression coverage for Android WebView detection and packaged-version fallback when native metadata is unavailable or stale.

## [0.1.0-alpha.30] - 2026-10-08

Android permissions and stability diagnostics.

### Added
- Added a live Settings diagnostic for VPN consent, foreground-service notifications, battery optimization, background restrictions, Data Saver, network availability/validation and Android Always-on/lockdown state.
- Added direct actions from each warning to the matching Android system settings screen, plus the standard VPN permission dialog and a manual refresh action.
- Added an explicit OEM background-controls note because vendor auto-start and sleeping-app policies cannot be queried through the standard Android API.

### Reliability
- Declared the Android 13+ notification permission used by foreground-service notifications.
- Kept battery handling compatible with store policy by opening the normal optimization settings instead of requesting direct exemption through a sensitive permission.

## [0.1.0-alpha.29] - 2026-10-08

Full Android ABI packaging.

### Added
- Added separate APK builds for `arm64-v8a`, `armeabi-v7a`, `x86` and `x86_64` to every Android prerelease.
- Added per-ABI CI validation for the KarinCore Rust library and AndroidLibXrayLite native library inside each APK.

### Changed
- Updated the Android workflow to install all four Rust Android targets and build split APKs instead of an arm64-only artifact.
- Kept the validated Android SDK/NDK bootstrap while expanding the installed Rust target set.
- Updated release publication to attach and consistently name all four architecture-specific APKs.

## [0.1.0-alpha.28] - 2026-10-08

One-tap Android home-screen VPN widget.

### Added
- Added a compact 1×1 home-screen widget that connects or disconnects KarinCore with one tap and displays distinct disconnected, connecting and connected colors.
- Added encrypted storage for the last successfully connected widget profile, including its routing mode, selected applications and MTU.
- Added localized guidance when the widget needs the initial Android VPN permission or a first successful in-app connection.

### Reliability
- Reused the existing foreground `VpnService` and status state instead of creating a second VPN control path.
- Preserved Android Always-on VPN guarantees: the widget opens system VPN settings instead of attempting a forbidden disconnect.
- Added an Android CI gate that verifies the widget provider and resources are packaged in the APK.

## [0.1.0-alpha.27] - 2026-10-08

Android back navigation and project release history.

### Added
- Added application-wide handling for the Android system Back button: dialogs and drawers close first, every secondary section returns to the main screen, and the main screen requires a second press within 2.2 seconds before exiting.
- Added a localized confirmation message after the first Back press on the main screen.

### Changed
- Replaced the inherited upstream update text on the About page with the actual KarinCore Android release history embedded from this repository's `CHANGELOG.md`.
- Structured About-page releases into separate version, summary, category and change blocks.

### Tests
- Added regression coverage for secondary-page navigation, overlay priority, double-press exit confirmation and project changelog rendering.

## [0.1.0-alpha.26] - 2026-10-08

Android Xray geodata installation repair.

### Fixed
- Extracted the bundled `geoip.dat` and `geosite.dat` assets into the app-private filesystem before calling `initCoreEnv`, fixing subscription routes that use `geoip:*` and `geosite:*` selectors.
- Installed geodata atomically and tracked its bundled revision so interrupted copies are retried and future bundled database revisions can replace old files safely.

### Reliability
- Added an Android CI gate that opens the completed APK and verifies both Xray geodata assets are present before the artifact can be published.
- Added native log output with the installed geodata sizes for on-device verification.

## [0.1.0-alpha.25] - 2026-10-08

Visible effective subscription routing.

### Added
- Added an effective subscription-route panel with source group, selected server, rule count, default outbound and provider metadata.
- Added explicit `Applied now` and `Ready for connection` states tied to the native VPN connection and active profile.
- Rendered every provider rule in original Xray evaluation order, including all domain, IP, port and other match fields.

### Changed
- Direct / Proxy / Block cards now display the selected subscription's effective route in read-only mode instead of continuing to show unrelated local rules.
- Provider routes disable local editing, priority dragging and route export while they override the local routing configuration.

## [0.1.0-alpha.24] - 2026-10-08

V2RayTun routing compatibility and Android route-priority layout repair.

### Added
- Added an active provider-route badge to subscription groups and a rule-count notice to the Routing page.
- Added a regression test for the five-rule V2RayTun routing array used by subscriptions.

### Fixed
- Accepted V2RayTun `routing` payloads supplied as a top-level JSON array in addition to the `{"rules": [...]}` form.
- Preserved and applied provider rule order and fields, including a terminal `proxy` rule with `port: "0-65535"`.
- Forced coarse-pointer and narrow-screen route priority cards into a full-width vertical flow, with correctly positioned arrows and vertical drag ordering.

## [0.1.0-alpha.23] - 2026-10-07

Mobile routing, settings and release-history layout repair.

### Fixed
- Replaced the nested half-screen routing scroller with one page-level Android scroll area.
- Rebuilt routing options and settings as separated cards with non-shrinking, right-aligned switches.
- Forced Android route priority columns and DNS editors into a stable single-column flow.
- Constrained the About-page identity image and removed stretched justified mobile text.
- Parsed patch notes into separate version cards and bullet items instead of one continuous text block.

## [0.1.0-alpha.22] - 2026-10-07

Android mobile interface stabilization and release hardening.

### Security
- Moved proxy profiles, subscription URLs and the selected profile from WebView storage into Android Keystore-backed AES-GCM storage, with a one-time legacy migration.
- Added strict HTML escaping and a restrictive Tauri content-security policy for renderer-controlled content.
- Restricted subscriptions to HTTPS, blocked private/local literal targets and enforced the same policy across redirects.
- Replaced writable temporary privileged configuration flows with a fixed root helper that validates Xray, OpenVPN, WireGuard, DNS, route and firewall inputs.
- Replaced predictable authentication tokens with operating-system CSPRNG output and expanded diagnostics redaction.
- Disabled Android application backups and restricted external browser navigation to the project repository.

### Reliability
- Corrected Android TUN MTU propagation, excluded VPN transports from upstream selection and persisted reconnect state securely.
- Serialized protected-state writes so rapid UI mutations cannot be committed out of order.
- Added locked dependency metadata, frontend security tests, privileged-helper tests, dependency audits and least-privilege pinned CI actions.
- Allowed debug prerelease publication through an explicit `[publish-debug]` release-commit marker when repository-variable administration is unavailable.

### Fixed
- Corrected Android safe-area padding and kept the configuration drawer control clear of system navigation on short displays.
- Prevented native file inputs from leaking into the mobile layout and replaced the disconnected core's technical `null` label with `idle`.
- Added narrow-screen wrapping for forms, profile actions, log controls and long About-page identifiers, and switched the About page to a scrollable single-column layout on phones.

### Documentation
- Added a bilingual privacy policy covering local storage, configured network services, diagnostics, permissions and data deletion.
- Added compatibility, known-limitations and upgrade guides, including the debug-to-production signing transition.
- Added a production release checklist for device validation, permanent signing, store preparation, versioning and artifact verification.
- Corrected the in-app privacy statement so it accurately distinguishes zero developer-operated telemetry from documented third-party network requests.

## [0.1.0-alpha.21] - 2026-10-06

Automated Rust parser and configuration regression coverage.

### Added
- Ten unit tests covering VLESS/Reality, VMess, Trojan and Shadowsocks outbound generation.
- Subscription tests for plain, unpadded Base64 and JSON inputs, including imported routing and DNS.
- WireGuard tests for Base64 payloads, executable-directive sanitization, required-field validation, defaults and Xray userspace outbound generation.
- Routing, DNS generation and diagnostic secret-redaction regression tests.
- A dedicated Rust core test job in Repository checks with cached Rust dependencies.

### Fixed
- WireGuard profile URIs are now redacted from exported diagnostic log content alongside the other supported secret-bearing profile formats.
- Desktop-host Rust compilation now resolves the VPN plugin runtime type explicitly and keeps the OpenVPN helper call signature synchronized.

### Verified
- All ten Rust core tests pass in a Linux/Tauri host build.
- The feature commit completes Repository checks and the full arm64 debug APK build in GitHub Actions.
- Release publication is handled by the automatic Android release workflow.

## [0.1.0-alpha.20] - 2026-10-06

Refreshable subscription groups.

### Added
- Subscription groups now retain their source URL in app-private local storage.
- Subscription groups expose a refresh action directly in the profile drawer.
- Refresh uses the same native Android subscription transport and 25 second UI watchdog as the initial import.
- Existing profiles are matched by URL so their IDs and pin state survive refreshes.
- New subscription profiles are added and profiles removed by the server disappear from the group.
- Imported routing and DNS settings are merged again when a subscription refresh supplies them.

### Behavior
- Existing groups created by older versions continue to work; they simply do not show Refresh until re-added from a subscription URL.
- An already active VPN connection is not force-disconnected if its profile disappears during a subscription refresh.
- A removed inactive selected profile is cleared from the frontend selection state.

### Verified
- Subscription-refresh feature commit completes the full arm64 debug APK build in GitHub Actions.
- Release publication is handled by the automatic Android release workflow.


## [0.1.0-alpha.19] - 2026-10-06

Major Android APK size reduction.

### Changed
- Cargo dev profile now disables native debug info and strips Rust symbols from debug-installable Android builds.
- The APK remains a normal debug-signed package suitable for direct installation and testing.
- KarinCore's runtime/native diagnostic logging remains available; only compiler/linker symbol baggage is removed.

### Size
- Android APK reduced from approximately 230.7 MB to 73.7 MB.
- `libkarin_proxy_lib.so` reduced from approximately 170.5 MB to 20.7 MB.
- Xray `libgojni.so` remains approximately 34.3 MB and is now the largest native library in the APK.

### Verified
- Stripped debug APK completes the full arm64 Android build in GitHub Actions.
- The generated APK still contains the expected arm64 Rust and Xray native libraries.


## [0.1.0-alpha.18] - 2026-10-06

Embedded WireGuard outbound support on Android.

### Added
- Android support for existing `wg://?payload=<base64>` profiles.
- wg-quick style configuration parsing for Interface and multiple Peer sections.
- Supported WireGuard fields: PrivateKey, Address, DNS, MTU, PublicKey, PresharedKey, Endpoint, AllowedIPs, PersistentKeepalive and optional Reserved bytes.
- Plain and Base64 subscriptions now retain `wg://` profiles.
- Manual profile input accepts `wg://` links.
- WireGuard profile naming/info fallbacks no longer depend on a hostname being present in the URL.

### Architecture
- Android WireGuard uses Xray's built-in userspace WireGuard outbound.
- `noKernelTun: true` forces Xray to use its in-process network stack instead of creating another system TUN.
- The existing Android `VpnService` remains the only system VPN interface.
- WireGuard endpoint sockets stay outside the Android VPN because the KarinCore package itself is excluded from the TUN.
- Android TUN MTU is reduced to 1420 for WireGuard profiles.

### Compatibility
- Existing Linux WireGuard behavior using wg-quick is unchanged.
- OpenVPN remains unsupported on Android for now.

### Verified
- Combined WireGuard outbound and subscription/input integration completes the full arm64 debug APK build in GitHub Actions.
- Release publication is handled by the automatic Android release workflow.


## [0.1.0-alpha.17] - 2026-10-06

Network-family diagnostics and VPN notification polish.

### Added
- Separate IPv4 and IPv6 proxy-path checks in the built-in Android VPN self-test.
- IPv4 probe uses `https://api4.ipify.org`.
- IPv6 probe uses `https://api6.ipify.org`.
- KarinCore monochrome shield icon for the Android foreground VPN notification.
- Android resource strings for notification states and actions, with Russian localization.

### Changed
- Generic external-IP lookup now uses HTTPS.
- Proxy latency/connectivity check now uses Cloudflare's HTTPS 204 endpoint.
- IPv6 absence is reported as an informational warning instead of failing the whole VPN self-test.
- IPv4 and the forced HTTPS proxy path remain required for a passing self-test.
- Notification connection, restore, handover and error text is no longer hardcoded in Kotlin.

### Verified
- Combined network-diagnostics and notification-resource feature build completes the full arm64 debug APK build in GitHub Actions.
- Release publication is handled by the automatic Android release workflow.


## [0.1.0-alpha.16] - 2026-10-06

Live Android UI synchronization with native VPN state.

### Added
- Foreground-only native VPN status monitor in the Android frontend.
- Native VPN state is checked every 2.5 seconds while the application is visible.
- UI automatically reflects service stop/start, Xray core state, reconnect state, Always-on and lockdown changes.
- Active frontend connection markers are removed when the native VPN is no longer active.
- Monitoring pauses while the application is hidden and resumes immediately when it becomes visible.

### Efficiency
- Concurrent native status polls are suppressed.
- UI is re-rendered only when the native status signature changes.
- Gradle dependency caching is enabled in the Android GitHub Actions workflow.

### Verified
- State-monitor feature commit completes the full arm64 debug APK build in GitHub Actions.
- Release publication is handled by the automatic Android release workflow.


## [0.1.0-alpha.15] - 2026-10-06

Built-in Android VPN self-test.

### Added
- VPN self-test action in the Android Logs page.
- Native VPN service, Xray core and TUN state checks.
- Visibility of reconnect/handover state, Always-on/lockdown state and per-app routing mode.
- Forced proxy-path connectivity test using the existing Xray ping inbound.
- External IP lookup through the active VPN/proxy path.
- Human-readable pass/fail output suitable for real-device debugging.

### Behavior
- Proxy-path checks run only when Xray and the Android TUN are active.
- The self-test reports native last-error state when available instead of silently hiding it.
- The test does not modify the active VPN configuration.

### Verified
- Self-test feature commit completes Repository checks and the full arm64 debug APK build in GitHub Actions.
- Release publication is handled by the automatic Android release workflow.


## [0.1.0-alpha.14] - 2026-10-06

Foreground VPN notification actions.

### Added
- Quick Disconnect action in the Android foreground VPN notification when Always-on VPN is disabled.
- VPN Settings action in the notification when Android Always-on VPN is active.
- Notification is explicitly categorized as a private ongoing service notification.

### Safety
- Service-level stop requests are ignored while Android reports Always-on VPN enabled.
- This prevents a notification action or stale pending intent from fighting Android's Always-on restart behavior.

### Verified
- Notification-action feature commit completes the full arm64 debug APK build in GitHub Actions.
- Release publication is handled by the automatic Android release workflow.


## [0.1.0-alpha.13] - 2026-10-06

Privacy-conscious Android diagnostics export.

### Added
- Export diagnostics action in the Android Logs page.
- Clear native VPN/Xray logs action in the Logs page.
- Device metadata bridge with manufacturer, brand, model, Android release and SDK level.
- Diagnostic report containing app version, architecture, Xray version, VPN lifecycle state, Always-on/lockdown state, TUN presence and per-app routing mode/count.
- Diagnostic files are written through the Android system document picker.

### Privacy
- Generated diagnostics do not include subscription URLs or generated Xray configuration.
- Proxy URI-bearing log lines are replaced with a redacted marker.
- Per-app diagnostics include only the routing mode and package count, not selected package names.

### Verified
- Diagnostic backend and UI complete the full arm64 debug APK build in GitHub Actions.
- Release publication is handled by the automatic Android release workflow.


## [0.1.0-alpha.12] - 2026-10-06

Android fork update channel and automated releases.

### Fixed
- The in-app update checker no longer falls back to the upstream `detestern/KarinCore` repository.
- Update checks now read the Android fork's `VERSION` file directly, so alpha/beta prereleases are detected correctly.
- Update links target the exact version tag in `VivaGushter/KarinCore-android`.
- The About page identifies the Android fork and keeps upstream attribution separate.

### Added
- Semantic prerelease-aware version comparison in the frontend.
- GitHub Actions release publishing for `release:` commits.
- Automatic version tag creation, prerelease creation, changelog release notes and APK attachment.
- Retry logic for transient Android SDK/NDK download corruption in CI.

### Verified
- The updater/release-channel feature commit completes the full arm64 debug APK build.
- This release commit is intended to validate automatic GitHub Release publication end-to-end.


## [0.1.0-alpha.11] - 2026-10-06

Native Android subscription transport.

### Fixed
- Android subscription downloads no longer depend on Rust reqwest transport.
- Added a native Android `HttpURLConnection` / `HttpsURLConnection` fetch bridge running on a background executor.
- Native fetch applies an 8 second connect timeout, 20 second read timeout, five-redirect limit and 8 MiB response cap.
- Gzip subscription responses are decoded natively.
- TLS validation remains enabled and TLS failures are surfaced explicitly.
- Added a frontend 25 second watchdog around the Tauri subscription command so the Add button always leaves Loading state even if the bridge does not answer.

### Architecture
- Rust still owns subscription parsing, Base64 decoding, routing import and DNS import.
- Android only owns the HTTP transport layer.

### Verified
- Native-fetch feature commit completes the full arm64 debug APK build in GitHub Actions.
- Release commit is validated by the same Android build workflow.


## [0.1.0-alpha.10] - 2026-10-06

Subscription loading reliability.

### Fixed
- Subscription HTTP requests no longer wait indefinitely.
- Added an 8 second connection timeout and 20 second total request timeout.
- Redirect chains are limited to five hops.
- Oversized subscription responses above 8 MiB are rejected.
- Timeout, connection and TLS-related failures are surfaced to the UI with useful messages.
- The subscription button always leaves Loading state once the backend returns an error.

### Changed
- Subscription requests now identify as KarinCore Android instead of using the old v2rayNG user-agent string.

### Verified
- Feature commit completes the full arm64 debug APK build in GitHub Actions.
- Release commit is validated by the same Android build workflow.


## [0.1.0-alpha.9] - 2026-10-06

Android Always-on VPN and system lockdown integration.

### Added
- Explicit Android Always-on VPN support for KarinCore's `VpnService`.
- App-private persistence of the last successfully started generated Xray configuration, MTU and per-app routing state.
- Restoration of the persisted VPN connection when Android starts the service for Always-on VPN, including after reboot.
- Android VPN Settings shortcut from KarinCore Settings.
- Native Always-on and lockdown status fields exposed to the frontend.
- Android-specific system Kill Switch section replacing the desktop iptables toggle.

### Changed
- User-requested profile changes clear the previously persisted native connection before attempting the new profile, preventing stale Always-on restoration.
- VPN permission revocation clears persisted restart state.
- Manual disconnect is rejected while Android reports Always-on VPN active; the UI directs the user to system VPN Settings instead.
- Desktop Kill Switch behavior remains unchanged on Linux.
- Android sends `killSwitch: false` to the shared Rust command because system lockdown, not iptables, is the authoritative Android mechanism.

### Safety
- KarinCore does not attempt to enable lockdown programmatically.
- System Always-on/lockdown configuration remains under Android user/device-policy control.
- Only a configuration that previously reached a running Xray state is persisted for system restart.

### Verified
- Feature commit completes the full arm64 debug APK build in GitHub Actions.
- Release commit is validated by the same Android build workflow.


## [0.1.0-alpha.8] - 2026-10-06

Native VPN state restoration and version metadata recovery.

### Added
- Native VPN runtime-status command exposed to the frontend.
- Android UI restores running, starting and reconnecting VPN state after Activity/WebView recreation.
- Active profile hint is persisted while the native VPN is running so the reopened UI can display the correct profile.

### Changed
- Native `VpnService` state is authoritative when the Android UI starts.
- Stale session/local active-connection markers are removed when the native VPN service is no longer active.
- Reconnecting/starting state is reflected as Connecting instead of incorrectly showing Disconnected.
- Ping and VPN IP controls remain hidden until the native Xray core is running.
- Version metadata is advanced monotonically after the interrupted alpha.6/alpha.7 documentation update.

### Verified
- Previous alpha.7 runtime-hardening build completed successfully in GitHub Actions.
- Full alpha.8 arm64 debug APK validation is required by the release CI workflow.

## [0.1.0-alpha.7] - 2026-10-06

Android runtime hardening.

### Added
- Android package-visibility query for launcher applications used by the per-app selector.
- Recovery after break-before-make network transitions where the old upstream disappears before the new one is available.
- VPN permission revocation event logging.

### Changed
- Underlying-network recovery now differentiates direct handovers from recovery after complete network loss.
- GitHub Actions Android workflow uses current checkout/setup Java/setup Node major versions.

### Verified
- Xray-core Android documentation confirms the TUN descriptor is supplied through `xray.tun.fd`.
- Pinned AndroidLibXrayLite `v26.9.30` sets `xray.tun.fd` inside `CoreController.startLoop(config, tunFd)`.
- Complete arm64 debug APK build succeeds in GitHub Actions after runtime hardening.


## [0.1.0-alpha.6] - 2026-10-06

Mobile UI and Android document export.

### Added
- Android system document picker for routing-profile JSON export.
- Native document-writing bridge through the KarinCore Tauri Android plugin.
- Android-specific responsive layout with safe-area handling.
- Narrow-screen routing layout that stacks Direct / Proxy / Block columns vertically.
- Runtime metadata command exposing platform, package version and update repository to the frontend.

### Changed
- Desktop frameless titlebar and minimize/maximize/close controls are hidden on Android.
- Splash screen, sidebar, dialogs and profile drawer now use Android viewport/safe-area dimensions.
- Hero connection control scales to phone width and short screens.
- Update checker uses the Android-port repository on Android.
- Visible application version is derived from Cargo package metadata instead of a hardcoded frontend string.

### Verified
- Complete arm64 debug APK build succeeds in GitHub Actions with mobile layout and Android document export enabled.


## [0.1.0-alpha.5] - 2026-10-06

Android-native VPN and Xray event logs.

### Added
- In-memory Android VPN/Xray event log buffer capped at 500 lines.
- Existing Logs tab now reads native Android service logs instead of Linux file paths.
- Native clear-log bridge for Android.
- Log entries for VPN startup, Xray initialization, per-app routing state, network handovers, reconnect attempts, errors and Xray status callbacks.
- Timestamped log entries while retaining matching Logcat output.

### Behavior
- Logs stay scoped to KarinCore VPN events instead of exposing unrelated system Logcat output.
- The bounded buffer prevents unbounded log growth during long-running VPN sessions.

### Verified
- Complete arm64 debug APK build succeeds in GitHub Actions with native Android logging enabled.


## [0.1.0-alpha.4] - 2026-10-06

Per-app split tunneling.

### Added
- Native discovery of launchable Android applications with labels and package names.
- Searchable application selector in Settings.
- Three VPN application-routing modes: All apps, Only selected and Bypass selected.
- Persistent per-app routing configuration in local storage.
- Android `VpnService.Builder.addAllowedApplication` and `addDisallowedApplication` integration.
- Validation that Only selected mode contains at least one installed application.

### Safety
- KarinCore's own package is never added to the VPN allowlist.
- Missing or uninstalled package names are ignored before the VPN interface is established.
- Xray outbound traffic remains outside the TUN to prevent routing loops.

### Verified
- Complete arm64 debug APK build succeeds in GitHub Actions with per-app routing enabled.


## [0.1.0-alpha.3] - 2026-10-06

Network handover recovery.

### Added
- Android underlying-network monitoring on Android P and newer.
- Debounced detection of Wi-Fi/cellular handovers.
- In-place Xray core restart using the existing TUN file descriptor.
- Up to three Xray restart attempts after an upstream network change.
- `reconnecting` state exposed through the native VPN status bridge.
- `ACCESS_NETWORK_STATE` and `CHANGE_NETWORK_STATE` permissions required for underlying-network monitoring.

### Behavior
- The TUN interface stays established during an Xray handover restart.
- A failed handover restart keeps the VPN interface active instead of silently falling back to direct traffic.
- The foreground notification reflects reconnecting and reconnect-failure states.

### Verified
- Complete arm64 debug APK build succeeds in GitHub Actions after the handover implementation.


## [0.1.0-alpha.2] - 2026-10-06

First CI-validated Android APK build.

### Added
- GitHub Actions arm64 debug APK build pipeline.
- Automatic Android SDK/NDK, Rust target, Xray AAR and Tauri Android bootstrap in CI.
- APK workflow artifact upload for successful builds.

### Fixed
- Corrected the Tauri VPN plugin error serializer return type so the Rust Android target compiles.
- Added the AndroidX AppCompat dependency required by Tauri ActivityResult callbacks.
- Replaced the failing Android setup action path with the runner's preinstalled Android command-line tools.

### Verified
- Tauri Android project initialization succeeds in CI.
- Rust compiles for `aarch64-linux-android`.
- Kotlin/Gradle compilation succeeds.
- AndroidLibXrayLite `v26.9.30` is downloaded and SHA-256 verified.
- A complete arm64 debug APK is produced and uploaded as a workflow artifact.

### Remaining validation
- Real-device installation and VPN runtime connection testing are still pending.


## [0.1.0-alpha.1] - 2026-10-06

First Android development snapshot.

### Added
- Android port repository based on KarinCore 1.3.7.
- Tauri 2 Android mobile entry point while retaining the desktop wrapper.
- Native Tauri Android plugin `karin-vpn`.
- Android `VpnService` with foreground-service lifecycle.
- IPv4 and IPv6 full-tunnel routes.
- Xray TUN integration using `AndroidLibXrayLite v26.9.30`.
- Pinned Xray AAR downloader with SHA-256 verification.
- VPN prepare/start/stop/status bridge.
- Android-specific Xray config generation using KarinCore routing and DNS data.
- Version consistency checker.
- Android build and architecture documentation.

### Changed
- Application identifier for this port is `com.vivagushter.karincore`.
- Android `reqwest` backend uses Rustls.
- Real KarinCore code moved into the library entry point so Tauri mobile can call it.
- The browser/activity unload event no longer automatically stops the VPN.

### Known limitations
- Full APK compilation and real-device runtime validation are still pending.
- OpenVPN and WireGuard chaining are not implemented on Android yet.
- Per-app split tunneling UI is not implemented yet.
- Network handover/reconnect handling is not implemented yet.
- Export still needs Android document-picker support.
- UI is still primarily the desktop KarinCore layout.
