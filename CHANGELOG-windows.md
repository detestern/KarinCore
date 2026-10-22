# Changelog (Windows)

All notable Windows-port changes are tracked here. Windows builds are released as
pre-releases under `windows-v<version>` tags; the Linux desktop history is in
[CHANGELOG.md](CHANGELOG.md).

## Unreleased

### Added
- KarinCore service for Windows (`karincore-service.exe`). The installer registers it; it runs as SYSTEM only while you are connected and is started by the app itself, not at boot. The app talks to it through a local channel that other computers cannot reach, and checks that the other end really is the KarinCore service before it sends anything.
- Xray 26.10.21, Wintun and the geo databases now ship with the installer, with pinned checksums.
- Connecting with VLESS, VMess, Trojan and Shadowsocks starts the Xray core. In this build the core works only as a local proxy: ping and "my IP" go through the server, but the rest of the system's traffic does not use the tunnel yet.
- The Xray logs are readable only by the Windows user who connected.

### Not yet available
- System-wide tunnel (TUN), Kill Switch, OpenVPN and WireGuard. Connecting with Kill Switch turned on is refused with an explanation.

## [0.1.0-alpha.1] - 2026-10-22

First preview build for Windows 10 and 11 (x64). It is meant for testing the
installer and the interface: connecting is not available yet.

### Added
- Windows installer (`-setup.exe`). It installs KarinCore for all users, so Windows asks for administrator rights once, during installation. The app itself runs without them.
- The full interface: servers, subscriptions, routing zones and profiles work and are saved as on Linux.
- Links, notifications and the "Paste" button use Windows' own mechanisms.
- The update check looks for the newest Windows pre-release instead of the Linux release.

### Not yet available
- Connecting. The "Connect" button explains that it comes in the next alpha builds.
- Kill Switch, diagnostics, the Routing Manager, Wi-Fi scenarios and the shell bridge.
