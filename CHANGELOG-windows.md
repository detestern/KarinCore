# Changelog (Windows)

All notable Windows-port changes are tracked here. Windows builds are released as
pre-releases under `windows-v<version>` tags; the Linux desktop history is in
[CHANGELOG.md](CHANGELOG.md).

## Unreleased

### Added
- KarinCore service for Windows. The installer registers it; it runs as SYSTEM only while you are connected and is started by the app itself, not at boot. The app talks to it through a local channel that other computers cannot reach, and checks that the other end really is the KarinCore service before it sends anything.
- Xray 26.10.21, Wintun and the geo databases ship with the installer, with pinned checksums.
- Connecting with VLESS, VMess, Trojan and Shadowsocks sends all of the computer's traffic through the tunnel (a Wintun adapter named "karincore"). The local network stays direct. Proxy, Direct and Block routing works as on Linux.
- DNS goes through the tunnel and does not leak: queries to any other DNS server, including those Windows sends to every network adapter at once, are blocked while you are connected. IPv6 goes through the tunnel too; if IPv6 is turned off in Windows, it stays blocked instead of bypassing the tunnel.
- After you disconnect, the adapter, its routes, its DNS settings and the blocking rules disappear, and the DNS cache is cleared.
- The Xray logs are readable only by the Windows user who connected.

### Not yet available
- Kill Switch, OpenVPN and WireGuard. Connecting with Kill Switch turned on is refused with an explanation.

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
