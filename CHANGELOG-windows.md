# Changelog (Windows)

All notable Windows-port changes are tracked here. Windows builds are released as
pre-releases under `windows-v<version>` tags; the Linux desktop history is in
[CHANGELOG.md](CHANGELOG.md).

## Unreleased

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
