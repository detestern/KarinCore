<div align="center">
<img src="public/karincore-icon-main.png" alt="KarinCore Logo" width="180"/>
<h1>KarinCore</h1>
<p><strong>A modern, aesthetic, and secure proxy client for Linux</strong></p>
<p><a href="https://karincore.ru">Website</a> · <a href="https://github.com/detestern/KarinCore/releases">Releases</a> · <a href="#karincore-on-android-alpha">Android</a> · <a href="https://github.com/detestern/KarinCore/issues">Issues</a></p>
<p><a href="README.md">🇬🇧 English</a> | <a href="README-ru.md">🇷🇺 Русский</a></p>

<p>
<img src="https://img.shields.io/badge/version-1.6.0-dc8add?style=flat-square&labelColor=11111b" alt="Version"/>
<img src="https://img.shields.io/badge/platform-linux-dc8add?style=flat-square&labelColor=11111b&logo=linux&logoColor=dc8add" alt="Platform"/>
<img src="https://img.shields.io/badge/built_with-rust-dc8add?style=flat-square&labelColor=11111b&logo=rust&logoColor=dc8add" alt="Rust"/>
<img src="https://img.shields.io/badge/framework-tauri-dc8add?style=flat-square&labelColor=11111b&logo=tauri&logoColor=dc8add" alt="Tauri"/>
<img src="https://img.shields.io/badge/license-MIT-dc8add?style=flat-square&labelColor=11111b" alt="License"/>
</p>
<p><a href="https://karincore.ru"><img src="https://img.shields.io/badge/website-karincore.ru-dc8add?style=flat-square&labelColor=11111b&logo=firefox-browser&logoColor=dc8add" alt="karincore.ru"/></a></p>
</div>

> 🌐 **Everything in one place: [karincore.ru](https://karincore.ru)**
> Step-by-step install guides for Arch, Debian/Ubuntu and Steam Deck, downloads, the Android alpha, and a live routing demo: type a domain and see whether it goes to Proxy, Direct or Block. The site speaks Russian and English.

<br/>

## Philosophy

The internet should be free, and the tools that protect it shouldn't feel like a chore to run.

KarinCore exists to end the ritual of hand-editing JSON configs, wrestling with `iptables`, and babysitting systemd units just to get a working tunnel on Linux. It's the bridge between a genuinely powerful anti-censorship core (Xray, OpenVPN, WireGuard) and an interface that respects your time and your eyes.

No Electron. No sandbox fighting your routing table. A Rust core, native `systemd` integration, and a UI built specifically for this app, not a generic template with a proxy client bolted on.

<div align="center">

[Features](#features) · [Screenshots](#screenshots) · [Install](#installation) · [Steam Deck](#karincore-on-steam-deck) · [Android](#karincore-on-android-alpha) · [Architecture](#architecture) · [Releases](#recent-releases) · [Roadmap](#roadmap) · [Support](#support-contributing-and-feedback)

</div>

<br/>

## Features

**Multi-level routing.** Native OpenVPN and WireGuard alongside Xray. Wrap VLESS/VMess traffic inside an encrypted OVPN or WireGuard tunnel via policy-based routing, or run Xray directly. Your call.

**Visual routing priority.** Drag columns (Proxy, Direct, Block) to set the exact order Xray evaluates rules. No editing JSON rule arrays by hand.

**Subscriptions and profiles.** Add a subscription URL or a single `vless://`, `vmess://`, `trojan://`, `ss://`, `wg://` link, or drop in `.ovpn` and `.conf` files. Routing rules from the subscription are imported too. Save full setups (rules, column order, DNS) as named profiles.

**Ping of every server.** One button in the servers panel measures the response time of the whole list and colours it: green up to 250 ms, yellow up to 500 ms, red above.

**Diagnostics.** A dedicated tab answers "why isn't it working?": internet, DNS, the server's port and a request through the tunnel, with a plain-language verdict and the fix.

**Real kill switch.** Firewall-level enforcement: if the tunnel drops unexpectedly, outbound traffic stops, and the rules survive a daemon restart.

**IPv6 and DNS control.** The tunnel carries IPv4 and IPv6 together. Independent Domestic and Remote DNS resolvers with DoH/DoU support, and one switch for proxying the VPN server's own IP.

**Narrow privilege boundary.** The GUI never runs as root. Everything privileged goes through a single root-owned helper that validates each request. See [Architecture](#architecture).

**Shell Bridge.** A status file and `--connect` / `--disconnect` flags let external panels and shells (karin-shell, Brain Shell) show and control the connection. Details in the [changelog](CHANGELOG.md#v140--shell-bridge).

**Karin.** The built-in terminal assistant narrates what the core is doing: connection status, DNS checks, the occasional dry joke about your ISP. Can be turned off in Settings.

**Zero telemetry.** Everything runs locally. No trackers, no analytics, no phone-home. Your keys, IPs and routing profiles never leave your machine. MIT licensed, source fully open.

<br/>

## Screenshots

<div align="center">
<img src=".github/assets/screenshot-main-connected.jpg" alt="Main screen, connected" width="45%"/>
<img src=".github/assets/screenshot-main-idle.jpg" alt="Main screen, idle" width="45%"/>
<br/>
<img src=".github/assets/screenshot-routing.jpg" alt="Routing tab" width="45%"/>
<img src=".github/assets/screenshot-settings.jpg" alt="Settings" width="45%"/>
</div>

<br/>

## Installation

### Arch Linux (AUR)

The recommended path for Arch-based systems (Manjaro, EndeavourOS, and the rest). Builds the core, pulls dependencies, and wires up system services automatically.

```bash
yay -S karincore-git
```

### Ubuntu / Debian / Linux Mint

Grab the latest `.deb` from [Releases](https://github.com/detestern/KarinCore/releases). It installs the privileged helper, a one-line `sudoers` rule and the `systemd` unit, creates the `karincore` group and adds the installing user (log out and back in afterwards). Make sure `openvpn` and `wireguard-tools` are present on your system first. The `.deb` does not bundle Xray: install it separately (e.g. via [XTLS/Xray-install](https://github.com/XTLS/Xray-install)). The binary has to be at `/usr/bin/xray`; if the installer puts it in `/usr/local/bin/xray`, the package creates the link for you.

```bash
sudo dpkg -i KarinCore_1.6.0_amd64.deb
sudo apt install -f # only if dependencies are missing
```

### First launch

The daemon should **not** be enabled at boot: that would let it start routing traffic before the GUI has generated a valid config. Don't run `systemctl enable` on it. Just launch KarinCore from your application menu; the GUI starts, monitors and stops the daemon on its own.

<br/>

## KarinCore on Steam Deck

**KarinCore runs great on Steam Deck.** SteamOS is Arch Linux under the hood, so the same AUR package that powers the desktop Linux experience installs cleanly on Deck too — full GUI, drag-and-drop routing, the kill switch, all of it. If you've been looking for a proper VPN client for Steam Deck instead of hand-editing WireGuard configs over SSH, this is built for exactly that.

### Before you start: set a password

Steam Deck's default `deck` account usually has **no password set** — fine for the console experience, but `sudo` (which the installer needs) requires one to exist. Set it once, in Desktop Mode:

```bash
passwd
```

Follow the prompts, then continue below.

### Switch to Desktop Mode

1. Press the **STEAM** button.
2. Select **Power**.
3. Select **Switch to Desktop**.

Open a terminal (Konsole is preinstalled) once you're on the desktop.

### Install

```bash
sudo steamos-readonly disable
sudo pacman-key --init
sudo pacman-key --populate archlinux
sudo pacman -S --needed base-devel git
yay -S karincore-git
```

`steamos-readonly disable` unlocks the system partition so packages can actually install — SteamOS ships read-only by default. This survives until the next SteamOS system update, at which point you'll need to run it again before reinstalling/updating KarinCore.

### Launch

KarinCore appears in your application menu like any other desktop app. Paste in a `vless://` link (or import an `.ovpn`/`.conf`), select it in the side panel, and hit the core to connect.

When you're done, return to Game Mode from the desktop: **Return to Gaming Mode**.

<details>
<summary><b>Troubleshooting</b></summary>

A couple of issues have shown up on some SteamOS images that the package itself can't fix automatically — both are one-time system fixes, not KarinCore-specific.

**`error: ... signature from "GitLab CI Package Builder ... is unknown trust`** (usually shows up while installing `base-devel`)

Some SteamOS package rebuilds are signed with Valve's own CI key, which isn't always trusted by default on a fresh system. Fix:

```bash
grep "^SigLevel" /etc/pacman.conf   # note the current value to restore later
sudo sed -i 's/^SigLevel.*/SigLevel = TrustAll/' /etc/pacman.conf
sudo pacman -Syy
sudo pacman -S holo-keyring archlinux-keyring
sudo pacman-key --populate archlinux holo
sudo sed -i 's/^SigLevel.*/SigLevel = Required DatabaseOptional/' /etc/pacman.conf
sudo pacman -Scc   # clear the cache of packages that failed signature checks, then Y
```

Then retry the `base-devel`/`yay -S karincore-git` step.

**`feature 'edition2024' is required` / build fails partway through Rust compilation**

Means the system `rust` package on your SteamOS image is too old. Install a current toolchain via `rustup` instead:

```bash
sudo pacman -S rustup
rustup default stable
rustc --version   # should be recent
```

Then retry `yay -S karincore-git`.

**Build stops with a message about missing headers for `openssl`, `glibc`, or `linux-api-headers`**

Same underlying issue as above (some SteamOS images strip header files while pacman's database still lists the package as installed) — the build will print the exact command to run, something like:

```bash
sudo pacman -S --overwrite '/usr/include/*' openssl glibc linux-api-headers
```

Run whichever the message names, then retry `yay -S karincore-git`. (The build deliberately stops and asks instead of running this itself — a PKGBUILD calling `sudo` on its own is a red flag worth being suspicious of, so it doesn't.)

If you hit something else entirely, open an issue on GitHub — SteamOS images seem to vary more than expected in what's stripped out of them, and it helps to know.

</details>

<br/>

## KarinCore on Android (alpha)

KarinCore also has an **experimental Android version**: the same interface and routing model on top of Android's `VpnService` and Xray-core. It lives on the [`android` branch](https://github.com/detestern/KarinCore/tree/android) of this repository and is developed independently from the Linux client, with its own version stream (`0.x.y-alpha.n`).

**What works:** VLESS/Reality, VMess, Trojan and Shadowsocks links, subscriptions with routing import, Direct / Proxy / Block zones, per-app split tunneling, DNS settings, a diagnostics tab, and a home-screen widget.

**Install:**
1. Open [Releases](https://github.com/detestern/KarinCore/releases) and pick the newest entry tagged `android-v…` (they are marked *Pre-release*; the Linux releases stay the "Latest"). The same APKs are linked from [karincore.ru](https://karincore.ru).
2. Download the APK that matches your phone: `arm64-v8a` for almost every modern device, `armeabi-v7a` for older 32-bit ones.
3. Allow installing from your browser or file manager when Android asks, then open the APK.

**Heads-up:** these are alpha builds and updates are manual (the About page tells you when a newer version exists). Treat it as a test build, and please report problems in [Issues](https://github.com/detestern/KarinCore/issues). Build instructions are in the [`android` branch README](https://github.com/detestern/KarinCore/blob/android/README.md).

<br/>

## Architecture

Privileges are split between a single unprivileged app and a small set of root-side helpers.

**Frontend (`karincore`).** A Tauri GUI running entirely in user-space. It never runs as root itself. Privileged actions go through a single root-owned helper (`/usr/libexec/karincore/karincore-helper`), the only program the `karincore` group may run via `sudo`. It reads a request on stdin, validates it as root and performs the operation.

**Root side.** The `karin-proxy-daemon` systemd service runs Xray (or OpenVPN/WireGuard) with the generated config, and `route.sh` sets up the TUN interface, policy routing and DNS (`resolvectl`), then restores everything on disconnect.

This split means the entire graphical stack (webview, rendering, everything) runs unprivileged. Only the narrow slice that actually needs root does.

<br/>

## Recent releases

| Version | Name | What changed |
|---|---|---|
| [v1.6.0](CHANGELOG.md#v160--waypoint) | Waypoint | Connection scenarios: switch the VPN by Wi‑Fi network |
| [v1.5.5](CHANGELOG.md#v155--afterglow) | Afterglow | Zone pages use the full width, soft glow on hover |
| [v1.5.4](CHANGELOG.md#v154--compass) | Compass | Routing tab redesigned: priority cards and zone pages |
| [v1.5.3](CHANGELOG.md#v153--sonar) | Sonar | Ping of every server, two-block servers panel |
| [v1.5.2](CHANGELOG.md#v152--check-engine) | Check Engine | Diagnostics tab |
| 1.3.x | — | Handheld mode, hardening, subscription routing import |

Every release since 1.0.0, with dates, is in the **[full changelog →](CHANGELOG.md)**

<br/>

## Roadmap

KarinCore was built for Linux first, but the free internet doesn't stop at the OS boundary. Native **Windows** and **macOS** ports are the next major milestone. Next on the Linux and Android side: automatic switching to the next-best server when the connection drops, context profiles, per-app traffic stats and encrypted settings transfer.

<br/>

## Acknowledgments

Special thanks to **Maxim Gushter** ([VivaGushter](https://github.com/VivaGushter)) for his help with testing and developing the Android version.

<br/>

## Support, contributing, and feedback

Built and maintained by a single independent developer. Bug reports, pull requests, and UI/UX ideas are genuinely welcome: open an [issue](https://github.com/detestern/KarinCore/issues), or find the project at **[karincore.ru](https://karincore.ru)**.

If KarinCore keeps you connected and you'd like to support development, including the upcoming Windows/macOS ports, you can send a tip:

**USDT (TRC20):** `TQCQhGQD6xgaDxwqAVcTiapS6rdcPyf24X`

If this project is useful to you, a ⭐️ on the repo goes a long way.

<div align="center"><p><a href="README.md">🇬🇧 English</a> | <a href="README-ru.md">🇷🇺 Русский</a></p></div>
