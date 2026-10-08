<div align="center">
<img src="public/karincore-icon-main.png" alt="KarinCore Logo" width="180"/>
<h1>KarinCore</h1>
<p><strong>A modern, aesthetic, and secure proxy client for Linux</strong></p>
<p>
<a href="README.md">🇬🇧 English</a> | <a href="README-ru.md">🇷🇺 Русский</a>
</p>

<p>
<img src="https://img.shields.io/badge/version-1.3.8-dc8add?style=flat-square&labelColor=11111b" alt="Version"/>
<img src="https://img.shields.io/badge/platform-linux-dc8add?style=flat-square&labelColor=11111b&logo=linux&logoColor=dc8add" alt="Platform"/>
<img src="https://img.shields.io/badge/built_with-rust-dc8add?style=flat-square&labelColor=11111b&logo=rust&logoColor=dc8add" alt="Built with Rust"/>
<img src="https://img.shields.io/badge/framework-tauri-dc8add?style=flat-square&labelColor=11111b&logo=tauri&logoColor=dc8add" alt="Tauri"/>
<img src="https://img.shields.io/badge/license-MIT-dc8add?style=flat-square&labelColor=11111b" alt="License"/>
</p>
</div>

<br/>

## Philosophy

The internet should be free, and the tools that protect it shouldn't feel like a chore to run.

KarinCore exists to end the ritual of hand-editing JSON configs, wrestling with `iptables`, and babysitting systemd units just to get a working tunnel on Linux. It's the bridge between a genuinely powerful anti-censorship core (Xray, OpenVPN, WireGuard) and an interface that respects your time and your eyes.

No Electron. No sandbox fighting your routing table. A Rust core, native `systemd` integration, and a UI built specifically for this app — not a generic template with a proxy client bolted on.

<br/>

## What's new in 1.3

This release is a full visual and functional overhaul, not just a patch.

* **A new connection core.** The connect button is gone — replaced by an animated graph-core visual: a bracket cursor that types itself open on connect, radiating nodes that light up in sequence, and a breathing pulse while the tunnel is live. Disconnecting runs the exact same animation in reverse.
* **A real kill switch.** Enable it in Settings and KarinCore drops all outbound traffic at the firewall level the moment the tunnel disappears unexpectedly — not just when you disconnect on purpose. Rules persist through a daemon crash-and-restart cycle, which is the entire point of a kill switch.
* **Profiles moved out of the way.** Your saved configs now live in a slide-out side panel instead of eating vertical space on the main screen. Pick one, it lights up with a soft accent glow, and you're back on the connect screen — the big glowing core is the only thing competing for your attention.
* **A light theme worth using.** The old light mode was a near-inversion of the dark one. It's been rebuilt from scratch with warm, low-contrast neutrals — readable without feeling like a different app.
* **A calmer routing tab.** Same drag-and-drop priority system, same DNS controls, thinner borders and a bit of restraint.

<br/>

### v1.3.8 — Subscription Routing Import

* **Fixed:** routing and DNS delivered by a subscription in the `routing` HTTP response header (Happ format — how mobile clients receive it) were ignored, because only the response body was read. They are now saved as a dedicated routing profile named after the subscription — rules for direct / proxy / block and the default-route mode (`GlobalProxy`). Pick it with the Select button when you want to use it: your current routing and DNS are never replaced automatically, and DNS from the subscription is not imported (those endpoints are tuned for mobile clients). Re-adding the same subscription refreshes its profile. Rule order and domain strategy have no equivalent in KarinCore's UI and are intentionally not imported.
* **Fixed:** with Kill Switch enabled, traffic routed to the Direct zone was dropped by the firewall together with everything else, so Direct rules silently stopped working. Traffic Xray sends to its direct outbound (marked `255`) is now allowed through the Kill Switch; everything else is still blocked if the tunnel drops.
* **Fixed:** a zone with both domain and IP rules (e.g. `domain:.pro` plus `geoip:ru` in Direct) was compiled into one Xray rule whose conditions are AND-ed, so a domain only matched if its IP matched too and such Direct rules silently did nothing. Domains and IPs now become separate rules.

### v1.3.7 — Dead Code & Window Dragging Fix

* **Fixed:** dragging the window by its custom titlebar silently did nothing on some systems — Tauri v2 requires the `core:window:allow-start-dragging` permission for a frameless window's `data-tauri-drag-region` to actually work, and it was missing from the app's capabilities file.
* **Removed:** the dead `karin-proxy-daemon` Cargo binary target — a leftover HTTP server (port 9090) from an earlier architecture that applied config over HTTP and restarted the service. Nothing calls it: the actual `karin-proxy-daemon.service` systemd unit runs Xray directly. It, and its unused `axum` dependency, were only adding unnecessary build time.

### v1.3.6 — Routing Cleanup & Subscription Import

* **Fixed:** `route.sh` left stale `ip rule` entries for local-subnet bypasses (loopback, private ranges) behind after disconnecting, and zeroed out the `rp_filter` sysctl on connect without ever restoring it. Both are now cleaned up on disconnect, mirroring the existing `resolv.conf` backup/restore pattern.
* **Fixed:** importing a full JSON subscription (one with its own `routing`/`dns` blocks, rather than plain proxy links) silently discarded that routing and DNS configuration. It's now translated into KarinCore's own routing zones and DNS settings and merged additively into your existing configuration. The subscription's `policy` block (buffer sizes, timeouts) has no equivalent in KarinCore's UI and is intentionally not imported.

### v1.3.5 — Protocol & Ping Fixes

* **Fixed:** importing a VMess, Trojan, or Shadowsocks link silently built a broken VLESS outbound instead — every protocol other than VLESS/OpenVPN/WireGuard was treated as VLESS without any error. All four protocols (VLESS, VMess, Trojan, Shadowsocks) are now parsed and proxied correctly.
* **Fixed:** the Ping button and the IP display measured latency through the app's general-purpose local proxy port, which obeys the same routing rules as the rest of your traffic — if your test target happened to match a "direct" rule, the result silently reflected your direct connection instead of the tunnel. Ping and IP checks now go through a dedicated path that's always forced through the proxy.

### v1.3.4 — TUN Config Schema Fix

* **Fixed:** the TUN inbound config shipped an `autoRoute: true` field that doesn't exist in Xray-core's actual schema (the real field is `autoSystemRoutingTable`, an array, not a boolean) — Xray silently ignored it, so it never did anything. Removed it; routing was always correctly handled by KarinCore's own `route.sh`, not by Xray.

### v1.3.3 — DNS / systemd-resolved Fix

* **Fixed:** on systems using `systemd-resolved` (CachyOS, Fedora, and most modern distros), DNS lookups could silently fail inside the tunnel — `systemd-resolved`'s NSS module bypasses `/etc/resolv.conf` entirely, so the app's previous approach of rewriting that file had no effect. `route.sh` now drives DNS through `resolvectl` when it's available, falling back to the old `resolv.conf` method otherwise.
* **Fixed:** domestic and remote DNS resolution now happens inside Xray itself, split by the same direct/proxy routing rules as your traffic — each resolver (DoH or plain DNS) is dispatched through its own outbound, so domestic DNS never gets needlessly tunneled and remote DNS never leaks in plaintext.

### v1.3.2 — Sudoers Hardening

* **Fixed:** a set of sudoers rules let the app copy an arbitrary file into `/usr/local/bin/xray` and mark it executable — Xray is now used exclusively from the package-managed binary, and the app only checks its version instead of ever downloading or replacing it.
* **Fixed:** every privileged rule the app installs is now scoped to a dedicated `karincore` group instead of every account on the machine (a new post-install hook creates it and adds you to it).
* **Fixed:** an imported OpenVPN or WireGuard profile could contain directives (`up`, `PostUp`, etc.) that execute external commands — these are now stripped before the tunnel starts, since these configs run with root privileges.

### v1.3.1 — Handheld Mode

* **Fixed:** every sudo call from the GUI silently required a password on systems where the user is in the `wheel` group (the default on Arch/SteamOS) — the app's own sudoers rules were being shadowed by the system's password-requiring wheel rule due to alphabetical file ordering. This was the real root cause behind the recurring "permission denied" errors on Steam Deck.
* **Fixed:** the connection core and its surrounding UI now scale proportionally on smaller or unusual screen resolutions (like Steam Deck's) instead of overlapping.
* See [KarinCore on Steam Deck](#karincore-on-steam-deck) below — full install guide for handheld users.

<br/>

## Key features

**Multi-level routing.** Native OpenVPN and WireGuard integration alongside Xray. Wrap VLESS/VMess traffic inside an encrypted OVPN or WireGuard tunnel via policy-based routing, or run Xray directly — your call.

**Visual routing priority.** Drag columns — Proxy, Direct, Block — to set the exact order Xray evaluates rules. No editing JSON rule arrays by hand.

**Kill switch.** Real firewall-level enforcement, not a checkbox that only remembers your preference. See [What's new in 1.3](#whats-new-in-13) above.

**Bypass and DNS control.** Toggle proxying of the VPN server's own IP with one switch. Independent Domestic and Remote DNS resolvers with DoH/DoU support.

**Universal parser and profiles.** Drop in `.ovpn` and `.conf` files, or paste `vless://`/`wg://` links straight from the clipboard. Save full setups — rules, column order, DNS — as named profiles.

**Native system integration.** The core runs as a background daemon (`karin-proxy-daemon.service`), with MTU handling and automatic tunnel teardown before every new connection to avoid leaks.

**Zero-prompt privilege model.** A tightly scoped `/etc/sudoers.d` rule set means the GUI can manage interfaces, routing, and the daemon without a single root password prompt during normal use.

**Karin.** The built-in terminal assistant narrates what the core is doing — connection status, DNS checks, the occasional dry joke about your ISP. Twenty lines and counting. Can be turned off in Settings if you'd rather have silence.

**Zero telemetry.** Everything runs locally. No trackers, no analytics, no phone-home. Your keys, IPs, and routing profiles never leave your machine. MIT licensed, source fully open.

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

### Troubleshooting

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

<br/>

## Installation

### Arch Linux (AUR)

The recommended path for Arch-based systems (Manjaro, EndeavourOS, and the rest). Builds the core, pulls dependencies, and wires up system services automatically.

```bash
yay -S karincore-git
```

### Ubuntu / Debian / Linux Mint

Grab the latest `.deb` from [Releases](../../releases). It registers `sudoers` and `systemd` rules on install. Make sure `openvpn` and `wireguard-tools` are present on your system first. The `.deb` does not bundle Xray: install it separately so that the binary is available at `/usr/local/bin/xray` (e.g. via [XTLS/Xray-install](https://github.com/XTLS/Xray-install)).

```bash
sudo dpkg -i KarinCore_1.3.8_amd64.deb
sudo apt install -f # only if dependencies are missing
```

### First launch

The daemon should **not** be enabled at boot — that would let it start routing traffic before the GUI has generated a valid config.

Don't run `systemctl enable` on it. Just launch KarinCore from your application menu; the GUI starts, monitors, and stops the daemon on its own using the pre-configured sudo rules.

<br/>

## Architecture

Privileges are split between a single unprivileged app and a small set of root-side helpers:

**Frontend (`karincore`)** — a Tauri GUI running entirely in user-space. It never runs as root itself. Privileged actions go through a fixed set of pre-approved `sudo` commands, allowed only for members of the `karincore` group.

**Root side** — the `karin-proxy-daemon` systemd service runs Xray (or OpenVPN/WireGuard) with the generated config, and `route.sh` sets up the TUN interface, policy routing and DNS (`resolvectl`), then restores everything on disconnect.

This split means the entire graphical stack — webview, rendering, everything — runs unprivileged. Only the narrow slice that actually needs root does.

<br/>

## Changelog

<details>
<summary>1.2.x and earlier</summary>

**1.2.8** — Fixed the app redundantly re-downloading Xray on every launch when it was already present as a system package (Arch/AUR/SteamOS), which also caused a spurious sudo prompt at startup.

**1.2.7** — Fixed a set of privileged commands being invoked without a fully-qualified path, which could silently fail with a permission error depending on shell PATH resolution.

**1.2.6** — Shipped the daemon's systemd unit and routing script inside the `.deb` package itself (previously missing on clean installs). Fixed the update checker reporting stale versions. Fixed the need to click Connect twice on a cold start. Clearer daemon-failure error messages.

</details>

Full history on the [Releases](../../releases) page.

<br/>

## Roadmap

KarinCore was built for Linux first, but the free internet doesn't stop at the OS boundary. Native **Windows** and **macOS** ports are the next major milestone — Karin isn't staying put.

<br/>

## Support, contributing, and feedback

Built and maintained by a single independent developer. Bug reports, pull requests, and UI/UX ideas are genuinely welcome.

If KarinCore keeps you connected and you'd like to support development — including the upcoming Windows/macOS ports — you can send a tip:

**USDT (TRC20):** `TQCQhGQD6xgaDxwqAVcTiapS6rdcPyf24X`

If this project is useful to you, a ⭐️ on the repo goes a long way.

<div align="center"><p><a href="README.md">🇬🇧 English</a> | <a href="README-ru.md">🇷🇺 Русский</a></p></div>
