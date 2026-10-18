# Changelog

KarinCore for Linux: every release, newest first. The Android port is developed on the [`android` branch](https://github.com/detestern/KarinCore/tree/android) and keeps its own log there.

<p><a href="CHANGELOG.md">🇬🇧 English</a> | <a href="CHANGELOG-ru.md">🇷🇺 Русский</a> · <a href="README.md">← README</a></p>


## v1.5.4 — Compass

<sub>2026-10-18</sub>

* **Changed:** the Routing tab now works the same way as in the Android app. A summary at the top shows the selected routing profile (the one last applied or saved) and the default route. Below it, Proxy, Direct and Block are three cards from left to right in order of priority. Drag a card to change the priority.
* **Added:** a zone page. Click a card to open it: the zone's rules with delete buttons, "Add rule", "Make default" and a priority control with left and right buttons. Esc or the back button closes it.
* **Changed:** the DNS cards, saved profiles and the two switches (proxy the server IP, proxy the local network) keep their logic and sit in a calmer layout under the cards. The three-column grid stays in the page only as a hidden store of the rules.

## v1.5.3 — Sonar

<sub>2026-10-16</sub>

* **Added:** a **Ping** button in the configurations panel. One tap measures the response time of every server in the list and shows it as a badge next to the name: green up to 250 ms, yellow up to 500 ms, red above that, grey when the server does not respond. The list order does not change. While the VPN is on, the measurement goes through the tunnel, so the badges are dimmed and a short note says so.
* **Changed:** the configurations panel is split into two blocks, as on Android: a card for adding a link or a subscription, and a separate "My servers" block with a counter and the Ping button. The header buttons now share one style.

## v1.5.2 — Check Engine

<sub>2026-10-16</sub>

* **Added:** a **Diagnostics** tab that answers "why isn't it working?". One button runs the chain: internet, DNS, the server's port, and a request through the tunnel to `cp.cloudflare.com`. Each step shows its own result, and under them Karin says in plain words what is wrong and offers one next step (switch the server, update the subscription, open routing, restart the core). "Details" shows every step, the raw probe results and the last lines of the Xray log.
* **Added:** the check tells a closed or blocked server port (refused, timed out or no route), a server that is reachable but rejects the handshake (usually outdated subscription data), a tunnel that connects but carries no traffic, a stopped Xray core, and a Kill Switch that blocks traffic because the tunnel is down. The verdict logic is a separate module with unit tests.

## v1.5.1 — Dual Stack

<sub>2026-10-13</sub>

* **Added:** IPv6. The tunnel carries IPv6 next to IPv4 (`ip -6` rules and table 100, a private /126 on `tun0`), local IPv6 ranges (`fc00::/7`, `fe80::/10`) and the server's own address of either family stay outside the tunnel, "proxy the server itself" works for IPv6 addresses, and the kill switch now also installs `ip6tables` rules (loopback, tunnel, server, Xray's own marked traffic, then DROP).
* **Fixed:** DNS routing follows the Xray documentation: every DNS server gets a `tag` and a routing rule with `inboundTag` sends its queries to `direct` or `proxy` (the non-existent `outboundTag` on DNS servers is gone). The local DNS inbound answers over `tcp,udp`.
* **Fixed:** a subscription header `routing-enable: 0` (also `false`/`off`/`no`) really disables routing import, and a `happ://routing/…` line inside the subscription body is imported when there is no `Routing` header.
* **Fixed:** Xray is checked when you press Connect and the error is shown in the app (missing, cannot start, version output unreadable, older than 25.6.8) instead of being swallowed at startup. The one supported path is `/usr/bin/xray`: the systemd unit, the app and the docs all use it, and the `.deb` creates a link there if Xray is only in `/usr/local/bin`.
* **Fixed:** JSON subscriptions with Trojan, Shadowsocks, VMess and other transports (TLS, XHTTP) are converted to links instead of being skipped; `route.sh` reads the server address from `vnext[0]` or `servers[0]`; IPv6 hosts such as `[2001:db8::1]` are parsed in links, WireGuard endpoints and `ss://`.
* **Changed:** installing or upgrading removes leftovers of older versions from `/etc/karin-proxy` (`resolv.conf.vpn`, old logs, OpenVPN/WireGuard configs when no tunnel is up) and sets `0600` on configs; the `.deb` no longer contains a second copy of the helper in `/usr/bin`.

## v1.5.0 — Privilege Boundary

<sub>2026-10-13</sub>

* **Security:** the long list of `sudo` rules is gone. Members of the `karincore` group can now run exactly one root-owned program, `/usr/libexec/karincore/karincore-helper`, and only with no arguments. The app sends a request over stdin and the helper validates it as root: operations come from a fixed list, parameters use a strict character set, and Xray / OpenVPN / WireGuard configs are re-built from an allowlist of options. Scripts, hooks, plugins, arbitrary file paths and log paths are rejected. Previously the raw `cp`, `openvpn`, `wg-quick`, `ip` and `iptables` rules could be turned into root by any group member.
* **Security:** HTML injection through profile, group and rule names (subscriptions, imports) is fixed, and a strict Content-Security-Policy is now set.
* **Security:** the local proxy password is generated from the system CSPRNG instead of the clock.
* **Changed:** logs are written to `/var/log/karin-proxy` and cleared via the helper; the package creates the `karincore` group and adds the installing user.
* **Added:** CI (tests, clippy, build, shellcheck, sudoers check, `.deb` smoke test).

## v1.4.0 — Shell Bridge

<sub>2026-10-12</sub>

* **Added:** a bridge for external shells and panels (karin-shell / Brain Shell). While the app runs it keeps a status file, `${XDG_STATE_HOME:-~/.local/state}/karincore/shell.json`, written atomically (`shell.json.tmp` → rename) whenever the connection state, the selected profile, the profile list or the public IP changes, at start and on exit (closing the window included):

  ```json
  {
    "bridge": 1,
    "app_version": "1.4.0",
    "pid": 4242,
    "state": "connected",
    "selected": "ba7816bf8f01",
    "profile_name": "Netherlands (nl.example.com)",
    "ip": "203.0.113.5",
    "profiles": [
      { "id": "ba7816bf8f01", "name": "Netherlands (nl.example.com)", "type": "vless", "group": "provider.example" }
    ],
    "updated": 1760000000
  }
  ```

  `state` is `disconnected`, `connecting` or `connected`; `pid` is `0` after exit (together with `state: "disconnected"` and an empty `ip`). `type` is `vless`, `vmess`, `trojan`, `shadowsocks`, `wireguard` or `openvpn`. A profile `id` is stable and not secret: the first 12 hex characters of `sha256(link)`. Links, keys, UUIDs and passwords never reach the file.
* **Added:** command-line flags. `karincore --connect [id]` selects the profile (if given) and connects, starting the app with its window if it is not running; `karincore --disconnect` disconnects (does nothing if the app is not running); `karincore --select id` selects a profile without connecting. Launching the app again hands the flags to the running instance (`tauri-plugin-single-instance`) and no second window opens. In the running app the flags do exactly what the buttons on the main screen do, core animation included. Flags can be combined: `karincore --select <id> --connect`.
* **Unchanged:** closing the window still turns the VPN off.

## v1.3.10 — Living Core

<sub>2026-10-12</sub>

* **Changed:** the connection core now plays out the whole sequence. While connecting, the network spins up fast, the lines and nodes light up in pink and waves run out from the ring. Once connected, it settles into a slow turn, the nodes turn green and the ring breathes. On disconnect the rotation slows to a stop and the ring sends out one last wave.
* **Changed:** the core is lifted by 30 px, so its lower lines no longer touch the status text.

## v1.3.9 — Rotating Core

<sub>2026-10-11</sub>

* **Changed:** the core on the main screen now keeps turning while connected. The network of lines and nodes rotates slowly around the ring, which stays in place and breathes as before; when you disconnect, the rotation pauses where it is instead of snapping back.
* **Changed:** the core drawing is slightly smaller inside its block, so the turning nodes never touch the status text.

## v1.3.8 — Subscription Routing Import

<sub>2026-10-08</sub>

* **Fixed:** routing and DNS delivered by a subscription in the `routing` HTTP response header (Happ format — how mobile clients receive it) were ignored, because only the response body was read. They are now saved as a dedicated routing profile named after the subscription — rules for direct / proxy / block and the default-route mode (`GlobalProxy`). Pick it with the Select button when you want to use it: your current routing and DNS are never replaced automatically, and DNS from the subscription is not imported (those endpoints are tuned for mobile clients). Re-adding the same subscription refreshes its profile. Rule order and domain strategy have no equivalent in KarinCore's UI and are intentionally not imported.
* **Fixed:** with Kill Switch enabled, traffic routed to the Direct zone was dropped by the firewall together with everything else, so Direct rules silently stopped working. Traffic Xray sends to its direct outbound (marked `255`) is now allowed through the Kill Switch; everything else is still blocked if the tunnel drops.
* **Fixed:** a zone with both domain and IP rules (e.g. `domain:.pro` plus `geoip:ru` in Direct) was compiled into one Xray rule whose conditions are AND-ed, so a domain only matched if its IP matched too and such Direct rules silently did nothing. Domains and IPs now become separate rules.

## v1.3.7 — Dead Code & Window Dragging Fix

<sub>2026-10-08</sub>

* **Fixed:** dragging the window by its custom titlebar silently did nothing on some systems — Tauri v2 requires the `core:window:allow-start-dragging` permission for a frameless window's `data-tauri-drag-region` to actually work, and it was missing from the app's capabilities file.
* **Removed:** the dead `karin-proxy-daemon` Cargo binary target — a leftover HTTP server (port 9090) from an earlier architecture that applied config over HTTP and restarted the service. Nothing calls it: the actual `karin-proxy-daemon.service` systemd unit runs Xray directly. It, and its unused `axum` dependency, were only adding unnecessary build time.

## v1.3.6 — Routing Cleanup & Subscription Import

<sub>2026-10-02</sub>

* **Fixed:** `route.sh` left stale `ip rule` entries for local-subnet bypasses (loopback, private ranges) behind after disconnecting, and zeroed out the `rp_filter` sysctl on connect without ever restoring it. Both are now cleaned up on disconnect, mirroring the existing `resolv.conf` backup/restore pattern.
* **Fixed:** importing a full JSON subscription (one with its own `routing`/`dns` blocks, rather than plain proxy links) silently discarded that routing and DNS configuration. It's now translated into KarinCore's own routing zones and DNS settings and merged additively into your existing configuration. The subscription's `policy` block (buffer sizes, timeouts) has no equivalent in KarinCore's UI and is intentionally not imported.

## v1.3.5 — Protocol & Ping Fixes

<sub>2026-10-02</sub>

* **Fixed:** importing a VMess, Trojan, or Shadowsocks link silently built a broken VLESS outbound instead — every protocol other than VLESS/OpenVPN/WireGuard was treated as VLESS without any error. All four protocols (VLESS, VMess, Trojan, Shadowsocks) are now parsed and proxied correctly.
* **Fixed:** the Ping button and the IP display measured latency through the app's general-purpose local proxy port, which obeys the same routing rules as the rest of your traffic — if your test target happened to match a "direct" rule, the result silently reflected your direct connection instead of the tunnel. Ping and IP checks now go through a dedicated path that's always forced through the proxy.

## v1.3.4 — TUN Config Schema Fix

<sub>2026-10-02</sub>

* **Fixed:** the TUN inbound config shipped an `autoRoute: true` field that doesn't exist in Xray-core's actual schema (the real field is `autoSystemRoutingTable`, an array, not a boolean) — Xray silently ignored it, so it never did anything. Removed it; routing was always correctly handled by KarinCore's own `route.sh`, not by Xray.

## v1.3.3 — DNS / systemd-resolved Fix

<sub>2026-10-02</sub>

* **Fixed:** on systems using `systemd-resolved` (CachyOS, Fedora, and most modern distros), DNS lookups could silently fail inside the tunnel — `systemd-resolved`'s NSS module bypasses `/etc/resolv.conf` entirely, so the app's previous approach of rewriting that file had no effect. `route.sh` now drives DNS through `resolvectl` when it's available, falling back to the old `resolv.conf` method otherwise.
* **Fixed:** domestic and remote DNS resolution now happens inside Xray itself, split by the same direct/proxy routing rules as your traffic — each resolver (DoH or plain DNS) is dispatched through its own outbound, so domestic DNS never gets needlessly tunneled and remote DNS never leaks in plaintext.

## v1.3.2 — Sudoers Hardening

<sub>2026-10-02</sub>

* **Fixed:** a set of sudoers rules let the app copy an arbitrary file into `/usr/local/bin/xray` and mark it executable — Xray is now used exclusively from the package-managed binary, and the app only checks its version instead of ever downloading or replacing it.
* **Fixed:** every privileged rule the app installs is now scoped to a dedicated `karincore` group instead of every account on the machine (a new post-install hook creates it and adds you to it).
* **Fixed:** an imported OpenVPN or WireGuard profile could contain directives (`up`, `PostUp`, etc.) that execute external commands — these are now stripped before the tunnel starts, since these configs run with root privileges.

## v1.3.1 — Handheld Mode

<sub>2026-08-26</sub>

* **Fixed:** every sudo call from the GUI silently required a password on systems where the user is in the `wheel` group (the default on Arch/SteamOS) — the app's own sudoers rules were being shadowed by the system's password-requiring wheel rule due to alphabetical file ordering. This was the real root cause behind the recurring "permission denied" errors on Steam Deck.
* **Fixed:** the connection core and its surrounding UI now scale proportionally on smaller or unusual screen resolutions (like Steam Deck's) instead of overlapping.
* See [KarinCore on Steam Deck](#karincore-on-steam-deck) below — full install guide for handheld users.

## v1.3.0 — New Look & Real Kill Switch

<sub>2026-08-25</sub>

* **Changed:** a new connection core. The connect button is gone, replaced by an animated graph-core visual: a bracket cursor that types itself open on connect, radiating nodes that light up in sequence, and a breathing pulse while the tunnel is live. Disconnecting runs the same animation in reverse.
* **Added:** a real kill switch. Enable it in Settings and KarinCore drops all outbound traffic at the firewall level the moment the tunnel disappears unexpectedly, not just when you disconnect on purpose. Rules persist through a daemon crash-and-restart cycle.
* **Changed:** profiles moved out of the way. Saved configs live in a slide-out side panel instead of eating vertical space on the main screen; the selected one lights up with a soft accent glow.
* **Changed:** the light theme was rebuilt from scratch on warm, low-contrast neutrals. The old one was a near-inversion of the dark theme.
* **Changed:** a calmer routing tab: the same drag-and-drop priority system and DNS controls, with thinner borders and more restraint.

## v1.2.8 — System Xray Detection

<sub>2026-08-25</sub>

* **Fixed:** the app re-downloaded Xray on every launch even when it was already provided by a system package (Arch/AUR/SteamOS) at a different path. This also stopped a spurious sudo prompt at startup.

## v1.2.7 — Sudo Path Reliability

<sub>2026-08-25</sub>

* **Fixed:** a set of privileged commands (config writes, geo-database updates, tunnel teardown) was invoked without a fully-qualified path, which could silently fail with a permission error depending on how the shell resolved `PATH`.

## v1.2.6 — Reliability & Packaging Fixes

<sub>2026-08-24</sub>

* **Fixed:** the daemon's systemd unit and the routing script were missing from the package, so a clean install did not connect. They now ship inside the `.deb`.
* **Fixed:** the in-app update checker reported an outdated version while the latest release was running.
* **Fixed:** you had to press Connect twice on a cold start. The fixed startup delay was replaced with an active readiness check of the core.
* **Changed:** clearer error messages when the daemon fails to start, including explicit detection of a missing service.

## v1.2.5 — Debian Compatibility & Core Auto-Deploy

<sub>2026-06-25</sub>

* **Changed:** the strict `xray` package dependency is gone, so the app installs cleanly on Debian, Ubuntu and Linux Mint.
* **Added:** Xray (v26.5.9) is downloaded and deployed automatically in the background on first launch.
* **Fixed:** permission errors during config generation and race conditions while the tunnel came up.

## v1.2.4 — LAN Bypass Control

<sub>2026-06-23</sub>

* **Added:** a toggle that sends local network traffic (10.x, 192.168.x, 172.x) directly or through the proxy.

## v1.2.3 — Visual Routing Priority

<sub>2026-06-18</sub>

* **Added:** drag and drop for routing columns. The priority of Xray rules is now set visually, from left to right.

## v1.2.2 — Bypass Control

<sub>2026-06-17</sub>

* **Added:** a toggle that removes the system bypass and proxies the IP address of the VPN server itself.

## v1.2.1 — WireGuard & Privacy

<sub>2026-06-02</sub>

* **Added:** the WireGuard protocol with policy-based routing (Matryoshka mode: Xray over WireGuard).
* **Added:** an asynchronous log collector for the WireGuard tunnel state (handshakes and traffic).
* **Added:** a universal configuration parser: import `.ovpn` and `.conf` files or `wg://` links.
* **Changed:** the About page now carries the Zero Telemetry statement and the legal information (MIT License).

## v1.2.0 — Multi-level Routing

<sub>2026-06-02</sub>

* **Added:** full native OpenVPN integration (Matryoshka mode: Xray over OpenVPN).
* **Added:** a silent background update check through the GitHub API.
* **Fixed:** automatic download of the geo databases (geosite/geoip) and its system permissions.
* **Changed:** custom dropdown menus and a clearer separation of the workspace.
* **Changed:** Karin's terminal vocabulary gained new interactive phrases.

## v1.1.0 — Isolation & Control

<sub>2026-06-01</sub>

* **Added:** smart MTU control (MSS clamping) against packet fragmentation.
* **Added:** session isolation: tunnels are torn down automatically before a new connection.
* **Added:** dynamic management of the system DNS (leak and DoH conflict prevention).
* **Changed:** ping optimization for VLESS profiles.

## v1.0.1 — Colors & Cultures

<sub>2026-05-31</sub>

* **Added:** a full light and dark theme.
* **Added:** the Turkish localization.
* **Fixed:** links to the GitHub repository.

## v1.0.0 — KarinCore Ready

<sub>2026-05-30</sub>

* **Changed:** the Xray core and the system daemon integration were stabilized.
* **Added:** dynamic protection of the local port (Zero Trust Auth).
* **Added:** an interactive terminal with the Karin assistant.
* **Added:** a custom frameless window and a splash screen.
* **Added:** deep cloning and saving of routing profiles.
* **Changed:** closing the app is now tied to stopping the daemon.
