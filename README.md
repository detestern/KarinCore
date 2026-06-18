<div align="center">
<img src="public/karincore-icon-main.png" alt="KarinCore Logo" width="200"/>
<h1>KarinCore</h1>
<p><strong>A modern, aesthetic, and secure proxy client for Linux</strong></p>
<p>
<a href="README.md">🇬🇧 English</a> | <a href="README-ru.md">🇷🇺 Русский</a>
</p>

![Platform](https://img.shields.io/badge/Platform-Linux-informational?style=flat&logo=linux)

![Built with Rust](https://img.shields.io/badge/Built_with-Rust-orange?style=flat&logo=rust)

![Tauri](https://img.shields.io/badge/Framework-Tauri-blue?style=flat&logo=tauri)

![License](https://img.shields.io/badge/License-MIT-green?style=flat)

</div>

  

## 🌌 Philosophy

The internet should be free, and the tools to protect it should be accessible and user-friendly.

KarinCore was built to end the struggle of configuring complex CLI utilities, writing endless JSON configs, and manually managing system services on Linux. It serves as a bridge between powerful, low-level anti-censorship protocols (like Xray) and an intuitive, highly aesthetic graphical interface.

No bloated Electron apps, no restrictive sandboxes breaking your system routing. Just a lightweight Rust core, native `systemd` integration, and a blazing-fast UI.

---



## ✨ Key Features

* **Multi-level Routing:** Full native integration of the OpenVPN and WireGuard protocols. Route your Xray traffic (VLESS/VMess/etc.) seamlessly over an encrypted OVPN or WG tunnel via PBR routing.
* **Visual Routing Priority (Drag & Drop):** Manage your Xray rule hierarchy visually. Simply drag and drop columns (Proxy, Direct, Block) from left to right to define the strict order of traffic processing.
* **Advanced Bypass Control & DNS Management:** Remove the system bypass with a single toggle to proxy the VPN server's own IP address. Built-in support for independent Domestic and Remote DNS servers (DoH/DoU).
* **Universal Parser & Route Profiles:** Instantly import `.ovpn` and `.conf` files, or parse `vless://`/`wg://` links directly from the clipboard. Save your perfect combinations of rules, column order, and DNS settings into local profiles for quick switching.
* **Native Integration & Session Isolation:** The core runs as a background system daemon (`karin-proxy-daemon.service`). It intelligently handles MTU (MSS Clamping) and automatically tears down tunnels before new connections to prevent leaks.
* **Seamless UX:** Thanks to dedicated `/etc/sudoers.d` rules, managing network interfaces, routing, and Geo-databases is just a click away. No annoying root password prompts.
* **Interactive Terminal Assistant:** Meet Karin — your built-in cyber-assistant. She monitors the core, asynchronously collects handshake logs, reacts to your actions, and respects your digital space without visual clutter.
* **Zero Telemetry & Absolute Privacy:** KarinCore operates entirely locally. No hidden trackers, no data collection, and no analytics. Your encryption keys, IP addresses, and routing profiles never leave your machine. Released under the open-source MIT License.
---

  

## 📸 Screenshots

<div align="center">
<img src=".github/assets/screenshot-main.jpeg" alt="Main Interface" width="45%"/>
<img src=".github/assets/screenshot-routing.jpeg" alt="Routing Options" width="45%"/>
</div>

---



## 🚀 Installation

KarinCore is designed for maximum compatibility with modern Linux distributions.



### Arch Linux (AUR)

The recommended installation method for Arch-based systems (Manjaro, EndeavourOS, etc.). This package will automatically compile the core, pull dependencies, and configure system services.

```bash

yay -S karincore-git

```



### Ubuntu / Debian / Linux Mint  

Check the [Releases](../../releases) page for the latest `.deb` package. It automatically configures `sudoers` and `systemd` rules during installation. Make sure you have `openvpn` and `wireguard-tools` installed on your system.

```bash
sudo dpkg -i KarinCore_1.2.3_amd64.deb
sudo apt install -f # if any dependencies are missing
```


### First Launch

Unlike standard system services, the KarinCore daemon should **not** be enabled in autostart (to prevent it from hijacking your traffic before the GUI generates a valid configuration). 

Do **not** use `systemctl enable`. Simply launch KarinCore from your desktop environment's application menu. The graphical interface will automatically start, manage, and safely stop the daemon as needed using pre-configured sudo rules.

Once the service is running, simply launch KarinCore from your desktop environment's application menu.



## 🛠 Architecture (Under the hood)

The application is cleanly separated into two independent binaries:

**1. Backend (```karin-proxy-daemon```):** A system service written in pure Rust. It runs as root, manages TUN interfaces, routing rules, and network traffic.

**2. Frontend (```karincore```):** A lightweight Tauri GUI running in user-space. It communicates with the daemon via IPC/sockets and safely restarts it using pre-configured sudoers rules.

This privilege separation keeps your system secure by avoiding running the entire graphical stack with superuser privileges.



## 🗺️ Roadmap (What's Next?)

While KarinCore was born natively for Linux, the free internet has no OS boundaries. 
**Cross-platform expansion is currently in the works:** Developing native versions for Windows and macOS is the next major milestone. Karin plans to take over other operating systems very soon!

## 🤝 Support, Contributing & Feedback

The project is created and maintained by a single independent developer. Bug reports, pull requests, and UI/UX ideas are highly appreciated! 

If KarinCore helps you stay connected to the free world and you want to support the ongoing development (including the upcoming Windows port), you can buy me a coffee or donate via crypto:

* **USDT (TRC20):** `TQCQhGQD6xgaDxwqAVcTiapS6rdcPyf24X`

If you find this tool useful, please consider giving this repository a ⭐️!

<div align="center"><p><a href="README.md">🇬🇧 English</a> | <a href="README-ru.md">🇷🇺 Русский</a></p></div>