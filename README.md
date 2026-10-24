# 80211ORCA

> **Automatic passive/active WiFi handshake sniffer**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?logo=linux&logoColor=white)
![Status](https://img.shields.io/badge/Status-Beta-yellow)
![License](https://img.shields.io/badge/License-MIT-green)

```
⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠺⢿⣿⣿⣿⣿⣿⣿⣷⣦⣠⣤⣤⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿HACK⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⣿⣿⣷⣄⠀⠀
⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⠀⠀⠀⣀⣿⣿⣿⣆⠀
⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄
⠀⠀⠀⠀⣾⣿⣿⡿⠋⠁⣀⣠⣬⣽⣿⣿THE⣿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠁
⠀⠀⠀⢀⣿⣿⡏⢀⣴⣿⠿⠛⠉⠉⠀⢸⣿⣿⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣿⣿⢠⣾⡟⠁⠀⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣿⣿⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣸⣿⣿⣿⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢠⣾⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣾PLANET⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⣿⡿⠛⠉⠀⠀⠀⠈⠙⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```

---

## ⚠️ Legal Disclaimer

**This tool is provided strictly for educational and authorized security research purposes.**

80211ORCA is designed to help security researchers, network administrators, and students understand how WiFi handshake capture works and how WPA/WPA2 authentication can be audited in a controlled environment.

You **must** only use this tool on networks you own or for which you have **explicit written authorization** from the network owner. Unauthorized interception of WiFi traffic, deauthentication attacks, and handshake capture on third-party networks are **illegal** in most jurisdictions, including (but not limited to):

- **Italy** — Art. 615-ter, 615-quater, 617-sexies c.p.
- **European Union** — Directive 2013/40/EU
- **United States** — Computer Fraud and Abuse Act (CFAA)
- **United Kingdom** — Computer Misuse Act 1990

The author assumes **no liability** for any misuse, damage, or legal consequences arising from the use of this software. By using 80211ORCA you accept full responsibility for your actions.

---

## 📖 Overview

**80211ORCA** is a Python tool that captures WPA/WPA2 4-way handshakes (EAPOL packets) from nearby WiFi networks.

It works in two modes:

| Mode | Description |
|------|-------------|
| **Passive** | Silently listens on a channel and saves any EAPOL packets it sees to a `.pcap` file. No interaction with the network. |
| **Active** | Detects WPA/WPA2 beacon frames and sends targeted deauthentication frames to force clients to re-authenticate, accelerating handshake capture. |

Captured `.pcap` files are fully compatible with tools like `aircrack-ng`, `hashcat`, and `hcxtools` for offline password auditing (on networks you are authorized to test).

---

## ✨ Features

- 🔍 **Passive & Active modes** — choose between silent capture or deauth-assisted capture.
- 🧠 **Smart target management** — beacon deduplication with automatic 10-second expiry to avoid re-attacking the same AP.

---

## 🧰 Requirements

- **Linux**
- **Python 3.8+**
- **Root privileges** (required for raw socket access)
- A **wireless adapter** that supports **monitor mode** and **packet injection** (for active mode)

### Python dependencies

```bash
pip install scapy rich psutil
```

### System dependencies

- `iw` / `iwconfig` — for channel switching
- `aircrack-ng` / `hashcat` — for offline handshake cracking (optional but recommended)

---

## 🚀 Installation

```bash
git clone https://github.com/n0nexist/80211ORCA.git
cd 80211ORCA
pip install -r requirements.txt
```

---

## 🕹️ Usage

```bash
sudo python3 80211orca.py
```

---

## 📂 Output

Captured handshakes are saved to a `.pcap` file in the working directory, named as:

```
DD_MM_YYYY__HH-MM.pcap
```

---

## 🏗️ How it works

```
┌─────────────────────────────────────────────────────────────┐
│                        scapy.sniff()                        │
│                     (single capture loop)                   │
└───────────────────────────┬─────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
       ┌──────▼──────┐             ┌──────▼──────┐
       │   EAPOL?    │             │  Beacon?    │
       │  (passive)  │             │  (active)   │
       └──────┬──────┘             └──────┬──────┘
              │                           │
       ┌──────▼──────┐             ┌──────▼──────┐
       │ Write PCAP  │             │  Dedup +    │
       │             │             │  WPA check  │
       └─────────────┘             └──────┬──────┘
                                          │
                                   ┌──────▼──────┐
                                   │  Deauth     │
                                   │  (thread)   │
                                   └─────────────┘
```

- **Passive mode** uses a single `sniff()` loop that writes only EAPOL frames to the PCAP file.
- **Active mode** uses the same loop, but also processes beacon frames: each new WPA/WPA2 BSSID is registered in a target list and deauthenticated every 10 seconds.
- WPA3/SAE, open (`OPN`), WEP and unknown-crypto networks are **skipped**, since they don't produce a crackable WPA/WPA2 handshake.

---

## 🖥️ Setting up the adapter

80211ORCA assumes your adapter is **already in monitor mode** and set to the correct channel. If you need to prepare it manually:

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
```

Or use `airmon-ng`:

```bash
sudo airmon-ng start wlan0
sudo airmon-ng check kill
```

---

## 🐛 80211ORCA Limitations

- **WPA3/SAE is not supported** — SAE does not produce a crackable 4-way handshake in the same way WPA2 does.
- **WEP is not targeted** — the tool focuses on WPA/WPA2-PSK.
- **Broadcast deauth** — the current deauth implementation sends broadcast frames, which may be ignored by some clients/drivers. A per-client deauth is planned for a future release.
- **Single interface** — only one adapter is used; the capture and injection share the same interface.
- **Linux only** — no Windows/macOS support.

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `NEED ROOT` | Run with `sudo` |
| No packets captured | Adapter not in monitor mode, or wrong channel |
| Handshake never captured | Try active mode, move closer to the AP, or target a busier network |
| `iwconfig: command not found` | Install `wireless-tools` |

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome.

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

## 👤 Author

**n0nexist**

- GitHub: [@n0nexist](https://github.com/n0nexist)

---

> **Remember:** *With great power comes great responsibility.* Only audit networks you own or have explicit permission to test.
