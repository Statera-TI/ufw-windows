# ufw-windows: Uncomplicated Firewall for Windows

An uncomplicated, command-line firewall manager for Windows written in Go. It brings the intuitive interface of Ubuntu and Arch Linux's `ufw` to Windows, backed natively by **Windows Defender Firewall** (`netsh advfirewall` / Win32 APIs).

---

## Features

- **Intuitive UFW Syntax**: Use the same commands you know from Linux (`ufw allow`, `ufw deny`, `ufw status`).
- **Native Windows Defender Firewall Integration**: Rules are applied directly into Windows Defender Firewall and immediately appear in the Windows Firewall GUI (`wf.msc`).
- **Clean Rule Isolation**: Mirrors `/etc/ufw/user.rules` in `%ProgramData%\ufw\user_rules.json`, separating your user-defined firewall rules from the 500+ default Windows system rules.
- **Subnet & CIDR Support**: Native CIDR parsing (`192.168.0.0/24`) and single-IP blacklisting (`199.115.117.99`).
- **Port Ranges & Protocols**: Full support for single ports (`51312`), ranges (`51312:51314`), and protocols (`/tcp`, `/udp`, or both).
- **Service Aliases**: Built-in support for common services (`ssh`, `http`, `https`, `deluge`, `rdp`, `dns`, `ftp`).
- **Administrator Elevation Detection**: Checks Windows privileges and provides clear feedback.

---

## Installation & Build

Requires Go 1.22+:

```bash
git clone https://github.com/user/ufw-windows.git
cd ufw-windows
go build -o ufw.exe ./cmd/ufw
```

> **Note**: Windows Defender Firewall commands require Administrator privileges. Run PowerShell or Command Prompt as **Administrator**.

---

## Quick Start & Examples

### Check Status
```powershell
# Standard status
.\ufw.exe status

# Numbered rules (with direction)
.\ufw.exe status numbered

# Verbose status (profiles, logging, default policies)
.\ufw.exe status verbose
```

### Allow Traffic
```powershell
# Allow port 51312 on both TCP and UDP
.\ufw.exe allow 51312

# Allow port on specific protocol
.\ufw.exe allow 51312/udp

# Allow port range
.\ufw.exe allow 51312:51314/tcp

# Allow service alias
.\ufw.exe allow ssh
.\ufw.exe allow Deluge

# Allow entire LAN subnet
.\ufw.exe allow from 192.168.0.0/24

# Allow subnet to specific port and protocol
.\ufw.exe allow from 192.168.0.0/24 to any port 22 proto tcp
```

### Block (Deny) Traffic
```powershell
# Block a port
.\ufw.exe deny 8080/tcp

# Blacklist an IP address
.\ufw.exe deny from 199.115.117.99
```

---

## Arch Wiki Compatibility

For a full breakdown of every recipe from the [Arch Linux UFW Wiki](https://wiki.archlinux.org/title/Uncomplicated_Firewall) and technical comparisons with Windows Defender Firewall, see:
- [ARCH_WIKI_COMPATIBILITY.md](ARCH_WIKI_COMPATIBILITY.md)

