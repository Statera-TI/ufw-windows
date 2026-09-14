# Arch Wiki UFW Compatibility Guide (Windows)

This document analyzes the [Arch Linux Uncomplicated Firewall (UFW) Wiki](https://wiki.archlinux.org/title/Uncomplicated_Firewall) and details how operations are reproduced on Windows using this Go implementation, including technical justifications for Windows-specific architectural differences.

---

## 1. Supported Operations (Vertical Slice)

The initial vertical slice implements the core, most common UFW operations: **`allow`**, **`deny`**, and **`status`**.

| Arch Wiki Recipe | Windows Command | Windows Defender Firewall Mapping | Status / Notes |
| :--- | :--- | :--- | :--- |
| `# ufw status` | `ufw status` | Reads active profile state from Windows Registry; displays user-managed rules. | **Fully Reproducible** |
| `# ufw status numbered` | `ufw status numbered` | Formats rules with sequential `[ 1]`, `[ 2]` indices and direction (`ALLOW IN`). | **Fully Reproducible** |
| `# ufw status verbose` | `ufw status verbose` | Displays profile status, logging state, and default incoming/outgoing policies. | **Fully Reproducible** |
| `# ufw allow 51312` | `ufw allow 51312` | Generates 2 inbound allow rules in Windows Firewall: one for `TCP 51312` and one for `UDP 51312`. | **Fully Reproducible** |
| `# ufw allow 51312/udp` | `ufw allow 51312/udp` | Creates an inbound allow rule: `protocol=UDP localport=51312`. | **Fully Reproducible** |
| `# ufw allow 51312:51314` | `ufw allow 51312:51314` | Generates TCP and UDP inbound rules for port range `51312-51314`. | **Fully Reproducible** |
| `# ufw allow 51312:51314/tcp` | `ufw allow 51312:51314/tcp` | Creates an inbound allow rule: `protocol=TCP localport=51312-51314`. | **Fully Reproducible** |
| `# ufw allow from 192.168.0.0/24` | `ufw allow from 192.168.0.0/24` | Creates an inbound allow rule: `remoteip=192.168.0.0/24 protocol=ANY`. | **Fully Reproducible** |
| Complex: `from ... to any port ... proto ...` | `ufw allow from 192.168.0.0/24 to any port 22 proto tcp` | Creates inbound rule: `remoteip=192.168.0.0/24 localport=22 protocol=TCP`. | **Fully Reproducible** |
| `# ufw allow ssh` | `ufw allow ssh` | Resolves service alias to port `22/tcp`. | **Fully Reproducible** |
| `# ufw allow Deluge` | `ufw allow Deluge` | Resolves Deluge service ports `51312:51314`. | **Fully Reproducible** |
| `# ufw deny 8080/tcp` | `ufw deny 8080/tcp` | Creates an inbound block rule: `action=block protocol=TCP localport=8080`. | **Fully Reproducible** |
| Blacklist IP: `before.rules` DROP | `ufw deny from 199.115.117.99` | Creates an inbound block rule: `action=block remoteip=199.115.117.99/32`. Windows Firewall gives block rules higher priority than allow rules. | **Fully Reproducible** |

---

## 2. In-Depth Arch Wiki Section Analysis & Windows Implementation

### 2.1 Basic Configuration & Default Ruleset
* **Arch Wiki**:
  ```bash
  # ufw default deny
  # ufw allow from 192.168.0.0/24
  # ufw allow Deluge
  # ufw limit ssh
  ```
* **Windows Implementation**:
  - `ufw allow from 192.168.0.0/24`, `ufw allow Deluge`, `ufw allow 51312` work identically.
  - Windows Defender Firewall contains hundreds of built-in system rules (mDNS, Core Networking, svchost, etc.). UFW for Windows maintains the user rule set in `%ProgramData%\ufw\user_rules.json` (mirroring Linux UFW's `/etc/ufw/user.rules`), isolating your customized firewall configuration so `ufw status` remains clean and uncluttered.

---

### 2.2 Rate Limiting (`ufw limit`)
* **Arch Wiki**:
  > *"ufw has the ability to deny connections from an IP address that has attempted to initiate 6 or more connections in the last 30 seconds. Users should consider using this option for services such as SSH."*
* **Architectural Difference on Windows**:
  - On Linux, this capability is provided by Netfilter's `iptables -m recent` kernel module, which tracks stateful IP connection timestamps dynamically in kernel memory.
  - **Windows Defender Firewall does not possess a native packet-level rate-limiting engine.** Standard Windows filtering (`MpsSvc` / `netsh advfirewall`) operates on stateless packet headers and stateful TCP flow tracking (ESTABLISHED), but does not expose an in-kernel sliding-window counter module without custom NDIS/WFP kernel drivers.
  - **Windows Alternative**: On Windows, connection rate-limiting and brute-force mitigation is conventionally handled by log-auditing services such as:
    1. [IPBan](https://github.com/DigitalRuby/IPBan) (inspects Windows Security Event Logs and dynamically injects Windows Firewall block rules).
    2. Windows Event Viewer scheduled tasks with PowerShell triggers.

---

### 2.3 Forward Policy
* **Arch Wiki**:
  > *"Users needing to run a VPN such as OpenVPN or WireGuard can adjust the DEFAULT_FORWARD_POLICY variable in /etc/default/ufw from a value of 'DROP' to 'ACCEPT' to forward all packets..."*
* **Architectural Difference on Windows**:
  - Linux uses Netfilter's `FORWARD` chain to route packets between interfaces.
  - Windows workstations operate as terminal IP hosts by default; IP packet forwarding is disabled at the TCP/IP stack level (`IPEnableRouter = 0`).
  - To enable packet forwarding on Windows, users configure the Routing and Remote Access Service (RRAS) or set `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\IPEnableRouter = 1` and run `netsh interface ipv4 set interface <idx> forwarding=enabled`.

---

### 2.4 Application Profiles (`/etc/ufw/applications.d`)
* **Arch Wiki**:
  > *"Inspect options by looking in the /etc/ufw/applications.d directory... [Deluge-my] ports=20202:20205/tcp"*
* **Windows Implementation**:
  - Common applications (`ssh`, `http`, `https`, `deluge`, `rdp`, `dns`, `ftp`) are natively built into the command parser.
  - Standard INI profile support can be placed under `%ProgramData%\ufw\applications.d\`.

---

### 2.5 Blacklisting IP Addresses
* **Arch Wiki**:
  > *"Add IP addresses to a blacklist by editing /etc/ufw/before.rules and inserting an iptables DROP line..."*
* **Windows Implementation**:
  - On Windows Defender Firewall, **Block rules automatically take precedence over Allow rules**.
  - Running `ufw deny from 199.115.117.99` directly inserts a top-priority Block rule into the Windows Firewall, achieving the exact blacklisting behavior without requiring manual file editing.

---

### 2.6 Remote Ping (ICMP Echo)
* **Arch Wiki**:
  > *"Disable remote ping: Change ACCEPT to DROP in /etc/ufw/before.rules: -A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT"*
* **Windows Implementation**:
  - In Windows Firewall, ICMP echo requests are managed via built-in rules named `File and Printer Sharing (Echo Request - ICMPv4-In)`. Blocking or allowing ICMP echo requests toggles these rules.

---

### 2.7 UFW and Docker
* **Arch Wiki**:
  > *"Docker in standard mode writes its own iptables rules and ignores ufw ones, which could lead to security issues."*
* **Architectural Difference on Windows**:
  - On Windows, Docker Desktop does not interact directly with Windows Defender Firewall. Instead, Docker Desktop runs inside a lightweight Hyper-V utility VM or WSL2 (Windows Subsystem for Linux), using its own internal virtual network adapter (`vEthernet (WSL)`).
  - Port publishing (`docker run -p 8080:80`) is handled through WSL2 port forwarding and the `docker-proxy` process.

---

### 2.8 GUI Frontends
* **Arch Wiki**: Mentions `Gufw` (GTK frontend for Linux).
* **Windows Implementation**:
  - Windows includes a built-in enterprise-grade GUI: **Windows Defender Firewall with Advanced Security** (`wf.msc`).
  - All rules created by this UFW utility are prefixed with `UFW: <ID> - ...` and tagged with `description=Managed by UFW for Windows`, making them immediately visible, searchable, and manageable in `wf.msc`.

