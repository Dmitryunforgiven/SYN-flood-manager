# SYN Flood Manager

## Overview
SYN Flood Manager is a graphical tool designed to help system administrators detect and mitigate SYN flood attacks on Linux-based servers. It provides an intuitive UI built with Flet to manage remote servers over SSH, monitor network traffic, configure `iptables` rules, and block malicious IPs or subnets. The tool is particularly useful for identifying and responding to DDoS attempts targeting TCP services.

**Note**: This is a work-in-progress (WIP) project. Features are still being developed and refined, so expect some rough edges.

## Features
- **🔒 SSH-based Server Management**: Securely connect to remote servers to monitor and manage network security.
- **🛡 IPTables Automation**: Add, remove, and view `iptables` rules to block malicious traffic.
- **📡 Traffic Monitoring**: Use `tcpdump` to capture and analyze SYN flood traffic in real-time.
- **🚫 IP/Subnet Blocking**: Block individual IPs or entire subnets identified as threats.
- **🌍 Whois Lookup**: Query IP information to investigate the origin of suspicious traffic.
- **🌙 Dark Mode**: Toggle between light and dark themes for a comfortable user experience.
- **🔐 Encrypted Configuration**: Server credentials are stored securely using Fernet encryption.

## Requirements
- **Python 3.12+**
- **Dependencies**:
  - `flet` - For the graphical user interface.
  - `paramiko` - For SSH connectivity.
  - `cryptography` - For encrypting sensitive data.

## Installation
1. **Clone the Repository**:
   ```sh
   git clone https://github.com/Dmitryunforgiven/syn-flood-manager.git
   cd syn-flood-manager
   ```
2. **Install Dependencies**:
   ```sh
   pip install -r requirements.txt
   ```
3. **Launch the Application**:
   ```sh
   python main.py
   ```

## Usage:
- **Add a Server**:
Enter the server's IP address, username, and password in the UI.
Click "Add Server" to save it securely (credentials are encrypted in config.json).
- **Connect to a Server**:
Select a server from the dropdown menu and click "Connect" to establish an SSH session.
- **Monitor Traffic**:
Click "Start TCPdump" to capture SYN flood traffic (filtered for TCP port 443 by default).
View unique IPs in the UI as they appear in the traffic.
- **Manage IPTables**:
Use "Add IP to drop list" or "Drop IP by subnet" to block malicious IPs or subnets.
Use "Remove IP from drop list" to unblock IPs.
Click "View IPTables rules" to inspect current rules.
- **Investigate IPs**:
Select an IP and click "Whois selected IP" to retrieve ownership details.
Optionally summarize Whois output using the "Summarize WhoIs output" checkbox.

## Configuration:
Server Credentials: Stored in config.json with encryption for security.
Whois Fields: Configurable via "Config WhoIs" button (changes are temporary and reset on restart).

## P.S.
- **🛠 Work in Progress**