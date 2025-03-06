# SYN Flood Manager

## Overview
SYN Flood Manager is a tool designed to help mitigate SYN flood attacks by managing iptables rules, analyzing traffic, and automating blocking malicious IPs via UI.

## Features
- 🔒 **SSH-based remote server management**
- 🛡 **Automated iptables rule configuration**
- 📡 **SYN flood traffic monitoring using tcpdump**
- 🚫 **IP and subnet blocking functionality**
- 🌍 **Whois lookup for identifying malicious IPs**
- 🌙 **Dark mode UI**

## Installation
### Requirements
- **Python 3.12+**
- **Flet**
- **Paramiko**
- **cryptography**

  ```sh
  pip install -r requirements.txt
  ```

## Usage
1. **Clone the repository:**
   ```sh
   git clone https://github.com/Dmitryunforgiven/syn-flood-manager.git
   cd syn-flood-manager
   ```
2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
3. **Run the application:**
   ```sh
   python SFM.py
   ```
4. **Connect to a remote server via SSH.**
5. **Start monitoring traffic and manage IPtables rules.**

---
🛠 **This is a WIP project so don't expect much**