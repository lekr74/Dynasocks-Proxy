# Dynasocks-Proxy

A powerful SOCKS proxy in Python that randomizes source IP addresses. Rotate traffic through SSH tunnels or leverage billions of unique IPv6 addresses.

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://raw.githubusercontent.com/blacklanternsecurity/nmappalyzer/master/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.6+-blue)](https://www.python.org)

## Key Features

- **Subnet Proxy Mode**: Utilize Linux AnyIP to send traffic from entire IPv6 subnets
- **Multiple Subnets**: Rotate within multiple subnets for more diversity
- **WAF Bypass**: Rotate source IPs to avoid rate limiting and blocking
- **Clean Traffic**: Maintains full SOCKS functionality for legitimate return traffic

## Quick Start

### Installation

```bash
sudo apt update && sudo apt install iptables python3-pip git nano
sudo pip install git+https://github.com/lekr74/Dynasocks-proxy --break-system-packages
```

### Post-Installation Setup

1. Modify `cli.py` in `/usr/local/lib/python3.X/dist-packages/trevorproxy` to configure:
   - Username
   - Password
2. Modify `subnets_config.json` in the same directory to configure subnets to use
3. Install service file in `/etc/systemd/system/` and edit to configure used subnets

## Usage Examples

### IPv6 Subnet Mode

```bash
# Start proxy with single subnet
sudo /usr/local/bin/trevorproxy subnet -i lo


# Test the connection
curl --proxy socks5://127.0.0.1:1080 -6 api64.ipify.org
```

## Command Line Interface


### Subnet Mode Options
```
-i INTERFACE      Network interface
-s SUBNET         Source subnet(s) (multiple -s to use multiple subnets)
```


## Demo

![Subnet Proxy Demo](https://user-images.githubusercontent.com/20261699/142468206-4e9a46db-b18b-4969-8934-19d1f3837300.gif)

---

Base on TREVORProxy and modified by Lekr74
