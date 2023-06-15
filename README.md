<a id="top"></a>

#

<h1 align="center">
Network Spoofing Scanning
</h1>

<p align="center"> 
  <kbd>
<img src="https://raw.githubusercontent.com/r0xd4n3t/spoofscan/main/img/sspoof.png"></img>
  </kbd>
</p>

<p align="center">
<img src="https://img.shields.io/github/last-commit/r0xd4n3t/spoofscan?style=flat">
<img src="https://img.shields.io/github/stars/r0xd4n3t/spoofscan?color=brightgreen">
<img src="https://img.shields.io/github/forks/r0xd4n3t/spoofscan?color=brightgreen">
</p>

# 📜 Introduction
This script allows you to perform network scanning using IP spoofing. It can scan TCP and UDP ports on a target IP address while using a spoofed IP address for packet headers.
The script uses the Scapy library for crafting and sending network packets.

## 📝 Prerequisites

- Python 3 installed
- Scapy library installed (`pip install scapy`)
- Colorama library installed (`pip install colorama`)

## 🕹️ Usage
> HELP

![](https://raw.githubusercontent.com/r0xd4n3t/spoofscan/main/img/help.png)

1. Clone the repository to your local machine:
```
git clone https://github.com/r0xd4n3t/spoofscan.git
```

2. Change to the project directory:
```
cd spoofscan
```

3. Run the script with the following command:
```
sudo python spoofed_scan.py -s <spoofed_ip> -t <target_ip>
```
Replace `<spoofed_ip>` with the IP address you want to use for IP spoofing, and `<target_ip>` with the IP address of the target you want to scan.

4. The script will perform a TCP and UDP scan on the specified target IP address, displaying the open ports found.

**Note:** Execute the script with appropriate permissions (e.g., as root or with sudo) to send raw packets.

### Example
```
sudo python spoofed_scan.py -s 1.2.3.4 -t 5.6.7.8
```

This example runs the script with the spoofed IP address `1.2.3.4` and the target IP address `5.6.7.8`. It performs a TCP and UDP scan on the target IP, displaying the open ports found.

> SAMPLE

![](https://raw.githubusercontent.com/r0xd4n3t/spoofscan/main/img/sample.png)
## Disclaimer

Please ensure you have proper authorization and comply with legal and ethical guidelines when conducting any network scanning activities.

<p align="center"><a href=#top>Back to Top</a></p>
