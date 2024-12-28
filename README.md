# BrightSniffer  
A Python-based tool that mimics the scanning capabilities of Nmap. BrightSniffer allows you to scan your local network and sniff network traffic with ease.  

## Features  
- **Scanner**: Discover IP addresses of hosts in your local network.  
- **Sniffer**: Capture and analyze network packets passing through your computer.  
- **ICMP Sniffer**: Specifically capture ICMP packets for detailed analysis.  

---

## Prerequisites  
1. **Python**: Ensure Python is installed on your system. You can download it from [python.org](https://www.python.org/).  
2. **Windows Users**: If you are on Windows, disable the Windows Defender Firewall for public networks to allow unrestricted scanning and sniffing.  

---

## Usage  

### 1. **Scanner**  
To scan your local network and discover host IPs, make sure to adjust the subnet value to match your network. Then run:  
```bash  
python3 scanner.py <host_ip>  
