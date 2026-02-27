# Python for Cybersecurity 🐍🔒

Welcome! This repository is a beginner-friendly place to **learn Python programming** alongside some **basic cybersecurity concepts**.

No prior experience is needed — we start from the very basics of Python and gradually introduce ideas from the world of cybersecurity. A little familiarity with Python syntax is helpful, but absolutely not required.

## Project Structure

### 📁 Simple Port Scanning (`simple_port_scanning/`)

Basic TCP port scanning scripts for both IPv4 and IPv6 networks. Learn how to:
- Use Python's socket library for network connections
- Test if ports are open or closed on target systems
- Understand the difference between IPv4 and IPv6 networking

#### Scripts:

**`ipv4_tcp_portscanneer.py`** - IPv4 TCP Port Scanner
- Scans TCP ports on IPv4 addresses
- Uses socket library for connection testing
- Default target: 192.168.1.4:443

**`ipv6_tcp_portscanner.py`** - IPv6 TCP Port Scanner
- Scans TCP ports on IPv6 addresses
- Uses AF_INET6 socket family for IPv6 support
- Default target: ::1:443 (localhost)

#### Usage:
```bash
cd simple_port_scanning
python ipv4_tcp_portscanneer.py
# or
python ipv6_tcp_portscanner.py
```

## Requirements

- Python 2.7 (current scripts use legacy Python 2 syntax)
- Standard Python socket library (included by default)

## Learning Path

1. **Start with Port Scanning** - Understand how network services work
2. **Modify the Scripts** - Change target hosts and ports to learn by doing
3. **Explore Further** - More tools and techniques coming soon!

## ⚠️ Important Notes

- **Educational Purpose Only** - These scripts are for learning cybersecurity concepts
- **Get Permission** - Always ensure you have authorization before scanning any network or system
- **Legal Considerations** - Unauthorized port scanning may be illegal in your jurisdiction
- **Ethical Hacking** - Use these tools responsibly and ethically

## Future Enhancements

- 🔄 Python 3 migration
- 🎯 Command-line argument support for flexible host/port configuration
- 📊 Port range scanning capabilities
- ⚡ Multi-threaded scanning for improved performance
- 📝 Output logging and reporting features
- 🛠️ Additional scanning techniques (UDP, SYN scanning, OS detection)

## Contributing

This is a learning repository! Contributions are welcome. Whether you're fixing bugs, improving documentation, or adding new security tools, feel free to contribute following best practices.

## Disclaimer

**These tools are for educational and authorized testing purposes only.** Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting any security testing or penetration testing activities.

## License

Educational use only.
