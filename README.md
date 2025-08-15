# Security Tool Builder

An autonomous AI agent that builds security-focused tools daily using GitHub Actions and LLM integration. Generates penetration testing utilities, vulnerability scanners, threat hunting scripts, and security automation components without restrictions.

## Overview

Automatically generates a diverse collection of security tools for professionals, researchers, and practitioners. From simple utilities to complex security frameworks, the builder creates tools that address real-world offensive and defensive security challenges.

## Tool Categories

The agent builds tools across these security domains:

- **Reconnaissance**: Network scanning, subdomain enumeration, OSINT collection
- **Vulnerability Assessment**: Scanners, fuzz testing, security auditing
- **Threat Hunting**: Log analysis, IOC detection, behavioral analysis
- **Cryptography**: Encryption utilities, hash crackers, certificate tools
- **Network Security**: Packet analyzers, firewall tools, intrusion detection
- **Mobile Security**: APK analysis, iOS security testing
- **Cloud Security**: AWS/Azure security tools, container scanning
- **Red Team**: Exploit tools, payload generators, persistence mechanisms
- **Compliance**: Audit tools, policy checkers, documentation generators

## Project Structure

```text
security-tool-builder/
├── agent/                  # AI agent core logic
│   ├── agent.py           # Main agent implementation
│   ├── tools.py           # Helper tools (git, LLM calls, etc.)
│   └── policies.py        # Configuration and policies
├── backlog/               # Security tool backlog
│   └── security_tools.yml # Tool definitions and status
├── tools/                 # Generated security tools
│   ├── recon/            # Reconnaissance tools
│   ├── vuln/             # Vulnerability assessment
│   ├── threat-hunt/      # Threat hunting utilities
│   ├── crypto/           # Cryptography tools
│   ├── network/          # Network security tools
│   └── ...               # Other categories
├── tests/                # Generated and manual tests
├── scripts/              # Utility scripts
└── .github/workflows/    # GitHub Actions workflows
```

## How It Works

1. **Daily Schedule**: GitHub Actions runs the security tool builder daily
2. **Tool Selection**: Agent picks next security tool from the backlog
3. **Research Phase**: AI researches security requirements and implementation patterns
4. **Implementation**: AI generates complete, functional security tool
5. **Testing**: Automated tests ensure tool works correctly
6. **Documentation**: Generates usage examples and technical details
7. **PR Creation**: Creates PR with the new security tool

## Current Security Tool Pipeline

### Ready for Development

- **Port Scanner Pro**: Advanced TCP/UDP port scanner with service detection
- **Hash Cracker Suite**: Multi-algorithm hash cracking utility
- **Subdomain Hunter**: Intelligent subdomain enumeration tool
- **Log Analyzer**: Security event log analysis and correlation
- **Certificate Inspector**: SSL/TLS certificate security auditor

### In Development

- **Network Mapper**: Visual network topology and vulnerability mapper
- **Payload Generator**: Custom exploit payload creation framework

### Completed Tools

- *Building begins soon*

## Development

### Running the Builder Locally

```bash
# Install dependencies
pip install -r requirements.txt
pip install -e .

# Run a specific tool (example)
python -m tools.recon.port_scanner --target 192.168.1.0/24

# Run tests
pytest

# Run builder agent manually
python -m agent.agent
```

### Adding Security Tool Ideas

1. Add tool specification to `backlog/security_tools.yml`
2. Define security requirements and test cases
3. Set `ready: true` and `status: todo`
4. Let the daily workflow build it automatically

### Tool Usage Examples

```bash
# Reconnaissance
python -m tools.recon.subdomain_hunter --domain example.com
python -m tools.recon.port_scanner --target 10.0.0.1 --ports 1-1000

# Vulnerability Assessment  
python -m tools.vuln.hash_cracker --hash sha256:abc123... --wordlist rockyou.txt
python -m tools.vuln.cert_inspector --url https://example.com

# Threat Hunting
python -m tools.threat_hunt.log_analyzer --logfile security.log --rules malware
```

## Agent Configuration

The security tool builder is configured through:

- `agent/security_policies.py`: Security-focused coding standards
- `backlog/security_tools.yml`: Tool specifications and priorities  
- `.github/workflows/daily-builder.yml`: Automated building schedule

## Dependencies

- **OpenAI**: LLM integration for security tool generation
- **Security Libraries**: cryptography, scapy, requests, etc.
- **Testing**: pytest, security test frameworks
- **Utilities**: PyYAML, argparse, pathlib

## Workflows

- **PR Checks**: Security code review and testing
- **Daily Builder**: Automated security tool development
- **Security Scan**: Regular security audit of generated tools

---

*This project generates security tools for research, testing, and educational purposes.*
```

## 🛡️ Security Considerations

### Ethical Use Only
All tools are designed for:
- ✅ Authorized penetration testing
- ✅ Security research and education  
- ✅ Defending your own infrastructure
- ✅ Compliance and audit activities

### Disclaimer
- 🚫 **Never use on systems you don't own**
- 🚫 **Always obtain proper authorization**
- 🚫 **Respect laws and regulations**
- 🚫 **No malicious or illegal activities**

## 🤖 Agent Configuration

The security tool builder is configured through:

- `agent/security_policies.py`: Security-focused coding standards
- `backlog/security_tools.yml`: Tool specifications and priorities  
- `.github/workflows/daily-builder.yml`: Automated building schedule

## 📦 Dependencies

- **OpenAI**: LLM integration for security tool generation
- **Security Libraries**: cryptography, scapy, requests, etc.
- **Testing**: pytest, security test frameworks
- **Utilities**: PyYAML, argparse, pathlib

## 🔄 Workflows

- **PR Checks**: Security code review and testing
- **Daily Builder**: Automated security tool development
- **Security Scan**: Regular security audit of generated tools

---

*⚠️ This project is for educational and authorized security testing purposes only. Always comply with applicable laws and obtain proper authorization before testing.*
