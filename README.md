# Security Tool Builder

[![Continuous Security Tool Builder](https://github.com/lewiswigmore/builder-agent/actions/workflows/daily-agent.yml/badge.svg)](https://github.com/lewiswigmore/builder-agent/actions/workflows/daily-agent.yml)

An experiment in using AI to generate random security scripts and proof-of-concepts. The system creates small tools in separate branches that you can review and potentially develop further if they're useful.

> **Badge Status**: Shows ✅ when the agent successfully generates and pushes new tools for review. Generated tools may need manual refinement, which is expected for experimental AI-generated code.

## What It Does

Runs periodically to build simple security tools in their own branches. Most will probably be basic or incomplete, but occasionally something might be worth keeping and improving. Think of it as automated brainstorming for security tooling ideas.

## How It Works

1. **Periodic Runs**: GitHub Actions triggers the builder every 6 hours
2. **Random Selection**: Picks a tool idea from the backlog
3. **Branch Creation**: Creates a `security-tool/category-###` branch
4. **Basic Implementation**: Generates a working script with some tests
5. **Review When Convenient**: Check branches occasionally to see what was built
6. **Keep What's Useful**: Merge any tools that look promising
7. **Generate More Ideas**: Adds new concepts to try building next time

### Workflow Outcomes

- ✅ **Success**: Agent generated code and pushed a branch for review
- 🔄 **In Progress**: Currently building a tool  
- ❌ **Failure**: Agent couldn't run (config issues, API problems, etc.)

Tools pushed for review may have test failures - this is expected for experimental AI-generated code and still counts as success.

## Branch Structure

```text
main branch
├── security-tool/recon-001     # port scanner attempt
├── security-tool/vuln-002      # some hash cracking script  
├── security-tool/crypto-003    # encryption utility idea
└── security-tool/hunt-004      # log parsing experiment
```

### Review Process

```bash
# See what's been built lately
python scripts/review_security_branches.py

# Check out something interesting
git checkout security-tool/recon-001
python -m pytest tests/ -v

# Keep it if it's useful
git checkout main
git merge security-tool/recon-001
git branch -d security-tool/recon-001
```

## Current Ideas in Queue

The backlog has some basic concepts to try building:

- **RECON-001**: Port scanner with basic OS detection
- **RECON-002**: Subdomain enumeration script
- **VULN-001**: Simple SQL injection tester
- **CRYPTO-001**: Hash cracking utility
- **NETWORK-001**: Basic traffic analyzer
- **THREAT-001**: IOC scanner for log files

These are just starting points - the system will generate new ideas as it goes. Categories like recon, vuln, crypto etc. are loose groupings, not requirements.

### What Gets Built

Most outputs will be simple scripts or proof-of-concepts. Some might be useful as-is, others might spark ideas for proper development. The goal is exploration rather than production-ready tools.

## Running Locally

```bash
# Install dependencies
pip install -r requirements.txt
pip install -e .

# Try running a generated tool
python -m tools.recon.port_scanner --target 192.168.1.1

# Run tests on something
pytest

# Trigger the builder manually
python -m agent.agent
```

### Adding Ideas

You can add concepts to `backlog/security_tools.yml` if you want the system to try building something specific. Just set `status: todo` and it'll get picked up eventually.

### Usage Examples

```bash
# Whatever gets built, basic usage might look like:
python -m tools.recon.subdomain_hunter --domain example.com
python -m tools.vuln.hash_cracker --hash abc123... --wordlist common.txt
python -m tools.threat_hunt.log_scanner --file /var/log/auth.log
```

## Configuration

- `agent/agent.py`: Main builder logic
- `backlog/security_tools.yml`: Ideas queue
- `.github/workflows/daily-agent.yml`: Automation schedule

## Dependencies

Basic Python packages for AI integration and common security libraries. Nothing fancy.

---

*Experimental tool generation for security research and learning.*
