# Builder Agent 🤖

An AI-powered development agent that automatically implements features from a backlog using GitHub Actions and LLM integration.

## 🌟 Features

- **Automated Feature Development**: AI agent reads feature backlog and implements code
- **Test-Driven Development**: Generates tests first, then implements features
- **CI/CD Integration**: Automated testing and PR creation/merging
- **Daily Automation**: Scheduled workflow picks up and completes ready features

## 🏗️ Project Structure

```text
builder-agent/
├── agent/                  # AI agent core logic
│   ├── agent.py           # Main agent implementation
│   ├── tools.py           # Helper tools (git, LLM calls, etc.)
│   └── policies.py        # Configuration and policies
├── backlog/               # Feature backlog
│   └── features.yml       # Feature definitions and status
├── src/your_package/      # Example package being developed
│   ├── cli.py            # CLI implementation
│   ├── __main__.py       # Module entrypoint
│   └── __init__.py       # Package initialization
├── tests/                 # Generated and manual tests
├── scripts/              # Utility scripts
└── .github/workflows/    # GitHub Actions workflows
```

## 🚀 How It Works

1. **Daily Schedule**: GitHub Actions runs daily agent workflow
2. **Feature Selection**: Agent picks next `ready: true, status: todo` feature
3. **Test Generation**: AI writes pytest tests based on acceptance criteria
4. **Implementation**: AI implements feature to pass the tests
5. **PR Creation**: Automatically creates and merges PR if tests pass
6. **Retry Logic**: If tests fail, agent retries with error context

## 📋 Current Status

### Completed Features ✅

- `FEAT-001`: Add CLI flag `--greet NAME`

### Ready for Development 📋

- `FEAT-002`: Add version flag `--version`
- `FEAT-003`: Add configuration file support

## 🛠️ Development

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt
pip install -e .

# Run the CLI
python -m your_package --greet "World"

# Run tests
pytest

# Run agent manually
python -m agent.agent
```

### Adding Features

1. Add feature to `backlog/features.yml`
2. Set `ready: true` and `status: todo`
3. Define acceptance tests and allowed files
4. Let the daily workflow pick it up, or run manually

### Package Usage

```bash
# Default greeting
python -m your_package
# Hello, world!

# Custom greeting  
python -m your_package --greet Alice
# Hello, Alice!
```

## 🤖 Agent Configuration

The agent is configured through:

- `agent/policies.py`: Retry limits, line count limits
- `backlog/features.yml`: Feature definitions
- `.github/workflows/daily-agent.yml`: Scheduling

## 📦 Dependencies

- **OpenAI**: LLM integration for code generation
- **PyYAML**: Configuration file parsing
- **pytest**: Test framework
- **requests**: HTTP client for API calls

## 🔄 Workflows

- **PR Checks**: Run tests on every push/PR
- **Daily Agent**: Automated feature development (scheduled)

---

*This project demonstrates AI-powered software development automation using GitHub Actions and LLM integration.*
