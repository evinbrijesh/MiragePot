# Contributing to MiragePot

Thank you for your interest in contributing to MiragePot! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/evinbrijesh/MiragePot/issues)
2. If not, create a new issue with:
   - A clear, descriptive title
   - Steps to reproduce the bug
   - Expected vs actual behavior
   - Your environment (OS, Python version, Ollama version)
   - Relevant logs or error messages

### Suggesting Features

1. Check existing issues and discussions for similar suggestions
2. Create a new issue with the "enhancement" label
3. Describe the feature and its use case
4. Explain why it would benefit the project

### Submitting Code

#### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/evinbrijesh/MiragePot.git
cd MiragePot

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

#### Development Workflow

1. **Fork the repository** and create a branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes** following our coding standards (see below)

3. **Write tests** for new functionality:
   ```bash
   pytest tests/ -v
   ```

4. **Run linters** before committing:
   ```bash
   make lint
   make format
   ```

5. **Commit your changes** with a clear message:
   ```bash
   git commit -m "feat: add new feature X"
   # or
   git commit -m "fix: resolve issue with Y"
   ```

6. **Push to your fork** and submit a Pull Request

#### Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Adding or updating tests
- `chore:` Maintenance tasks

### Coding Standards

#### Python Style

- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Use [Black](https://github.com/psf/black) for formatting (line length: 88)
- Use type hints for function signatures
- Write docstrings for public functions and classes

#### Code Organization

```
miragepot/
├── __init__.py          # Package initialization
├── __main__.py          # CLI entry point
├── config.py            # Configuration management
├── server.py            # Main SSH server
├── ssh_interface.py     # SSH protocol handling
├── command_handler.py   # Command processing
├── ai_interface.py      # LLM integration
└── defense_module.py    # Threat detection
```

#### Testing Guidelines

- Write tests for all new functionality
- Place tests in `tests/` directory
- Name test files as `test_<module>.py`
- Use pytest fixtures for common setup
- Aim for meaningful coverage, not just high percentages

### Pull Request Guidelines

1. **Title**: Use a clear, descriptive title
2. **Description**: Explain what changes you made and why
3. **Testing**: Describe how you tested the changes
4. **Screenshots**: Include if relevant (especially for dashboard changes)
5. **Breaking Changes**: Clearly note any breaking changes

### Areas to Contribute

We especially welcome contributions in these areas:

- **Command responses**: Expand `data/cache.json` with more realistic outputs
- **LLM prompts**: Improve prompt engineering for better responses
- **Defense rules**: Add threat detection patterns in `defense_module.py`
- **Documentation**: Improve docs, add examples, fix typos
- **Tests**: Increase test coverage
- **Dashboard**: Add visualizations and analytics features

## Questions?

Feel free to:
- Open an issue with the "question" label
- Start a discussion in the Discussions tab
- Reach out to the maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
