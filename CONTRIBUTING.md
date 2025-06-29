# Contributing to Morning Vuln Briefing

Thank you for your interest in contributing to the Morning Vuln Briefing project! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct: Be respectful, inclusive, and constructive in all interactions.

## How to Contribute

### Reporting Issues

1. **Check existing issues** first to avoid duplicates
2. **Use issue templates** when available
3. **Provide clear descriptions** including:
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Environment details

### Submitting Pull Requests

1. **Fork the repository** and create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our coding standards

3. **Write/update tests** to maintain 63% coverage minimum (CI requirement)

4. **Run all checks locally**:
   ```bash
   # Python checks
   ruff check scripts/
   ruff format scripts/
   pytest --cov=scripts --cov-report=term
   
   # JavaScript checks
   npm run lint
   npm run format
   npm run build
   ```

5. **Commit with conventional commits**:
   ```bash
   git commit -m "feat: add new vulnerability filter"
   git commit -m "fix: correct EPSS score calculation"
   git commit -m "docs: update API documentation"
   ```

6. **Push and create a Pull Request**

## Development Setup

### Prerequisites

- Python 3.9+
- Node.js 18+
- Git

### Local Development

1. **Clone the repository**:
   ```bash
   git clone https://github.com/wclaytor/vuln-bot.git
   cd vuln-bot
   ```

2. **Set up Python environment**:
   ```bash
   # Install uv (if not already installed)
   curl -LsSf https://astral.sh/uv/install.sh | sh
   
   # Install dependencies
   uv pip install -r requirements.txt
   ```

3. **Set up Node environment**:
   ```bash
   npm install
   ```

4. **Make Husky scripts executable**:
   ```bash
   chmod +x .husky/pre-commit .husky/commit-msg
   ```

5. **Run the development server**:
   ```bash
   npm run serve
   ```

## Coding Standards

### Python

- Follow PEP 8 with Black formatting (enforced by Ruff)
- Use type hints for all function signatures
- Write docstrings for all classes and functions
- Maintain 63% test coverage minimum (CI requirement)

Example:
```python
def calculate_risk_score(
    cvss_score: float,
    epss_score: float,
    is_kev: bool = False
) -> int:
    """Calculate composite risk score for a vulnerability.
    
    Args:
        cvss_score: CVSS base score (0-10)
        epss_score: EPSS probability (0-1)
        is_kev: Whether vulnerability is in CISA KEV
        
    Returns:
        Risk score from 0-100
    """
    # Implementation
```

### JavaScript/TypeScript

- Follow Google JavaScript Style Guide (enforced by ESLint)
- Use JavaScript/TypeScript for frontend code
- Avoid `any` types - use `unknown` or specific types
- Use nullish coalescing (`??`) instead of logical OR (`||`) for defaults

Example:
```typescript
interface VulnerabilityFilter {
  severity?: SeverityLevel;
  minScore?: number;
  vendor?: string;
}

function applyFilter(
  vulnerabilities: Vulnerability[],
  filter: VulnerabilityFilter
): Vulnerability[] {
  const minScore = filter.minScore ?? 0;
  // Implementation
}
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Test additions or changes
- `chore:` Build process or auxiliary tool changes

## Testing

### Python Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=scripts --cov-report=html

# Run specific test file
pytest tests/test_harvest.py
```

### JavaScript Tests

```bash
# Run ESLint
npm run lint

# Run type checking
npm run typecheck
```

## Architecture Guidelines

### Data Flow

1. **Harvesting** (Python): CVE data → Enrichment → Risk Scoring → Cache
2. **Generation** (11ty): Cache → Templates → Static HTML/JSON
3. **Frontend** (Alpine.js): JSON API → Client-side filtering → UI

### Adding New Features

1. **New Data Source**:
   - Create client in `scripts/harvest/`
   - Add to orchestrator
   - Write tests
   - Update documentation

2. **New Frontend Feature**:
   - Add TypeScript types
   - Implement in Alpine component
   - Add analytics tracking
   - Ensure accessibility

3. **New Risk Factor**:
   - Update risk scorer algorithm
   - Add to vulnerability model
   - Update tests
   - Document in README

## Pull Request Checklist

- [ ] Tests pass locally
- [ ] Code coverage ≥ 63% (CI requirement)
- [ ] Linting passes (Ruff & ESLint)
- [ ] Security scans pass
- [ ] Documentation updated
- [ ] Commit messages follow conventions
- [ ] PR description explains changes

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open an Issue
- **Security**: Email security concerns privately

## Recognition

Contributors will be recognized in:
- GitHub contributors graph
- Project documentation
- Release notes

Thank you for contributing to make vulnerability intelligence more accessible!