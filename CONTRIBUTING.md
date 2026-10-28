# Contributing to LeakLock

Thank you for your interest in contributing! Here's how you can help.

## Development Setup

```bash
git clone https://github.com/hanyxd/leaklock.git
cd leaklock
pip install -e ".[dev]"
```

## Adding New Secret Patterns

1. Add your pattern to the `SECRET_PATTERNS` list in `leaklock.py`
2. Format: `("Pattern Name", r"regex_pattern", "severity")`
3. Severity: `critical`, `high`, `medium`, or `low`
4. Test: `python3 leaklock.py scan ./` on a test repo
5. Update README patterns section if you added a new service

## Running Tests

```bash
python3 -m pytest tests/ -v
```

## Submitting Changes

1. Fork the repo
2. Create a branch: `git checkout -b feat/my-pattern`
3. Commit: `git commit -m "feat: add MyCloud API key pattern"`
4. Push: `git push origin feat/my-pattern`
5. Open a Pull Request

## Reporting a Leaked Pattern

If you find a secret that LeakLock missed, open an issue with:
- The secret type
- A sample redacted
- The regex pattern you'd suggest

Please don't post actual secrets in issues!
