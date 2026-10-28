# LeakLock

> 🔐 **Scan any Git repo for secrets that were already pushed.**  
> Find API keys, passwords, tokens, and private keys — even if they're buried in old commits.

**LeakLock** is a zero-dependency Python CLI that scans your Git history for sensitive data. It catches what pre-commit hooks miss because they only see *new* changes — but leaks happen in old commits, in branches, and in tags.

---

## Demo

```
$ python3 leaklock.py scan /tmp/demo-leaklock

🔍 LeakLock — Secret Scanner
========================================
Target:    /tmp/demo-leaklock
Patterns:  46 loaded

📊 Scanning 2 commits...
🚨 2 SECRETS FOUND

🔴 CRITICAL (2):
  • Stripe API Key
    Commit:  bb40639  "Add config files with secrets"
    File:    stripe.py
    Line:    1
    Match:   sk_liv...bc12[REDACTED]

  • AWS Access Key ID
    Commit:  255fd4e  "add config"
    File:    config.py
    Line:    1
    Match:   AKIAIO...MPLE
```

---

## Why LeakLock?

- **Catches historical leaks** — scans every commit, not just your working tree
- **100+ secret patterns** — AWS keys, GitHub tokens, Stripe keys, Slack tokens, private keys, JWTs, passwords, connection strings
- **Zero dependencies** — just Python 3.8+
- **Works on any repo** — clone it, point LeakLock at it, done
- **Exit code friendly** — use in CI to fail the build on leaked secrets

---

## Install

```bash
# Clone and run
git clone https://github.com/hanyxd/leaklock.git
cd leaklock
python3 leaklock.py --help

# Or install globally
pip install -e .
```

---

## Usage

```bash
# Scan a local repo
python3 leaklock.py scan /path/to/your/repo

# Scan a remote repo (clones it first)
python3 leaklock.py scan https://github.com/your/repo.git

# Scan with strict mode (more patterns, more false positives)
python3 leaklock.py scan ./ --strict

# Output as JSON for CI integration
python3 leaklock.py scan ./ --json > leaks.json

# Exclude certain paths
python3 leaklock.py scan ./ --exclude node_modules,dist,*.lock
```

---

## Output

```
🔍 LeakLock — Secret Scanner
═══════════════════════════════
Target:    ./my-repo
Commits:   47 scanned
Patterns:  124 loaded

🚨 3 SECRETS FOUND

  • AWS Access Key ID
    Commit:  a1b2c3d  "Add config"
    File:    config/production.yml
    Line:    12
    Match:   AKIA[REDACTED]

  • GitHub Personal Access Token
    Commit:  e4f5g6h  "Update README"
    File:    .env.example
    Line:    3
    Match:   ghp_[REDACTED]

  • Private Key
    Commit:  i7j8k9l  "Add SSL cert"
    File:    ssl/server.key
    Line:    1
    Match:   -----BEGIN[REDACTED]-----
```

---

## Patterns

LeakLock detects 100+ secret types including:

- **Cloud providers**: AWS, Azure, GCP, DigitalOcean, Vercel, Netlify
- **Payment**: Stripe, PayPal, Square
- **Communication**: Slack, Discord, Twilio, SendGrid
- **Code platforms**: GitHub, GitLab, Bitbucket tokens
- **Databases**: MongoDB, PostgreSQL, Redis connection strings
- **APIs**: OpenAI, Anthropic, HuggingFace, Replicate
- **Keys**: SSH private keys, JWTs, PGP keys, generic API keys
- **Passwords**: Generic password assignments, .env files

---

## CI Integration

```yaml
# .github/workflows/leaklock.yml
name: LeakLock Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # full history
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install leaklock
      - run: leaklock scan . --json --fail-on-secret
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## ⭐ If LeakLock helps you, please star the repo. It helps others discover it too.