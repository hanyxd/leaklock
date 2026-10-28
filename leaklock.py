#!/usr/bin/env python3
"""
LeakLock — Git repository secret scanner
Scans all commits, branches, and tags for sensitive data patterns.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Dict, Set

# Secret patterns (name, regex, severity)
SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "critical"),
    ("AWS Secret Access Key", r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "critical"),
    
    # GitHub
    ("GitHub Personal Access Token", r"ghp_[A-Za-z0-9]{36}", "critical"),
    ("GitHub OAuth Token", r"gho_[A-Za-z0-9]{36}", "critical"),
    ("GitHub App Token", r"ghu_[A-Za-z0-9]{36}", "critical"),
    ("GitHub Refresh Token", r"ghr_[A-Za-z0-9]{36}", "critical"),
    
    # GitLab
    ("GitLab Personal Access Token", r"glpat-[A-Za-z0-9\-]{20}", "critical"),
    
    # Stripe
    ("Stripe API Key", r"sk_live_[0-9a-zA-Z]{24}", "critical"),
    ("Stripe Restricted API Key", r"rk_live_[0-9a-zA-Z]{24}", "critical"),
    ("Stripe Publishable Key", r"pk_(test|live)_[0-9a-zA-Z]{24}", "low"),
    
    # Slack
    ("Slack Bot Token", r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", "high"),
    ("Slack User Token", r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", "high"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}", "high"),
    
    # Twilio
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", "high"),
    
    # SendGrid
    ("SendGrid API Key", r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}", "critical"),
    
    # Google
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "high"),
    ("Google OAuth Client ID", r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com", "medium"),
    ("Google Cloud Service Account Key", r'"type"\s*:\s*"service_account"', "high"),
    
    # Azure
    ("Azure Storage Account Key", r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "critical"),
    
    # DigitalOcean
    ("DigitalOcean Personal Access Token", r"dop_v1_[a-f0-9]{64}", "critical"),
    
    # Vercel
    ("Vercel Token", r"vercel_token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{24,}['\"]?", "high"),
    
    # Netlify
    ("Netlify API Key", r"(?i)netlify[_\s]?api[_\s]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{40,}['\"]?", "high"),
    
    # MongoDB
    ("MongoDB Connection String", r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+/", "critical"),
    
    # PostgreSQL
    ("PostgreSQL Connection String", r"postgres(ql)?://[^:]+:[^@]+@[^/]+/", "critical"),
    
    # Redis
    ("Redis Connection String", r"redis://[^:]+:[^@]+@[^/]+/", "high"),
    
    # Private Keys
    ("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "critical"),
    ("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "critical"),
    ("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "critical"),
    ("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "critical"),
    
    # JWT
    ("JWT Token", r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", "medium"),
    
    # OpenAI
    ("OpenAI API Key", r"sk-[a-zA-Z0-9]{48}", "critical"),
    ("OpenAI Project Key", r"sk-proj-[a-zA-Z0-9]{48}", "critical"),
    
    # Anthropic
    ("Anthropic API Key", r"sk-ant-[a-zA-Z0-9_-]{32,}", "critical"),
    
    # HuggingFace
    ("HuggingFace Token", r"hf_[a-zA-Z0-9]{34}", "critical"),
    
    # Discord
    ("Discord Bot Token", r"MT[A-Za-z0-9]{23}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_-]{27}", "high"),
    
    # Telegram
    ("Telegram Bot Token", r"[0-9]{9,10}:[A-Za-z0-9_-]{35}", "high"),
    
    # Mailchimp
    ("Mailchimp API Key", r"[a-f0-9]{32}-us[0-9]{1,2}", "medium"),
    
    # PayPal
    ("PayPal Client ID", r"(?i)paypal[_\s]?client[_\s]?id\s*[=:]\s*['\"]?[A-Za-z0-9_-]{30,}['\"]?", "high"),
    
    # Square
    ("Square Access Token", r"sq0atp-[A-Za-z0-9_-]{22}", "high"),
    
    # Shopify
    ("Shopify Access Token", r"shpat_[a-f0-9]{32}", "critical"),
    
    # Heroku
    ("Heroku API Key", r"(?i)heroku[_\s]?api[_\s]?key\s*[=:]\s*['\"]?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]?", "high"),
    
    # Generic
    ("Generic API Key", r"(?i)api[_\s]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{20,}['\"]?", "medium"),
    ("Generic Secret", r"(?i)secret\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{16,}['\"]?", "medium"),
    ("Generic Password", r"(?i)password\s*[=:]\s*['\"]?[a-zA-Z0-9_-@#$%^&*!]{8,}['\"]?", "medium"),
    
    # Connection strings
    ("MySQL Connection String", r"mysql://[^:]+:[^@]+@[^/]+/", "critical"),
    
    # .env files with secrets
    ("Environment File with Secrets", r"\.env(\.local|\.production|\.staging)?$", "low"),
]

# Additional patterns
from extra_patterns import EXTRA_PATTERNS
ALL_PATTERNS = SECRET_PATTERNS + EXTRA_PATTERNS

# Strict mode patterns (more aggressive, higher false positive rate)
STRICT_PATTERNS = [
    ("Email Address", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "low"),
    ("IP Address", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "low"),
    ("Phone Number", r"\+?[\d\s\-()]{10,}", "low"),
    ("Base64 String", r"(?i)['\"][A-Za-z0-9+/]{40,}={0,2}['\"]", "low"),
]

@dataclass
class Finding:
    pattern_name: str
    commit_hash: str
    commit_message: str
    file_path: str
    line_number: int
    line_content: str
    match: str
    severity: str

def run_command(cmd: List[str], cwd: Optional[str] = None) -> tuple:
    """Run a shell command and return stdout, stderr, exit_code."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1

def get_all_commits(repo_path: str) -> List[str]:
    """Get all commit hashes in the repository."""
    stdout, stderr, code = run_command(
        ["git", "rev-list", "--all"],
        cwd=repo_path
    )
    if code != 0:
        print(f"Error getting commits: {stderr}", file=sys.stderr)
        return []
    return [c.strip() for c in stdout.strip().split("\n") if c.strip()]

def get_commit_diff(repo_path: str, commit_hash: str) -> str:
    """Get the diff for a specific commit."""
    stdout, stderr, code = run_command(
        ["git", "show", "--patch", commit_hash],
        cwd=repo_path
    )
    if code != 0:
        return ""
    return stdout

def get_commit_info(repo_path: str, commit_hash: str) -> Dict:
    """Get commit metadata."""
    stdout, stderr, code = run_command(
        ["git", "show", "-s", "--format=%s", commit_hash],
        cwd=repo_path
    )
    message = stdout.strip() if code == 0 else "Unknown"
    
    stdout, stderr, code = run_command(
        ["git", "show", "-s", "--format=%h", commit_hash],
        cwd=repo_path
    )
    short_hash = stdout.strip() if code == 0 else commit_hash[:7]
    
    return {"hash": short_hash, "message": message}

def scan_content(content: str, patterns: List[tuple]) -> List[tuple]:
    """Scan content for secret patterns."""
    findings = []
    for pattern_name, regex, severity in patterns:
        try:
            matches = re.finditer(regex, content, re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count("\n") + 1
                line_start = content.rfind("\n", 0, match.start()) + 1
                line_end = content.find("\n", match.end())
                if line_end == -1:
                    line_end = len(content)
                line = content[line_start:line_end].strip()
                findings.append((pattern_name, match.group(), line_num, line, severity))
        except re.error:
            continue
    return findings

def scan_repo(repo_path: str, strict: bool = False, exclude: Optional[List[str]] = None) -> List[Finding]:
    """Scan a Git repository for secrets."""
    findings = []
    # Use combined patterns for full coverage
    from extra_patterns import EXTRA_PATTERNS
    patterns = list(SECRET_PATTERNS) + list(EXTRA_PATTERNS)
    
    if strict:
        patterns.extend(STRICT_PATTERNS)
    
    exclude_patterns = list(exclude) if exclude else []
    # Always exclude scanner's own file and common false-positive files
    exclude_patterns.extend(["leaklock.py", "extra_patterns.py", ".gitignore"])
    
    commits = get_all_commits(repo_path)
    print(f"📊 Scanning {len(commits)} commits...")
    
    seen = set()  # Deduplicate findings
    
    for i, commit_hash in enumerate(commits):
        if (i + 1) % 10 == 0:
            print(f"  Progress: {i + 1}/{len(commits)} commits", end="\r")
        
        diff = get_commit_diff(repo_path, commit_hash)
        if not diff:
            continue
        
        commit_info = get_commit_info(repo_path, commit_hash)
        
        # Parse diff
        current_file = None
        for line in diff.split("\n"):
            if line.startswith("diff --git"):
                # Extract file path
                parts = line.split(" ")
                if len(parts) >= 3:
                    a_path = parts[2][2:] if parts[2].startswith("a/") else parts[2]
                    b_path = parts[3][2:] if len(parts) > 3 and parts[3].startswith("b/") else parts[2][2:]
                    current_file = b_path
                    
                    # Check exclusions
                    if any(re.match(pat, current_file) for pat in exclude_patterns):
                        current_file = None
                        continue
            elif line.startswith("--- ") or line.startswith("+++ "):
                continue
            elif line.startswith("+") and current_file:
                content = line[1:]  # Remove the + prefix
                matches = scan_content(content, patterns)
                
                for pattern_name, match, line_num, line_content, severity in matches:
                    key = (pattern_name, commit_info["hash"], current_file, match)
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding(
                            pattern_name=pattern_name,
                            commit_hash=commit_info["hash"],
                            commit_message=commit_info["message"],
                            file_path=current_file,
                            line_number=line_num,
                            line_content=line_content[:100] + "..." if len(line_content) > 100 else line_content,
                            match=match[:20] + "[REDACTED]" if len(match) > 20 else match,
                            severity=severity
                        ))
    
    return findings

def clone_repo(repo_url: str, temp_dir: str) -> Optional[str]:
    """Clone a remote repository."""
    print(f"📥 Cloning {repo_url}...")
    stdout, stderr, code = run_command(
        ["git", "clone", "--depth", "1", repo_url, temp_dir]
    )
    if code != 0:
        print(f"Error cloning: {stderr}", file=sys.stderr)
        return None
    return temp_dir

def main():
    parser = argparse.ArgumentParser(
        description="LeakLock — Scan Git repositories for leaked secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan /path/to/repo
  %(prog)s scan https://github.com/user/repo.git
  %(prog)s scan ./myrepo --strict
  %(prog)s scan ./myrepo --json --fail-on-secret
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a repository for secrets")
    scan_parser.add_argument("target", help="Path to local repo or URL of remote repo")
    scan_parser.add_argument("--strict", action="store_true", help="Enable strict mode (more patterns)")
    scan_parser.add_argument("--json", action="store_true", help="Output as JSON")
    scan_parser.add_argument("--exclude", type=str, help="Comma-separated glob patterns to exclude")
    scan_parser.add_argument("--fail-on-secret", action="store_true", help="Exit with code 1 if secrets found")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    if args.command == "scan":
        target = args.target
        temp_dir = None
        
        # Check if target is a URL
        if target.startswith("http://") or target.startswith("https://"):
            import tempfile
            temp_dir = tempfile.mkdtemp(prefix="leaklock_")
            repo_path = clone_repo(target, temp_dir)
            if not repo_path:
                sys.exit(1)
        else:
            repo_path = target
        
        if not os.path.isdir(repo_path):
            print(f"Error: {repo_path} is not a directory", file=sys.stderr)
            sys.exit(1)
        
        # Check if it's a git repo
        git_dir = os.path.join(repo_path, ".git")
        if not os.path.exists(git_dir):
            print(f"Error: {repo_path} is not a Git repository", file=sys.stderr)
            sys.exit(1)
        
        exclude_patterns = []
        if args.exclude:
            exclude_patterns = [p.strip() for p in args.exclude.split(",")]
        
        print("🔍 LeakLock — Secret Scanner")
        print("=" * 40)
        print(f"Target:    {target}")
        from extra_patterns import EXTRA_PATTERNS as _ep
        total = len(SECRET_PATTERNS) + len(_ep)
        if args.strict:
            total += len(STRICT_PATTERNS)
        print(f"Patterns:  {total} loaded")
        if args.strict:
            print(f"Mode:      Strict (+{len(STRICT_PATTERNS)} patterns)")
        print()
        
        findings = scan_repo(repo_path, strict=args.strict, exclude=exclude_patterns)
        
        # Cleanup temp dir
        if temp_dir:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        
        if args.json:
            output = {
                "target": target,
                "findings_count": len(findings),
                "findings": [asdict(f) for f in findings]
            }
            print(json.dumps(output, indent=2))
        else:
            if findings:
                print(f"🚨 {len(findings)} SECRETS FOUND\n")
                
                # Group by severity
                critical = [f for f in findings if f.severity == "critical"]
                high = [f for f in findings if f.severity == "high"]
                medium = [f for f in findings if f.severity == "medium"]
                low = [f for f in findings if f.severity == "low"]
                
                for severity_name, color in [("critical", "🔴"), ("high", "🟠"), ("medium", "🟡"), ("low", "🔵")]:
                    group = [f for f in findings if f.severity == severity_name]
                    if group:
                        print(f"{color} {severity_name.upper()} ({len(group)}):")
                        for f in group[:10]:  # Show first 10 per severity
                            print(f"  • {f.pattern_name}")
                            print(f"    Commit:  {f.commit_hash}  \"{f.commit_message[:50]}\"")
                            print(f"    File:    {f.file_path}")
                            print(f"    Line:    {f.line_number}")
                            print(f"    Match:   {f.match}")
                            print()
                        if len(group) > 10:
                            print(f"  ... and {len(group) - 10} more\n")
                
                if len(findings) > 40:
                    print(f"💡 Tip: Use --json for full output")
            else:
                print("✅ No secrets detected!")
        
        if args.fail_on_secret and findings:
            sys.exit(1)

if __name__ == "__main__":
    main()
