# Additional secret patterns for LeakLock (100+ total)
# These are imported by leaklock.py

EXTRA_PATTERNS = [
    # AWS (additional patterns)
    ("AWS Account ID", r"(?i)aws[_\-]?account[_\-]?id\s*[=:]\s*['\"]?[0-9]{12}['\"]?", "medium"),
    ("AWS Session Token", r"(?i)aws[_\-]?session[_\-]?token\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40,}['\"]?", "high"),
    ("AWS Bearer Token", r"(?i)aws[_\-]?bearer\s*[=:]\s*['\"]?[A-Za-z0-9._\-]{50,}['\"]?", "high"),
    ("AWS MWS Key", r"amzn.mws.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "high"),
    
    # GitHub (additional)
    ("GitHub OAuth Client Secret", r"(?i)github[_\-]?client[_\-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9]{40,}['\"]?", "high"),
    ("GitHub SSH Deploy Key", r"ssh-rsa AAAAB3NzaC1yc2E[a-zA-Z0-9+/=]+", "high"),
    
    # GitLab (additional)
    ("GitLab CI/CD Token", r"glc_[a-zA-Z0-9_-]{20}", "high"),
    ("GitLab Runner Token", r"glrunner_[a-zA-Z0-9_-]{20}", "high"),
    
    # Azure (additional)
    ("Azure Client Secret", r"(?i)azure[_]?client[_\-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?", "high"),
    ("Azure Subscription Key", r"(?i)azure[_]?subscription[_\-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9]{32}['\"]?", "medium"),
    
    # Google Cloud (additional)
    ("Google Cloud Access Token", r"ya29\.[a-zA-Z0-9._-]+", "high"),
    ("Google OAuth Refresh Token", r"(?i)refresh[_\-]?token\s*[=:]\s*['\"](1//[a-zA-Z0-9._-]+)['\"]", "high"),
    ("Google Service Account File", r'"private_key"\s*:\s*"-----BEGIN [A-Z ]+PRIVATE KEY-----', "high"),
    
    # CI/CD
    ("CircleCI Token", r"[0-9a-f]{64}", "critical"),
    ("GitHub Actions Token", r"ghs_[A-Za-z0-9]{36}", "critical"),
    ("GitHub Fine-Grained Token", r"github_pat_[A-Za-z0-9]{22}_[a-zA-Z0-9]{36}", "critical"),
    ("Travis CI Token", r"(?i)travis[_\-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?", "medium"),
    ("Buildkite Agent Token", r"bk_[a-z0-9]{40}", "high"),
    ("Netlify CLI Token", r"nfp_[A-Za-z0-9]{32}", "high"),
    ("Vercel Automation Token", r"vca_[A-Za-z0-9]{32}", "high"),
    
    # Package Managers
    ("npm Access Token", r"npm_[a-zA-Z0-9]{40}", "high"),
    ("PyPI API Token", r"pypi-[a-zA-Z0-9]{32,}", "high"),
    ("RubyGems API Key", r"rubygems_[a-zA-Z0-9]{20}", "medium"),
    
    # Cloud Provider Keys
    ("DigitalOcean DB Password", r"DO_[a-zA-Z0-9]{20}", "high"),
    ("Linode API Key", r"linode_api_key\s*[=:]\s*['\"]?[a-f0-9]{64}['\"]?", "high"),
    ("Vultr API Key", r"VULTR[A-Z0-9]{20}", "medium"),
    ("Cloudflare API Token", r"[a-zA-Z0-9_-]{40}", "medium"),
    ("Cloudflare Global API Key", r"(?i)cloudflare[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[a-f0-9]{64}['\"]?", "critical"),
    
    # Monitoring & Observability
    ("Datadog API Key", r"(?i)datadog[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[a-z0-9]{32}['\"]?", "high"),
    ("Datadog Application Key", r"(?i)datadog[_\-]?app[_\-]?key\s*[=:]\s*['\"][a-z0-9]{32}['\"]?", "high"),
    ("New Relic API Key", r"(?i)newrelic[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9]{32,}['\"]?", "high"),
    ("Sentry DSN", r"https://[a-f0-9]{32}@apps\.sentry\.io/[0-9]+", "high"),
    
    # Communication (additional)
    ("Discord Webhook", r"https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+", "high"),
    ("Mailgun API Key", r"key-[a-zA-Z0-9]{32}", "high"),
    ("Postmark API Key", r"(?i)postmark[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[a-f0-9]{64}['\"]?", "medium"),
    ("Mandrill API Key", r"(?i)mandrill[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9]{32}['\"]?", "medium"),
    
    # Payment Processors (additional)
    ("Braintree API Key", r"(?i)braintree[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9]{16,}['\"]?", "high"),
    ("PayPal Secret", r"(?i)paypal[_\-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9]{32,}['\"]?", "high"),
    ("Razorpay API Key", r"(?i)razorpay[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9]{32}['\"]?", "high"),
    ("Razorpay Secret", r"(?i)razorpay[_\-]?secret\s*[=:]\s*['\"]?[a-zA-Z0-9]{24}['\"]?", "critical"),
    ("Square OAuth Token", r"sq0c-?[A-Za-z0-9_-]{40}", "high"),
    ("Coinbase API Key", r"(?i)coinbase[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?", "high"),
    ("Binance API Key", r"(?i)binance[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?", "high"),
    
    # AI APIs (additional)
    ("Replicate API Key", r"r8_[A-Za-z0-9]{72}", "critical"),
    ("Together API Key", r"together-[a-zA-Z0-9]{32}", "high"),
    ("DeepSeek API Key", r"sk-[a-zA-Z0-9]{32}", "high"),
    ("Mistral API Key", r"mistral-[a-zA-Z0-9]{32}", "high"),
    ("Cohere API Key", r"(?i)cohere[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9]{32}['\"]?", "high"),
    ("Groq API Key", r"gsk_[a-zA-Z0-9]{32}", "high"),
    
    # Other Cloud / Database
    ("Supabase Service Role Key", r"service_role[_-]key", "high"),
    ("PlanetScale DB URL", r"mysql://[a-zA-Z0-9]+:[a-zA-Z0-9]+@ep-", "high"),
    ("PlanetScale Key", r"pscale_[a-zA-Z0-9]{32}", "high"),
    ("Parse App ID", r"(?i)parse[_\-]?app[_\-]?id\s*[=:]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?", "medium"),
    ("Parse REST Key", r"(?i)parse[_\-]?rest[_\-]?key\s*[=:]\s*['\"][a-zA-Z0-9]{20,}['\"]?", "medium"),
    ("MongoURI", r"mongodb(\+srv)?://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-z0-9.-]+\.[a-z]{2,}", "critical"),
    
    # Private Keys (additional formats)
    ("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "critical"),
    ("PuTTY Private Key", r"PuTTY-User-Key-File-2:", "high"),
    
    # Auth Tokens
    ("Auth0 Token", r"(?i)auth0[_\-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_.-]{50,}['\"]?", "high"),
    ("Auth0 Domain", r"(?i)auth0[_\-]?domain\s*[=:]\s*['\"]?[a-z0-9-]+\.auth0\.com['\"]?", "medium"),
    ("Okta API Token", r"00[a-zA-Z0-9_-]{40}", "high"),
    ("Firebase API Key", r"AIza[0-9A-Za-z\-_]{35}", "medium"),
    ("Firebase Auth Token", r"(?i)firebase[_\-]?auth\s*[=:]\s*['\"]?[a-zA-Z0-9._-]{40,}['\"]?", "high"),
    ("Firebase Database URL", r"https://[a-z0-9-]+\.firebaseio\.com", "medium"),
    
    # API Keys (Generic, additional)
    ("Google Maps API Key", r"(?i)google[_\-]?maps[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{39}['\"]?", "medium"),
    ("Amazon Secret Key", r"(?i)amazon[_\-]?secret[_\-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "critical"),
    ("Amazon Access Key", r"(?i)amazon[_\-]?access[_\-]?key\s*[=:]\s*['\"]?[A-Z0-9]{20}['\"]?", "high"),
    
    # Database Passwords
    ("MySQL Password", r"(?i)mysql[_\-]?password\s*[=:]\s*['\"][^'\"\s]{8,}['\"]", "high"),
    ("PostgreSQL Password", r"(?i)postgres[_\-]?password\s*[=:]\s*['\"][^'\"\s]{8,}['\"]", "high"),
    ("MongoDB Password", r"(?i)mongo[_\-]?password\s*[=:]\s*['\"][^'\"\s]{8,}['\"]", "high"),
    ("Redis Password", r"(?i)redis[_\-]?password\s*[=:]\s*['\"][^'\"\s]{8,}['\"]", "high"),
    
    # Session / Cookie
    ("Session Secret", r"(?i)session[_\-]?secret\s*[=:]\s*['\"][a-zA-Z0-9_-]{16,}['\"]", "medium"),
    ("JWT Secret", r"(?i)jwt[_\-]?secret\s*[=:]\s*['\"][a-zA-Z0-9_-]{16,}['\"]", "medium"),
    ("Cookie Secret", r"(?i)cookie[_\-]?secret\s*[=:]\s*['\"][a-zA-Z0-9_-]{16,}['\"]", "medium"),
    ("Encryption Key", r"(?i)encryption[_\-]?key\s*[=:]\s*['\"][a-zA-Z0-9_-]{16,}['\"]", "medium"),
    
    # OAuth
    ("OAuth Token Secret", r"(?i)oauth[_\-]?token[_\-]?secret\s*[=:]\s*['\"][a-zA-Z0-9_-]{20,}['\"]", "high"),
    ("OAuth Client Secret", r"(?i)oauth[_\-]?client[_\-]?secret\s*[=:]\s*['\"][a-zA-Z0-9_-]{20,}['\"]", "high"),
    ("OAuth Consumer Secret", r"(?i)oauth[_\-]?consumer[_\-]?secret\s*[=:]\s*['\"][a-zA-Z0-9_-]{20,}['\"]", "high"),
    
    # Misc Services
    ("SonarQube Token", r"(?i)sonar[_\-]?token\s*[=:]\s*['\"][a-zA-Z0-9_-]{40,}['\"]", "high"),
    ("GitHub Webhook Secret", r"(?i)webhook[_\-]?secret\s*[=:]\s*['\"][a-zA-Z0-9_-]{20,}['\"]", "high"),
    ("NPM Token (env)", r"(?i)npm[_\-]?token\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{40,}['\"]?", "high"),
    ("Twilio Auth Token", r"(?i)twilio[_\-]?auth[_\-]?token\s*[=:]\s*['\"][a-zA-Z0-9]{32}['\"]", "high"),
    ("Twilio Account SID", r"AC[a-zA-Z0-9]{32}", "high"),
]