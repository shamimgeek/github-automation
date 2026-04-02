Script

# Install all required packages
`pip install -r requirements.txt`

# Verify installations
`pip list | grep -E "PyGithub|pynacl|requests|python-dotenv"`


```cat > .env << EOF
# GitHub Personal Access Token
# Generate at: https://github.com/settings/tokens
# Required scopes: repo, public_repo, admin:org
GITHUB_TOKEN=ghp_your_personal_access_token_here
EOF

# Secure the .env file
chmod 600 .env```


`cat > secrets.txt << EOF
# GitHub Secrets File
# Format: SECRET_NAME=value
# Lines starting with # are ignored

DEPLOY_KEY=your-ssh-private-key-here
API_TOKEN=your-api-token-here
DATABASE_URL=postgresql://username:password@localhost:5432/mydb
SLACK_WEBHOOK=https://hooks.slack.com/services/XXXX/YYYY/ZZZZ
EOF

# Secure the secrets file
chmod 600 secrets.txt`


# 1. Sync secrets from file to all repositories
python github_secret_sync.py --secrets-file secrets.txt

# 2. Sync a single secret to all repositories
python github_secret_sync.py --secret DEPLOY_KEY="my-ssh-key"

# 3. Sync multiple secrets via command line
python github_secret_sync.py --secret API_KEY="abc123" --secret DB_PASS="securepass"

# 4. Only sync to repositories containing "prod" in name
python github_secret_sync.py --secrets-file secrets.txt --repo-filter prod

# 5. Force update specific secrets even if they exist
python github_secret_sync.py --secrets-file secrets.txt --force DEPLOY_KEY,API_TOKEN

# 6. Dry run to see what would change (safe to run)
python github_secret_sync.py --secrets-file secrets.txt --dry-run

# 7. Sync to organization repositories
python github_secret_sync.py --org my-company --secrets-file secrets.txt

# 8. Verbose output with token from command line
python github_secret_sync.py --token ghp_xxxx --secrets-file secrets.txt --verbose

Advanced Examples:

# 9. Combine multiple sources and force update
python github_secret_sync.py \
    --secrets-file secrets.txt \
    --secret TEMP_SECRET="temp-value" \
    --force DEPLOY_KEY \
    --repo-filter production \
    --verbose

# 10. Test configuration with dry run
python github_secret_sync.py \
    --org my-org \
    --secrets-file secrets.txt \
    --repo-filter api \
    --dry-run



# Complete setup from scratch
cd ~/github-secret-manager
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Create and edit your secrets file
cp secrets.txt.example secrets.txt  # if you have example
nano secrets.txt  # Add your actual secrets

# Test with dry run first
python github_secret_sync.py --secrets-file secrets.txt --dry-run

# If dry run looks good, run for real
python github_secret_sync.py --secrets-file secrets.txt

# To exit virtual environment when done
deactivate
