#!/usr/bin/env python3
"""
GitHub Secret Sync Tool with Proxy Support
Synchronizes secrets across multiple GitHub repositories using GitHub API
"""

import os
import sys
import base64
import argparse
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from collections import Counter

import requests
from github import Github
from github.GithubException import GithubException
from nacl import encoding, public
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class GitHubSecretSync:
    """Main class to handle GitHub secret synchronization with proxy support"""
    
    def __init__(self, github_token: str, org_name: Optional[str] = None, 
                 proxy: Optional[str] = None, proxy_user: Optional[str] = None, 
                 proxy_pass: Optional[str] = None):
        """
        Initialize the GitHub Secret Sync tool
        
        Args:
            github_token: GitHub Personal Access Token
            org_name: GitHub organization name (None for user account)
            proxy: Proxy server URL (e.g., http://proxy.company.com:8080)
            proxy_user: Proxy username (if authentication required)
            proxy_pass: Proxy password (if authentication required)
        """
        self.github_token = github_token
        self.org_name = org_name
        self.proxy = proxy
        self.proxy_user = proxy_user
        self.proxy_pass = proxy_pass
        
        # Configure proxy for requests
        self.proxies = self._configure_proxy()
        
        # Initialize GitHub client with proxy support
        self.github = self._init_github_client()
        self.api_base = "https://api.github.com"
    
    def _configure_proxy(self) -> Dict:
        """Configure proxy settings for requests"""
        proxies = {}
        
        if self.proxy:
            # If username and password provided, add them to proxy URL
            if self.proxy_user and self.proxy_pass:
                # Parse proxy URL and add credentials
                if self.proxy.startswith('http://'):
                    proxy_url = f"http://{self.proxy_user}:{self.proxy_pass}@{self.proxy[7:]}"
                elif self.proxy.startswith('https://'):
                    proxy_url = f"https://{self.proxy_user}:{self.proxy_pass}@{self.proxy[8:]}"
                else:
                    proxy_url = f"http://{self.proxy_user}:{self.proxy_pass}@{self.proxy}"
                
                proxies['http'] = proxy_url
                proxies['https'] = proxy_url
            else:
                # Use proxy without authentication
                proxies['http'] = self.proxy
                proxies['https'] = self.proxy
            
            print(f"✓ Proxy configured: {self.proxy.split(':')[0]}://{self.proxy.split('://')[1].split('@')[-1] if '@' in self.proxy else self.proxy}")
        
        # Also check environment variables
        if not proxies:
            http_proxy = os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
            https_proxy = os.getenv('HTTPS_PROXY') or os.getenv('https_proxy')
            
            if http_proxy:
                proxies['http'] = http_proxy
            if https_proxy:
                proxies['https'] = https_proxy
            
            if proxies:
                print("✓ Using proxy from environment variables")
        
        return proxies
    
    def _init_github_client(self):
        """Initialize GitHub client with optional proxy"""
        try:
            if self.proxies:
                # Configure requests session with proxy
                session = requests.Session()
                session.proxies.update(self.proxies)
                
                # For PyGithub, we need to use custom requester
                from github import Github
                from github.Requester import Requester
                
                # Create custom requester with proxy
                requester = Requester(
                    login_or_token=self.github_token,
                    password=None,
                    jwt=None,
                    base_url="https://api.github.com",
                    timeout=10,
                    user_agent="PyGithub/Python",
                    per_page=30,
                    verify=True,
                    retry=0,
                    pool_size=None,
                    proxies=self.proxies
                )
                
                return Github(login_or_token=self.github_token, requester=requester)
            else:
                return Github(self.github_token)
        except Exception as e:
            print(f"⚠ GitHub client initialization with proxy failed: {e}")
            print("Trying without proxy...")
            return Github(self.github_token)
    
    def encrypt_secret(self, public_key: str, secret_value: str) -> str:
        """Encrypt a secret using the repository's public key"""
        public_key = public.PublicKey(
            public_key.encode("utf-8"), 
            encoding.Base64Encoder()
        )
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
        return base64.b64encode(encrypted).decode("utf-8")
    
    def secret_exists(self, repo_full_name: str, secret_name: str) -> Tuple[bool, Optional[Dict]]:
        """Check if a secret exists in a repository"""
        url = f"{self.api_base}/repos/{repo_full_name}/actions/secrets/{secret_name}"
        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            # Use requests with proxy configuration
            response = requests.get(url, headers=headers, proxies=self.proxies if self.proxies else None)
            
            if response.status_code == 200:
                return True, response.json()
            elif response.status_code == 404:
                return False, None
            else:
                print(f"    ⚠ API returned {response.status_code}: {response.text}")
                return False, None
        except requests.RequestException as e:
            print(f"    ✗ API request failed: {e}")
            if "407" in str(e):
                print("    💡 Proxy authentication failed. Check your proxy credentials.")
            return False, None
    
    def get_repositories(self, repo_filter: Optional[str] = None, language: Optional[str] = None) -> List:
        """Get all repositories based on filters"""
        try:
            if self.org_name:
                repos = list(self.github.get_organization(self.org_name).get_repos())
            else:
                repos = list(self.github.get_user().get_repos())
            
            # Apply name filter if provided
            if repo_filter:
                filtered_repos = []
                for repo in repos:
                    if repo_filter.lower() in repo.name.lower():
                        filtered_repos.append(repo)
                repos = filtered_repos
            
            # Apply language filter if provided
            if language:
                language_filtered = []
                for repo in repos:
                    if repo.language and repo.language.lower() == language.lower():
                        language_filtered.append(repo)
                repos = language_filtered
            
            return repos
            
        except GithubException as e:
            print(f"✗ Failed to fetch repositories: {e}")
            if "407" in str(e):
                print("💡 Proxy authentication error. Use --proxy, --proxy-user, and --proxy-pass options")
            return []
    
    def get_single_repository(self, repo_name: str):
        """Get a single repository by name"""
        try:
            if '/' in repo_name:
                return self.github.get_repo(repo_name)
            else:
                if self.org_name:
                    full_name = f"{self.org_name}/{repo_name}"
                else:
                    user = self.github.get_user()
                    full_name = f"{user.login}/{repo_name}"
                return self.github.get_repo(full_name)
        except GithubException as e:
            print(f"✗ Repository '{repo_name}' not found: {e}")
            return None
    
    def list_repositories_by_language(self, language: Optional[str] = None, repo_filter: Optional[str] = None) -> Dict[str, List]:
        """List repositories grouped by language"""
        try:
            if self.org_name:
                repos = list(self.github.get_organization(self.org_name).get_repos())
            else:
                repos = list(self.github.get_user().get_repos())
            
            # Apply name filter if provided
            if repo_filter:
                repos = [repo for repo in repos if repo_filter.lower() in repo.name.lower()]
            
            # Group by language
            language_groups = {}
            repo_details = []
            
            for repo in repos:
                lang = repo.language if repo.language else "Unknown/No Language"
                
                # Filter by specific language if provided
                if language and lang.lower() != language.lower():
                    continue
                
                if lang not in language_groups:
                    language_groups[lang] = []
                
                repo_info = {
                    "name": repo.full_name,
                    "url": repo.html_url,
                    "description": repo.description[:50] + "..." if repo.description and len(repo.description) > 50 else repo.description,
                    "private": repo.private,
                    "updated_at": repo.updated_at.strftime("%Y-%m-%d"),
                    "size_mb": round(repo.size / 1024, 2) if repo.size else 0
                }
                language_groups[lang].append(repo_info)
                repo_details.append(repo_info)
            
            return language_groups
            
        except GithubException as e:
            print(f"✗ Failed to fetch repositories: {e}")
            return {}
    
    def add_secret(self, repo, secret_name: str, secret_value: str, force: bool = False) -> Tuple[str, str]:
        """Add or update a secret in a repository"""
        repo_full_name = repo.full_name
        
        # Check if secret already exists
        exists, secret_data = self.secret_exists(repo_full_name, secret_name)
        
        if exists and not force:
            updated_at = secret_data.get('updated_at', 'unknown')
            return "skipped", f"already exists (last updated: {updated_at})"
        
        try:
            # Get repository's public key
            public_key = repo.get_public_key()
            
            # Encrypt the secret
            encrypted_value = self.encrypt_secret(public_key.key, secret_value)
            
            # Create or update the secret
            repo.create_secret(secret_name, encrypted_value, public_key.key_id)
            
            if exists and force:
                return "updated", "successfully updated"
            else:
                return "added", "successfully added"
                
        except GithubException as e:
            return "error", f"GitHub API error: {e}"
        except Exception as e:
            return "error", f"unexpected error: {e}"
    
    def sync_secrets(self, secrets: Dict[str, str], force_secrets: Optional[List[str]] = None,
                    repo_filter: Optional[str] = None, language: Optional[str] = None, 
                    dry_run: bool = False) -> Dict[str, int]:
        """Synchronize secrets across all repositories"""
        force_secrets = force_secrets or []
        stats = {"added": 0, "updated": 0, "skipped": 0, "errors": 0, "repos_processed": 0}
        
        # Get repositories with filters
        repositories = self.get_repositories(repo_filter, language)
        
        if not repositories:
            print("✗ No repositories found matching the criteria!")
            return stats
        
        print(f"\n📊 Found {len(repositories)} repository(ies) to process")
        if language:
            print(f"   Language filter: {language}")
        if repo_filter:
            print(f"   Name filter: {repo_filter}")
        if dry_run:
            print("⚠ DRY RUN MODE: No changes will be made\n")
        
        # Process each repository
        for repo in repositories:
            stats["repos_processed"] += 1
            print(f"\n📁 Repository: {repo.full_name}")
            print(f"   Language: {repo.language if repo.language else 'Unknown'}")
            print(f"   URL: {repo.html_url}")
            
            for secret_name, secret_value in secrets.items():
                force = secret_name in force_secrets
                
                if dry_run:
                    # Check if secret exists without modifying
                    exists, _ = self.secret_exists(repo.full_name, secret_name)
                    if exists and not force:
                        print(f"   ⏭ [DRY RUN] Would skip {secret_name} (already exists)")
                        stats["skipped"] += 1
                    else:
                        action = "update" if exists and force else "add"
                        print(f"   🔄 [DRY RUN] Would {action} {secret_name}")
                        stats["added" if action == "add" else "updated"] += 1
                else:
                    # Actually add/update the secret
                    status, message = self.add_secret(repo, secret_name, secret_value, force)
                    
                    # Print appropriate message
                    if status == "added":
                        print(f"   ✓ Added {secret_name}: {message}")
                        stats["added"] += 1
                    elif status == "updated":
                        print(f"   🔄 Updated {secret_name}: {message}")
                        stats["updated"] += 1
                    elif status == "skipped":
                        print(f"   ⏭ Skipped {secret_name}: {message}")
                        stats["skipped"] += 1
                    else:
                        print(f"   ✗ Error with {secret_name}: {message}")
                        stats["errors"] += 1
        
        return stats
    
    def validate_token(self) -> bool:
        """Validate that the GitHub token has necessary permissions"""
        try:
            user = self.github.get_user()
            print(f"✓ Authenticated as: {user.login}")
            
            # Test token permissions by attempting to list secrets (won't actually create)
            test_repos = self.get_repositories()
            if test_repos:
                print(f"✓ Successfully accessed {len(test_repos)} repository(ies)")
                return True
            else:
                print("⚠ No repositories found - check token permissions")
                return False
                
        except GithubException as e:
            print(f"✗ Authentication failed: {e}")
            return False

def load_secrets_from_file(filepath: str) -> Dict[str, str]:
    """Load secrets from a file (format: SECRET_NAME=value)"""
    secrets = {}
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        secrets[key.strip()] = value.strip()
        print(f"✓ Loaded {len(secrets)} secret(s) from {filepath}")
        return secrets
    except FileNotFoundError:
        print(f"✗ File not found: {filepath}")
        return {}
    except Exception as e:
        print(f"✗ Error loading secrets file: {e}")
        return {}

def main():
    """Main entry point for the script"""
    parser = argparse.ArgumentParser(
        description="GitHub Secret Sync Tool - Synchronize secrets across repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage without proxy
  python github_secret_sync.py --secrets-file secrets.txt --dry-run
  
  # With proxy authentication
  python github_secret_sync.py --secrets-file secrets.txt --proxy http://proxy.company.com:8080 --proxy-user myuser --proxy-pass mypass
  
  # With proxy from environment variables
  export HTTP_PROXY=http://user:pass@proxy:8080
  python github_secret_sync.py --secrets-file secrets.txt
  
  # List repositories with proxy
  python github_secret_sync.py --list-repos --proxy http://proxy.company.com:8080 --proxy-user myuser --proxy-pass mypass
  
  # Update single repository through proxy
  python github_secret_sync.py --repo my-repo --secrets-file secrets.txt --proxy http://proxy.company.com:8080 --proxy-user domain\\username --proxy-pass mypass
        """
    )
    
    # GitHub configuration
    parser.add_argument("--token", help="GitHub Personal Access Token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--org", help="GitHub organization name (omit for user account)")
    
    # Proxy configuration
    parser.add_argument("--proxy", help="Proxy server URL (e.g., http://proxy.company.com:8080)")
    parser.add_argument("--proxy-user", help="Proxy username (if authentication required)")
    parser.add_argument("--proxy-pass", help="Proxy password (if authentication required)")
    
    # Secret sources (at least one required for sync operations)
    parser.add_argument("--secret", action="append", help="Single secret in format NAME=value (can be used multiple times)")
    parser.add_argument("--secrets-file", help="File containing secrets (one per line: NAME=value)")
    
    # Filter options
    parser.add_argument("--repo", help="Specific repository to update (format: owner/repo or just repo name)")
    parser.add_argument("--language", help="Filter repositories by programming language (e.g., python, javascript, go)")
    parser.add_argument("--repo-filter", help="Only process repositories containing this string in name")
    parser.add_argument("--force", help="Comma-separated list of secret names to force update")
    
    # Action options
    parser.add_argument("--list-repos", action="store_true", help="List repositories grouped by language")
    parser.add_argument("--language-stats", action="store_true", help="Show language statistics across repositories")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")
    
    args = parser.parse_args()
    
    # Get GitHub token
    github_token = args.token or os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("✗ Error: GitHub token not found. Provide --token or set GITHUB_TOKEN environment variable")
        sys.exit(1)
    
    # Initialize the sync tool with proxy settings
    syncer = GitHubSecretSync(
        github_token=github_token,
        org_name=args.org,
        proxy=args.proxy,
        proxy_user=args.proxy_user,
        proxy_pass=args.proxy_pass
    )
    
    # Handle list-only operations
    if args.list_repos or args.language_stats:
        # Validate token
        if not syncer.validate_token():
            print("\n✗ Token validation failed. Please check your GitHub token permissions.")
            sys.exit(1)
        
        if args.language_stats:
            # Show language statistics
            stats = syncer.get_language_statistics(args.repo_filter)
            print("\n" + "="*60)
            print("📊 LANGUAGE STATISTICS")
            print("="*60)
            for language, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
                bar_length = min(50, count * 2)
                bar = "█" * bar_length
                print(f"{language:<20} {count:>4} repositories {bar}")
            print("="*60)
        
        if args.list_repos:
            # List repositories by language
            repos_by_language = syncer.list_repositories_by_language(args.language, args.repo_filter)
            if repos_by_language:
                # Use the print function from earlier
                print("\n" + "="*100)
                print(f"📚 REPOSITORIES BY LANGUAGE")
                print("="*100)
                for language, repos in sorted(repos_by_language.items()):
                    print(f"\n🔤 {language} ({len(repos)} repositories)")
                    print("-" * 80)
                    for repo in repos:
                        private_icon = "🔒" if repo['private'] else "🌐"
                        print(f"{repo['name']:<40} {private_icon:<8} {repo['updated_at']:<12} {repo['size_mb']:<10} {repo['description'] or ''}")
                print("\n" + "="*100)
            else:
                print(f"\n✗ No repositories found matching the criteria")
        
        sys.exit(0)
    
    # For sync operations, validate secrets source
    if not args.secret and not args.secrets_file:
        print("✗ Error: Either --secret or --secrets-file must be provided for sync operations")
        print("Use --list-repos or --language-stats to just view repositories")
        sys.exit(1)
    
    # Collect secrets
    secrets = {}
    
    # Load from file if provided
    if args.secrets_file:
        file_secrets = load_secrets_from_file(args.secrets_file)
        secrets.update(file_secrets)
    
    # Add command-line secrets
    if args.secret:
        for secret_pair in args.secret:
            if '=' in secret_pair:
                key, value = secret_pair.split('=', 1)
                secrets[key] = value
            else:
                print(f"⚠ Warning: Invalid secret format: {secret_pair}")
    
    if not secrets:
        print("✗ Error: No valid secrets provided")
        sys.exit(1)
    
    # Parse force update list
    force_secrets = []
    if args.force:
        force_secrets = [s.strip() for s in args.force.split(',')]
    
    # Display configuration
    print("\n" + "="*60)
    print("🔐 GITHUB SECRET SYNC TOOL")
    print("="*60)
    print(f"Organization: {args.org if args.org else 'Personal account'}")
    print(f"Secrets to sync: {', '.join(secrets.keys())}")
    if force_secrets:
        print(f"Force update: {', '.join(force_secrets)}")
    if args.repo:
        print(f"Target repository: {args.repo}")
    if args.repo_filter:
        print(f"Repository name filter: {args.repo_filter}")
    if args.language:
        print(f"Language filter: {args.language}")
    if args.dry_run:
        print("⚠ MODE: DRY RUN (no changes will be made)")
    print("="*60)
    
    # Validate token
    if not syncer.validate_token():
        print("\n✗ Token validation failed. Please check your GitHub token permissions.")
        print("Required scopes: repo, public_repo, admin:org")
        sys.exit(1)
    
    # Get repositories (specific or filtered)
    if args.repo:
        repositories = [syncer.get_single_repository(args.repo)] if syncer.get_single_repository(args.repo) else []
        if not repositories:
            sys.exit(1)
    else:
        repositories = syncer.get_repositories(args.repo_filter, args.language)
    
    if not repositories:
        print("✗ No repositories found matching the criteria!")
        sys.exit(1)
    
    print(f"\n📋 Will process {len(repositories)} repository(ies):")
    for repo in repositories[:10]:
        lang_info = f" [{repo.language}]" if repo.language else ""
        print(f"   • {repo.full_name}{lang_info}")
    if len(repositories) > 10:
        print(f"   ... and {len(repositories) - 10} more")
    
    # Confirm before proceeding (skip for dry run)
    if not args.dry_run:
        print("\n⚠ WARNING: This will add/update secrets in the repositories listed above.")
        response = input("Continue? (y/N): ").strip().lower()
        if response not in ['y', 'yes']:
            print("Operation cancelled.")
            sys.exit(0)
    
    # Sync secrets
    stats = syncer.sync_secrets(
        secrets=secrets,
        force_secrets=force_secrets,
        repo_filter=args.repo_filter if not args.repo else None,
        language=args.language,
        dry_run=args.dry_run
    )
    
    # Print final summary
    print("\n" + "="*60)
    print("📊 SYNC SUMMARY")
    print("="*60)
    print(f"Repositories processed: {stats['repos_processed']}")
    print(f"✓ Secrets added: {stats['added']}")
    print(f"🔄 Secrets updated: {stats['updated']}")
    print(f"⏭ Secrets skipped: {stats['skipped']}")
    print(f"✗ Errors: {stats['errors']}")
    print("="*60)
    
    if args.dry_run:
        print("\n💡 Run without --dry-run to apply these changes")
    
    # Exit with error code if there were errors
    if stats['errors'] > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
