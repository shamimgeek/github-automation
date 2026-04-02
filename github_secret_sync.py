#!/usr/bin/env python3
"""
GitHub Secret Sync Tool
Synchronizes secrets across multiple GitHub repositories using GitHub API
Author: GitHub Secret Manager
Version: 2.0.0
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
    """Main class to handle GitHub secret synchronization"""
    
    def __init__(self, github_token: str, org_name: Optional[str] = None):
        """
        Initialize the GitHub Secret Sync tool
        
        Args:
            github_token: GitHub Personal Access Token
            org_name: GitHub organization name (None for user account)
        """
        self.github_token = github_token
        self.org_name = org_name
        self.github = Github(github_token)
        self.api_base = "https://api.github.com"
        
    def encrypt_secret(self, public_key: str, secret_value: str) -> str:
        """
        Encrypt a secret using the repository's public key
        
        Args:
            public_key: Repository's public key (base64 encoded)
            secret_value: Secret value to encrypt
            
        Returns:
            Encrypted secret as base64 string
        """
        public_key = public.PublicKey(
            public_key.encode("utf-8"), 
            encoding.Base64Encoder()
        )
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
        return base64.b64encode(encrypted).decode("utf-8")
    
    def secret_exists(self, repo_full_name: str, secret_name: str) -> Tuple[bool, Optional[Dict]]:
        """
        Check if a secret exists in a repository
        
        Args:
            repo_full_name: Full repository name (e.g., "owner/repo")
            secret_name: Name of the secret to check
            
        Returns:
            Tuple of (exists, secret_data)
        """
        url = f"{self.api_base}/repos/{repo_full_name}/actions/secrets/{secret_name}"
        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return True, response.json()
            elif response.status_code == 404:
                return False, None
            else:
                print(f"    ⚠ API returned {response.status_code}: {response.text}")
                return False, None
        except requests.RequestException as e:
            print(f"    ✗ API request failed: {e}")
            return False, None
    
    def get_repositories(self, repo_filter: Optional[str] = None, language: Optional[str] = None) -> List:
        """
        Get all repositories based on filters
        
        Args:
            repo_filter: Optional filter pattern for repository names
            language: Optional filter for programming language
            
        Returns:
            List of repository objects
        """
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
                    # Check if repository has the specified language
                    if repo.language and repo.language.lower() == language.lower():
                        language_filtered.append(repo)
                    elif not repo.language:
                        # Optionally include repos with no language detected
                        pass  # Skip repos without language
                repos = language_filtered
            
            return repos
            
        except GithubException as e:
            print(f"✗ Failed to fetch repositories: {e}")
            return []
    
    def list_repositories_by_language(self, language: Optional[str] = None, repo_filter: Optional[str] = None) -> Dict[str, List]:
        """
        List repositories grouped by language
        
        Args:
            language: Optional specific language to filter by
            repo_filter: Optional pattern to filter repository names
            
        Returns:
            Dictionary with language as key and list of repos as value
        """
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
        """
        Add or update a secret in a repository
        
        Args:
            repo: GitHub repository object
            secret_name: Name of the secret
            secret_value: Value of the secret
            force: Force update even if secret exists
            
        Returns:
            Tuple of (status, message)
        """
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
        """
        Synchronize secrets across all repositories
        
        Args:
            secrets: Dictionary of secret names and values
            force_secrets: List of secret names to force update
            repo_filter: Optional filter for repository names
            language: Optional filter for programming language
            dry_run: If True, only show what would be done without making changes
            
        Returns:
            Dictionary with statistics
        """
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
    
    def get_language_statistics(self, repo_filter: Optional[str] = None) -> Dict:
        """
        Get statistics about languages used in repositories
        
        Args:
            repo_filter: Optional pattern to filter repository names
            
        Returns:
            Dictionary with language statistics
        """
        try:
            if self.org_name:
                repos = list(self.github.get_organization(self.org_name).get_repos())
            else:
                repos = list(self.github.get_user().get_repos())
            
            # Apply name filter if provided
            if repo_filter:
                repos = [repo for repo in repos if repo_filter.lower() in repo.name.lower()]
            
            language_counts = Counter()
            for repo in repos:
                lang = repo.language if repo.language else "Unknown"
                language_counts[lang] += 1
            
            return dict(language_counts)
            
        except GithubException as e:
            print(f"✗ Failed to fetch repositories: {e}")
            return {}
    
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

def print_repositories_table(repos_by_language: Dict[str, List]):
    """Print repositories in a formatted table grouped by language"""
    total_repos = sum(len(repos) for repos in repos_by_language.values())
    
    print("\n" + "="*100)
    print(f"📚 REPOSITORIES BY LANGUAGE (Total: {total_repos})")
    print("="*100)
    
    for language, repos in sorted(repos_by_language.items()):
        print(f"\n🔤 {language} ({len(repos)} repositories)")
        print("-" * 80)
        
        # Print table header
        print(f"{'Repository Name':<40} {'Private':<8} {'Updated':<12} {'Size(MB)':<10} Description")
        print("-" * 80)
        
        for repo in repos:
            private_icon = "🔒" if repo['private'] else "🌐"
            print(f"{repo['name']:<40} {private_icon:<8} {repo['updated_at']:<12} {repo['size_mb']:<10} {repo['description'] or ''}")
    
    print("\n" + "="*100)

def main():
    """Main entry point for the script"""
    parser = argparse.ArgumentParser(
        description="GitHub Secret Sync Tool - Synchronize secrets across repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all repositories grouped by language
  python github_secret_sync.py --list-repos
  
  # List only Python repositories
  python github_secret_sync.py --list-repos --language python
  
  # Show language statistics
  python github_secret_sync.py --language-stats
  
  # Sync secrets to Python repositories only
  python github_secret_sync.py --secrets-file secrets.txt --language python
  
  # Sync secrets to JavaScript repos containing "api" in name
  python github_secret_sync.py --secrets-file secrets.txt --language javascript --repo-filter api
  
  # Sync specific secrets to all repositories
  python github_secret_sync.py --secret DEPLOY_KEY=value --secret API_KEY=value
  
  # Force update specific secrets in TypeScript repos
  python github_secret_sync.py --secrets-file secrets.txt --language typescript --force DATABASE_URL,API_KEY
  
  # Dry run to see what would change
  python github_secret_sync.py --secrets-file secrets.txt --language python --dry-run
  
  # Use organization instead of user account
  python github_secret_sync.py --org my-organization --secrets-file secrets.txt --language go
        """
    )
    
    # GitHub configuration
    parser.add_argument("--token", help="GitHub Personal Access Token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--org", help="GitHub organization name (omit for user account)")
    
    # Secret sources (at least one required for sync operations)
    parser.add_argument("--secret", action="append", help="Single secret in format NAME=value (can be used multiple times)")
    parser.add_argument("--secrets-file", help="File containing secrets (one per line: NAME=value)")
    
    # Filter options
    parser.add_argument("--language", help="Filter repositories by programming language (e.g., python, javascript, go)")
    parser.add_argument("--repo-filter", help="Only process repositories containing this string in name")
    parser.add_argument("--force", help="Comma-separated list of secret names to force update")
    
    # Action options
    parser.add_argument("--list-repos", action="store_true", help="List repositories grouped by language")
    parser.add_argument("--language-stats", action="store_true", help="Show language statistics across repositories")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")
    
    args = parser.parse_args()
    
    # Handle list-only operations (no secrets required)
    if args.list_repos or args.language_stats:
        # Get GitHub token
        github_token = args.token or os.getenv("GITHUB_TOKEN")
        if not github_token:
            print("✗ Error: GitHub token not found. Provide --token or set GITHUB_TOKEN environment variable")
            sys.exit(1)
        
        # Initialize the sync tool
        syncer = GitHubSecretSync(github_token, args.org)
        
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
                print_repositories_table(repos_by_language)
            else:
                print(f"\n✗ No repositories found matching the criteria")
                if args.language:
                    print(f"   Language filter: {args.language}")
                if args.repo_filter:
                    print(f"   Name filter: {args.repo_filter}")
        
        sys.exit(0)
    
    # For sync operations, validate secrets source
    if not args.secret and not args.secrets_file:
        print("✗ Error: Either --secret or --secrets-file must be provided for sync operations")
        print("Use --list-repos or --language-stats to just view repositories")
        print("Use --help for more information")
        sys.exit(1)
    
    # Get GitHub token
    github_token = args.token or os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("✗ Error: GitHub token not found. Provide --token or set GITHUB_TOKEN environment variable")
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
                print(f"⚠ Warning: Invalid secret format: {secret_pair} (expected NAME=value)")
    
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
    if args.repo_filter:
        print(f"Repository name filter: {args.repo_filter}")
    if args.language:
        print(f"Language filter: {args.language}")
    if args.dry_run:
        print("⚠ MODE: DRY RUN (no changes will be made)")
    print("="*60)
    
    # Initialize the sync tool
    syncer = GitHubSecretSync(github_token, args.org)
    
    # Validate token
    if not syncer.validate_token():
        print("\n✗ Token validation failed. Please check your GitHub token permissions.")
        print("Required scopes: repo, public_repo, admin:org")
        sys.exit(1)
    
    # Show language statistics before proceeding (optional)
    if args.verbose:
        stats = syncer.get_language_statistics(args.repo_filter)
        if stats:
            print("\n📊 Current language distribution:")
            for lang, count in sorted(stats.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"   {lang}: {count} repos")
    
    # Show repositories that will be affected
    matching_repos = syncer.get_repositories(args.repo_filter, args.language)
    if matching_repos:
        print(f"\n📋 Will process {len(matching_repos)} repository(ies):")
        for repo in matching_repos[:10]:  # Show first 10
            lang_info = f" [{repo.language}]" if repo.language else ""
            print(f"   • {repo.full_name}{lang_info}")
        if len(matching_repos) > 10:
            print(f"   ... and {len(matching_repos) - 10} more")
    
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
        repo_filter=args.repo_filter,
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
