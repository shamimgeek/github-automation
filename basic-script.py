from github import Github
from collections import defaultdict

# --- Configuration ---
ACCESS_TOKEN = "your_github_pat_here"
ORG_NAME = "your-org-name"

def list_repos_by_language():
    # Initialize GitHub client
    g = Github(ACCESS_TOKEN)
    
    try:
        # Get the organization
        org = g.get_organization(ORG_NAME)
        print(f"Connected to: {org.name or ORG_NAME}")
        
        # Dictionary to store repositories: { "Python": ["repo1", "repo2"], "Go": ["repo3"] }
        lang_map = defaultdict(list)
        
        print("Fetching repositories... This may take a moment.")
        
        # Iterate through all repos in the organization
        for repo in org.get_repos():
            # Use 'language' for the primary language identified by GitHub
            primary_lang = repo.language if repo.language else "Unspecified"
            lang_map[primary_lang].append(repo.full_name)

        # Print results in a clean format
        print("\n--- Repositories by Language ---")
        for language, repos in sorted(lang_map.items()):
            print(f"\n[ {language} ] - {len(repos)} repositories")
            for repo_name in repos:
                print(f"  - {repo_name}")
                
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    list_repos_by_language()
