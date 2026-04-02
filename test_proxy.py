import os
from dotenv import load_dotenv
import requests

load_dotenv()

print("Testing proxy configuration...")
print(f"HTTP_PROXY: {os.getenv('HTTP_PROXY')}")
print(f"PROXY_USER: {os.getenv('PROXY_USER')}")

# Test GitHub API through proxy
proxy_url = os.getenv('HTTP_PROXY')
proxies = {}
if proxy_url:
    if os.getenv('PROXY_USER') and os.getenv('PROXY_PASS'):
        # Add credentials
        proxy_parts = proxy_url.split('://')
        proxy_with_auth = f"{proxy_parts[0]}://{os.getenv('PROXY_USER')}:{os.getenv('PROXY_PASS')}@{proxy_parts[1]}"
        proxies = {'http': proxy_with_auth, 'https': proxy_with_auth}
    else:
        proxies = {'http': proxy_url, 'https': proxy_url}

try:
    response = requests.get('https://api.github.com', proxies=proxies, timeout=10)
    print(f"✓ Proxy working! Status code: {response.status_code}")
except Exception as e:
    print(f"✗ Proxy test failed: {e}")

