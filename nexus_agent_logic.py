import requests
import json
import os

def scan_repo_manifest(repo_url):
    """
    Nexus Agent Tool: Scan Repository Manifest
    """
    
    # 1. Sanitize URL to get "owner/repo"
    try:
        clean_url = repo_url.rstrip(".git").split("github.com/")[-1]
    except IndexError:
        return json.dumps({"error": "Invalid GitHub URL format. Use https://github.com/owner/repo"})

    api_base = f"https://api.github.com/repos/{clean_url}/contents"
    
    report = {
        "target": clean_url,
        "critical_files_found": [],
        "dependencies": [],
        "scan_status": "Success"
    }

    # 2. Prepare Authentication (THE CRITICAL FIX)
    headers = {}
    
    # Try to get token from Environment (Streamlit Secrets injects this into os.environ)
    token = os.environ.get('GITHUB_TOKEN')
    
    if token:
        headers['Authorization'] = f"token {token}"
    else:
        # Fallback: Try to find Streamlit secrets if not in env
        try:
            import streamlit as st
            if "GITHUB_TOKEN" in st.secrets:
                headers['Authorization'] = f"token {st.secrets['GITHUB_TOKEN']}"
        except:
            pass

    # 3. List files via GitHub API
    try:
        # We pass 'headers' here so GitHub knows who we are!
        resp = requests.get(api_base, headers=headers, timeout=10)
        
        if resp.status_code == 403:
            return json.dumps({"error": "Rate Limit Exceeded or Bad Token. Check Streamlit Secrets."})
        elif resp.status_code == 404:
            return json.dumps({"error": "Repository not found or private."})
        elif resp.status_code != 200:
            return json.dumps({"error": f"API Error: {resp.status_code}"})
        
        files = resp.json()
        
        # 4. Hunt for 'requirements.txt'
        for f in files:
            name = f['name']
            if name in ["requirements.txt", "package.json", "Pipfile", "setup.py"]:
                report["critical_files_found"].append(name)
            
            # Fetch content of requirements.txt
            if name == "requirements.txt":
                req_resp = requests.get(f['download_url'], headers=headers, timeout=10)
                deps = [line.strip() for line in req_resp.text.split('\n') if line.strip() and not line.startswith('#')]
                report["dependencies"] = deps

    except Exception as e:
        return json.dumps({"error": f"Internal Agent Error: {str(e)}"})

    return json.dumps(report, indent=2)
