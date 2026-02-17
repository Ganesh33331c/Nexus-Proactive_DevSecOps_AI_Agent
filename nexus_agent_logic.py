import requests
import json
import os

def scan_repo_manifest(repo_url):
    """
    Nexus Agent Tool: Diagnostic Mode
    """
    # 1. Clean URL
    try:
        # Remove trailing slash and .git
        clean_url = repo_url.rstrip("/").rstrip(".git").split("github.com/")[-1]
    except:
        return json.dumps({"error": "Invalid URL format."})

    api_base = f"https://api.github.com/repos/{clean_url}/contents"
    
    # 2. Setup Auth (Token is REQUIRED for Streamlit Cloud)
    headers = {
        "Accept": "application/vnd.github.v3+json"
    }
    
    token_source = "None"
    token = os.environ.get('GITHUB_TOKEN')
    
    # Check Environment Variable
    if token:
        headers['Authorization'] = f"token {token}"
        token_source = "Environment (os.environ)"
    else:
        # Check Streamlit Secrets directly
        try:
            import streamlit as st
            if "GITHUB_TOKEN" in st.secrets:
                headers['Authorization'] = f"token {st.secrets['GITHUB_TOKEN']}"
                token_source = "Streamlit Secrets"
        except:
            pass

    # 3. Initialize Report with Debug Info
    report = {
        "target": clean_url,
        "debug_info": {
            "token_source": token_source,
            "api_url": api_base,
            "status_code": "Not Run",
            "files_found": []
        },
        "critical_files_found": [],
        "dependencies": [],
        "scan_status": "Failed"
    }

    # 4. Execute Request
    try:
        resp = requests.get(api_base, headers=headers, timeout=10)
        report["debug_info"]["status_code"] = resp.status_code
        
        # ERROR HANDLING
        if resp.status_code == 403:
            return json.dumps({"error": "CRITICAL: GitHub Rate Limit Hit. Your Token is NOT working.", "debug": report["debug_info"]})
        elif resp.status_code == 404:
            return json.dumps({"error": "Repository Not Found (Check URL)", "debug": report["debug_info"]})
        elif resp.status_code != 200:
            return json.dumps({"error": f"API Error {resp.status_code}", "debug": report["debug_info"]})
        
        # SUCCESS HANDLING
        files = resp.json()
        file_names = [f['name'] for f in files]
        report["debug_info"]["files_found"] = file_names # Log what we see
        report["scan_status"] = "Success"
        
        for f in files:
            name = f['name']
            if name.lower() in ["requirements.txt", "package.json", "pipfile"]:
                report["critical_files_found"].append(name)
            
            if name.lower() == "requirements.txt":
                # Download the file content
                dl_url = f['download_url']
                file_resp = requests.get(dl_url, headers=headers, timeout=10)
                deps = [line.strip() for line in file_resp.text.split('\n') if line.strip() and not line.startswith('#')]
                report["dependencies"] = deps

    except Exception as e:
        return json.dumps({"error": f"Crash: {str(e)}"})

    return json.dumps(report, indent=2)
