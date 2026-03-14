import requests
import json
import os

def scan_repo_manifest(repo_url):
    """
    Nexus Agent Tool: Smart Deep Scan
    """
    # 1. Clean URL
    try:
        clean_url = repo_url.rstrip("/").rstrip(".git").split("github.com/")[-1]
    except:
        return json.dumps({"error": "Invalid URL format."})

    api_base = f"https://api.github.com/repos/{clean_url}/contents"
    
    # 2. Setup Auth
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get('GITHUB_TOKEN')
    
    if token:
        headers['Authorization'] = f"token {token}"
    else:
        try:
            import streamlit as st
            if "GITHUB_TOKEN" in st.secrets:
                headers['Authorization'] = f"token {st.secrets['GITHUB_TOKEN']}"
        except:
            pass

    report = {
        "target": clean_url,
        "critical_files_found": [],
        "dependencies": [],
        "scan_status": "Success", 
        "debug_log": [] # To help us track where it looked
    }

    def fetch_file_content(download_url):
        try:
            resp = requests.get(download_url, headers=headers, timeout=10)
            return [line.strip() for line in resp.text.split('\n') if line.strip() and not line.startswith('#')]
        except:
            return []

    try:
        # PHASE 1: Scan Root Directory
        resp = requests.get(api_base, headers=headers, timeout=10)
        if resp.status_code != 200:
            return json.dumps({"error": f"GitHub API Error: {resp.status_code}"})
        
        root_files = resp.json()
        report["debug_log"].append(f"Scanned Root: Found {len(root_files)} files")
        
        # Check for manifest in root
        found_manifest = False
        for f in root_files:
            if f['name'] == "requirements.txt":
                report["critical_files_found"].append("requirements.txt (Root)")
                report["dependencies"] = fetch_file_content(f['download_url'])
                found_manifest = True
                break
        
        # PHASE 2: Deep Scan (If not found in root)
        if not found_manifest:
            report["debug_log"].append("Manifest not found in root. Scanning subfolders...")
            
            # Look for folders like 'app', 'src', 'backend'
            subfolders = [f for f in root_files if f['type'] == 'dir']
            
            for folder in subfolders:
                # Construct URL for subfolder content
                folder_url = f"{api_base}/{folder['name']}"
                sub_resp = requests.get(folder_url, headers=headers, timeout=10)
                
                if sub_resp.status_code == 200:
                    sub_files = sub_resp.json()
                    # Look for requirements.txt inside this folder
                    for sub_f in sub_files:
                        if sub_f['name'] == "requirements.txt":
                            report["critical_files_found"].append(f"requirements.txt ({folder['name']}/)")
                            report["dependencies"] = fetch_file_content(sub_f['download_url'])
                            found_manifest = True
                            break
                
                if found_manifest:
                    break

    except Exception as e:
        return json.dumps({"error": f"Crash: {str(e)}"})

    return json.dumps(report, indent=2)
