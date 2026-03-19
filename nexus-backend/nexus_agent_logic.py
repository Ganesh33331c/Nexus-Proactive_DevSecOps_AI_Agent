import os
import json
import requests
import tempfile
import shutil
import re
from git import Repo

# --- LANGCHAIN & PYDANTIC IMPORTS (GOOGLE GEMINI) ---
from pydantic import BaseModel, Field
from typing import List, Literal
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI

# ─── 1. STRICT JSON SCHEMAS (PYDANTIC) ───
class Vulnerability(BaseModel):
    id: str = Field(description="A unique identifier (e.g., 'SEC-001', 'CVE-2023-1234').")
    title: str = Field(description="A concise, professional title for the vulnerability.")
    severity: Literal["critical", "high", "medium", "low"] = Field(description="The strict severity level.")
    analysis: str = Field(
        description="Write a detailed, 3-4 sentence explanation of the vulnerability. Explain why it is a security risk. Placeholders are strictly forbidden."
    )
    poc: str = Field(description="The exact file path, line of code, or dependency version that triggered the finding.")
    remediation: str = Field(
        description="Provide exact, actionable patch instructions (code changes, terminal commands, or version bumps). Vague advice is forbidden."
    )

class SecurityReport(BaseModel):
    scan_status: str = Field(description="Overall status (e.g., 'Completed - Action Required').")
    critical_count: int = Field(description="Total number of critical vulnerabilities found.")
    high_count: int = Field(description="Total number of high vulnerabilities found.")
    medium_count: int = Field(description="Total number of medium vulnerabilities found.")
    vulnerabilities: List[Vulnerability] = Field(description="The comprehensive list of all synthesized SAST and SCA findings.")


# ─── 2. REPOSITORY CLONING ───
def clone_repository(repo_url):
    temp_dir = tempfile.mkdtemp()
    try:
        Repo.clone_from(repo_url, temp_dir)
        return temp_dir
    except Exception as e:
        return None

def cleanup(repo_path):
    if repo_path and os.path.exists(repo_path):
        shutil.rmtree(repo_path, ignore_errors=True)


# ─── 3. SAST SCANNER (Regex Engine) ───
def run_sast(repo_path):
    if not repo_path:
        return "SAST Scan Failed: Repository not cloned."
    
    findings = []
    patterns = {
        "Disabled SSL Verification": r"verify\s*=\s*False",
        "Hardcoded Secret Key": r"SECRET_KEY\s*=\s*['\"][a-zA-Z0-9_]+['\"]",
        "Debug Mode Enabled": r"debug\s*=\s*True",
        "Exposed API Key": r"api_key\s*=\s*['\"][a-zA-Z0-9_\-]+['\"]"
    }

    for root, dirs, files in os.walk(repo_path):
        if '.git' in dirs:
            dirs.remove('.git')
            
        for file in files:
            if file.endswith('.py') or file.endswith('.js') or file.endswith('.env'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        for i, line in enumerate(lines):
                            for vulnerability, regex in patterns.items():
                                if re.search(regex, line):
                                    relative_path = os.path.relpath(file_path, repo_path)
                                    findings.append(f"[{vulnerability}] Found in {relative_path} on line {i+1}: {line.strip()}")
                except Exception:
                    continue
                    
    return json.dumps(findings) if findings else "No SAST vulnerabilities found."


# ─── 4. SCA SCANNER (Deep Scan via GitHub API) ───
def run_sca(repo_url):
    try:
        clean_url = repo_url.rstrip("/").rstrip(".git").split("github.com/")[-1]
    except:
        return json.dumps({"error": "Invalid URL format."})

    api_base = f"https://api.github.com/repos/{clean_url}/contents"
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get('GITHUB_TOKEN')
    
    if token:
        headers['Authorization'] = f"token {token}"

    report = {
        "target": clean_url,
        "critical_files_found": [],
        "dependencies": [],
        "scan_status": "Success", 
        "debug_log": [] 
    }

    def fetch_file_content(download_url):
        try:
            resp = requests.get(download_url, headers=headers, timeout=10)
            return [line.strip() for line in resp.text.split('\n') if line.strip() and not line.startswith('#')]
        except:
            return []

    try:
        resp = requests.get(api_base, headers=headers, timeout=10)
        if resp.status_code != 200:
            return json.dumps({"error": f"GitHub API Error: {resp.status_code}"})
        
        root_files = resp.json()
        
        found_manifest = False
        for f in root_files:
            if f['name'] == "requirements.txt":
                report["critical_files_found"].append("requirements.txt (Root)")
                report["dependencies"] = fetch_file_content(f['download_url'])
                found_manifest = True
                break
        
        if not found_manifest:
            subfolders = [f for f in root_files if f['type'] == 'dir']
            for folder in subfolders:
                folder_url = f"{api_base}/{folder['name']}"
                sub_resp = requests.get(folder_url, headers=headers, timeout=10)
                if sub_resp.status_code == 200:
                    sub_files = sub_resp.json()
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


# ─── 5. DETERMINISTIC AI ANALYSIS ENGINE (GEMINI) ───
def analyze_with_ai(sast_results, sca_results, repo_url):
    NEXUS_SYSTEM_PROMPT = """
    You are the core intelligence engine of Nexus, an elite, autonomous Senior AppSec Engineer.
    Your objective is to synthesize raw telemetry from our DevSecOps pipeline into a professional, actionable JSON report.

    You will receive raw logs from TWO distinct scanners for the repository: {repo_url}
    1. SAST Scanner: Identifies static code flaws, hardcoded secrets, and injection risks.
    2. SCA Scanner: Identifies outdated, vulnerable, or End-of-Life (EOL) dependencies.

    YOUR DIRECTIVES:
    - Synthesize both inputs. If the SCA scanner finds an outdated library, and the SAST scanner finds a flaw caused by it, correlate them.
    - DO NOT drop SCA dependency findings. Every vulnerable package must be documented.
    - Write deep, contextual analysis. Explain the 'Why'.
    - Provide exact remediation steps. Explain the 'How'.
    - Never use placeholder text like "No description provided".
    - Combine identical SAST findings (e.g., if 'verify=False' appears 4 times, make it ONE vulnerability card and list the 4 lines in the POC).
    """

    prompt_template = ChatPromptTemplate.from_messages([
        ("system", NEXUS_SYSTEM_PROMPT),
        ("human", "=== SAST RAW LOGS ===\n{sast_raw}\n\n=== SCA RAW LOGS ===\n{sca_raw}")
    ])

    # Initialize Gemini with maximum determinism (Temperature = 0.0)
    llm = ChatGoogleGenerativeAI(
        model="gemini-1.5-flash",
        temperature=0.0,
        google_api_key=os.environ.get("GEMINI_API_KEY")
    )
    
    # Bind the Pydantic schema to the LLM
    structured_llm = llm.with_structured_output(SecurityReport)
    
    chain = prompt_template | structured_llm
    
    try:
        report_obj: SecurityReport = chain.invoke({
            "repo_url": repo_url,
            "sast_raw": sast_results,
            "sca_raw": sca_results
        })
        return report_obj.model_dump()
        
    except Exception as e:
        print(f"Nexus AI Engine Error: {e}")
        return {
            "scan_status": "Failed - Parsing Error",
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "vulnerabilities": []
        }
