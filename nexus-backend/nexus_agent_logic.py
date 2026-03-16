import os
import json
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
    id: str = Field(description="Generate a unique identifier like 'SEC-001' or 'CVE-2023-1234'.")
    title: str = Field(description="Write a concise, professional title (e.g., 'JWT Signature Verification Bypass').")
    severity: Literal["critical", "high", "medium", "low"] = Field(description="Select the appropriate strict severity level.")
    
    # THE FIX: Positive Commands only. Force the AI to explain it.
    analysis: str = Field(
        description="Explain the attack vector in 3 to 4 sentences. Start your explanation with 'This vulnerability occurs when...' and explain the worst-case scenario if exploited by an attacker."
    )
    poc: str = Field(description="Include the exact file path and line of code, or the vulnerable dependency version found in the raw logs.")
    
    # THE FIX: Force the AI to write the patch.
    remediation: str = Field(
        description="Write a step-by-step guide to fixing this. Provide the exact Python code rewrite or the exact 'pip install' terminal command required to patch the vulnerability."
    )

class SecurityReport(BaseModel):
    scan_status: str = Field(description="Set to 'Success' or 'Failed'.")
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


# ─── 3. SAST SCANNER (Local Regex Engine) ───
def run_sast(repo_path):
    if not repo_path:
        return "SAST Scan Failed: Repository not cloned."
    
    findings = []
    patterns = {
        "Disabled SSL Verification": r"verify\s*=\s*False",
        "Hardcoded Secret Key": r"SECRET_KEY\s*=\s*['\"][a-zA-Z0-9_]+['\"]",
        "Debug Mode Enabled": r"debug\s*=\s*True",
        "Exposed API Key": r"api_key\s*=\s*['\"][a-zA-Z0-9_\-]+['\"]",
        "JWT Signature Bypass": r"verify\s*=\s*False" # Catching the JWT flaw specifically
    }

    for root, dirs, files in os.walk(repo_path):
        if '.git' in dirs:
            dirs.remove('.git')
            
        for file in files:
            if file.endswith('.py') or file.endswith('.js') or file.endswith('.env'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        for i, line in enumerate(lines):
                            for vulnerability, regex in patterns.items():
                                if re.search(regex, line):
                                    relative_path = os.path.relpath(file_path, repo_path)
                                    findings.append(f"[{vulnerability}] Found in {relative_path} on line {i+1}: {line.strip()}")
                except Exception:
                    continue
                    
    return json.dumps(findings) if findings else "No SAST vulnerabilities found."


# ─── 4. SCA SCANNER (Local File Parsing - NO GITHUB API) ───
def run_sca(repo_path):
    """Scans the local cloned repository for dependency manifests."""
    if not repo_path:
        return json.dumps({"error": "SCA Scan Failed: Repository not cloned."})
        
    manifests_found = []
    
    for root, dirs, files in os.walk(repo_path):
        if '.git' in dirs:
            dirs.remove('.git')
            
        if "requirements.txt" in files:
            file_path = os.path.join(root, "requirements.txt")
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    # Read dependencies, ignoring comments and empty lines
                    deps = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                    rel_path = os.path.relpath(file_path, repo_path)
                    manifests_found.append({"manifest_file": rel_path, "dependencies": deps})
            except Exception as e:
                continue

    if not manifests_found:
        return json.dumps({"message": "No requirements.txt found in repository."})
        
    return json.dumps({"scan_status": "Success", "manifests": manifests_found}, indent=2)


# ─── 5. DETERMINISTIC AI ANALYSIS ENGINE (GEMINI) ───
def analyze_with_ai(sast_results, sca_results, repo_url):
    NEXUS_SYSTEM_PROMPT = """
    You are the core intelligence engine of Nexus, an elite, autonomous Senior AppSec Engineer.
    Your objective is to synthesize raw telemetry from our DevSecOps pipeline into a professional JSON report.

    You will receive raw logs from TWO distinct local scanners for the repository: {repo_url}
    1. SAST Scanner: Identifies static code flaws.
    2. SCA Scanner: Identifies dependencies from local requirements.txt files.

    YOUR DIRECTIVES:
    1. SYNTHESIS: You must deeply analyze BOTH logs. If the SCA scanner lists an outdated or vulnerable library (like PyYAML 3.x or Flask 0.x), you MUST create a vulnerability card for it.
    2. CONTEXT: Act as a security tutor. Explain exactly how a hacker would exploit the raw finding. 
    3. DEDUPLICATION: If 'verify=False' appears 4 times, group them into ONE single vulnerability card and list all affected lines in the 'poc' field. Do not repeat titles.
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
