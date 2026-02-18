import streamlit as st
import google.generativeai as genai
import nexus_agent_logic
import os
import re
import json
import tempfile
from git import Repo
import importlib.metadata
from datetime import datetime

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Nexus DevSecOps Agent",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# --- 2. CUSTOM CSS (Professional UI & Visible Text) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&display=swap');

    .stApp {
        background: linear-gradient(-45deg, #ee7752, #e73c7e, #23a6d5, #23d5ab);
        background-size: 400% 400%;
        animation: gradient 15s ease infinite;
    }
    
    @keyframes gradient {
        0% {background-position: 0% 50%;}
        50% {background-position: 100% 50%;}
        100% {background-position: 0% 50%;}
    }

    h1, h2, h3, p, div, span {
        font-family: 'Outfit', sans-serif !important;
        color: #ffffff !important;
        text-align: center;
        text-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .logo-container {
        display: flex;
        justify-content: center;
        margin-bottom: 20px;
    }
    
    .nexus-logo {
        width: 140px; height: 140px;
        background: rgba(255, 255, 255, 0.2);
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.3);
        backdrop-filter: blur(10px);
        border: 2px solid rgba(255, 255, 255, 0.5);
        font-size: 70px;
        animation: float 6s ease-in-out infinite;
    }
    
    @keyframes float {
        0% { transform: translateY(0px); }
        50% { transform: translateY(-10px); }
        100% { transform: translateY(0px); }
    }

    .stTextArea > div > div > textarea {
        background-color: #ffffff !important;
        border: 2px solid #e2e8f0;
        color: #000000 !important;
        font-weight: 600;
        border-radius: 12px;
        padding: 15px;
    }

    .stButton > button {
        width: 100%;
        background: linear-gradient(90deg, #4f46e5 0%, #7c3aed 100%);
        color: white !important;
        font-weight: 800;
        border-radius: 12px;
        padding: 15px 30px;
        border: none;
        cursor: pointer !important;
    }
    
    #MainMenu, footer, header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# --- 3. ROBUST CLONE & SCAN TOOLS ---

def clone_repository(repo_url):
    """Clones a repo into a unique temp directory and returns the absolute path."""
    try:
        target_dir = tempfile.mkdtemp() #
        Repo.clone_from(repo_url, target_dir)
        return os.path.abspath(target_dir) #
    except Exception as e:
        return f"Error: Failed to clone repository. {str(e)}"

def find_python_root(start_path):
    """Recursively finds the first folder containing .py files."""
    for dirpath, _, filenames in os.walk(start_path):
        if any(f.endswith(".py") for f in filenames):
            return dirpath
    return start_path

def scan_code_for_patterns(base_dir):
    """Path-intelligent recursive Regex scan using dynamic base_dir."""
    actual_path = find_python_root(base_dir)
    findings = [f"[DEBUG] Scanning directory: {actual_path}"] #

    patterns = {
        r'yaml\.load\(': "RCE Risk (Unsafe Deserialization)",
        r'pickle\.load\(': "RCE Risk (Unsafe Deserialization)",
        r'eval\(': "Arbitrary Code Execution",
        r'exec\(': "Arbitrary Code Execution",
        r'os\.system\(': "Command Injection",
        r'subprocess\.Popen.*shell=True': "Command Injection",
        r'(?i)(api_key|secret_key|password|token)\s*=\s*[\'"][a-zA-Z0-9_\-]{16,}[\'"]': "Hardcoded Secret",
        r'app\.run\(.*debug=True': "Flask Debug Enabled"
    }

    if not os.path.exists(actual_path):
        return "[DEBUG] Directory not found."

    for dirpath, _, filenames in os.walk(actual_path):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if filename.startswith('.') or filename.lower().endswith(('.png', '.pyc')):
                continue
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f):
                        for pattern, risk in patterns.items():
                            if re.search(pattern, line):
                                rel_path = os.path.relpath(filepath, base_dir)
                                findings.append(f"[CRITICAL] Found '{risk}' in {rel_path} at line {i+1}: \"{line.strip()[:100]}\"")
            except: continue

    return "\n".join(findings) if len(findings) > 1 else "SAFE: No critical patterns found."

# --- 4. UI LAYOUT ---
st.markdown('<div class="logo-container"><div class="nexus-logo">🛡️</div></div>', unsafe_allow_html=True)
st.markdown('<h1 class="agent-title">NEXUS AGENT</h1>', unsafe_allow_html=True)

with st.form(key="nexus_input_form"):
    repo_url = st.text_area("Target Repository URL", height=100, placeholder="Paste GitHub URL here...", label_visibility="collapsed")
    scan_btn = st.form_submit_button("🚀 LAUNCH AUDIT")

# --- 5. EXECUTION LOGIC ---
if scan_btn and repo_url:
    api_key = st.secrets.get("GEMINI_API_KEY")
    if not api_key: st.error("❌ API Key Missing"); st.stop()
    genai.configure(api_key=api_key)

    with st.status("⚙️ **NEXUS CORE ACTIVE**", expanded=True) as status:
        # Step 1: Clone
        st.write("📂 Cloning repository into unique workspace...")
        cloned_path = clone_repository(repo_url)
        
        if cloned_path.startswith("Error:"):
            st.error(cloned_path); st.stop()

        # Step 2: SAST
        st.write(f"🔬 Analyzing source code in {cloned_path}...")
        sast_results = scan_code_for_patterns(cloned_path)
        
        # Step 3: SCA (Manifest)
        st.write("📡 Scanning dependencies...")
        sca_data = nexus_agent_logic.scan_repo_manifest(repo_url)
        
        # Combine data for AI
        scan_data = {"cloned_path": cloned_path, "sast": sast_results, "sca": sca_data}
        
        # AI Analysis
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            prompt = f"""
            Analyze this repository: {scan_data}
            MANDATORY PROTOCOL:
            1. Use the absolute path provided in 'cloned_path'. Do not guess.
            2. Verbatim report all [CRITICAL] findings from 'sast'.
            3. Create a dark terminal 'Code Evidence' section in the HTML.
            Output a professional Tailwind CSS HTML report.
            """
            response = model.generate_content(prompt)
            report_html = response.text.replace("```html", "").replace("```", "")
            
            status.update(label="✅ AUDIT COMPLETE", state="complete", expanded=False)
            st.components.v1.html(report_html, height=800, scrolling=True)
            st.download_button("📥 Download Report", data=report_html, file_name="Nexus_Audit.html", mime="text/html")
        except Exception as e: st.error(f"AI Failure: {e}")
