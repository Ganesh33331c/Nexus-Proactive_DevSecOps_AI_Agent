import streamlit as st
import google.generativeai as genai
import nexus_agent_logic
import os
import re
import json
import tempfile
import shutil
import time
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

# --- 2. CUSTOM CSS ---
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
    .logo-container { display: flex; justify-content: center; margin-bottom: 20px; }
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
    @keyframes float { 0% { transform: translateY(0px); } 50% { transform: translateY(-10px); } 100% { transform: translateY(0px); } }
    .stTextArea > div > div > textarea {
        background-color: #ffffff !important;
        border: 2px solid #e2e8f0;
        color: #000000 !important;
        font-weight: 600;
        border-radius: 12px;
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

# --- 3. TOOLS ---

def find_python_root(start_path):
    for dirpath, _, filenames in os.walk(start_path):
        if any(f.endswith(".py") for f in filenames):
            return dirpath
    return start_path

def scan_code_for_patterns(base_dir):
    actual_path = find_python_root(base_dir)
    findings = [f"[DEBUG] Scanning directory: {actual_path}"]
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

    temp_dir = None
    try:
        with st.status("⚙️ **NEXUS CORE ACTIVE**", expanded=True) as status:
            # 1. CLONE
            st.write("📂 Cloning repository into unique workspace...")
            temp_dir = tempfile.mkdtemp()
            Repo.clone_from(repo_url, temp_dir)
            cloned_path = os.path.abspath(temp_dir)

            # 2. SAST
            st.write(f"🔬 Analyzing source code in {cloned_path}...")
            sast_results = scan_code_for_patterns(cloned_path)
            
            # 3. SCA
            st.write("📡 Scanning dependencies...")
            sca_data = nexus_agent_logic.scan_repo_manifest(repo_url)
            
            scan_data = {"cloned_path": cloned_path, "sast": sast_results, "sca": sca_data}
            
            # --- INTELLIGENT MODEL SELECTOR ---
            st.write("🛡️ Determining compatible AI model...")
            all_models = list(genai.list_models())
            available_models = [m.name for m in all_models if 'generateContent' in m.supported_generation_methods]
            
            # PRIORITY LIST: Flash is faster and has higher limits
            priority_models = ["models/gemini-1.5-flash", "models/gemini-1.5-flash-8b", "models/gemini-1.0-pro"]
            best_model = available_models[0]
            for p in priority_models:
                if p in available_models:
                    best_model = p
                    break
            
            model = genai.GenerativeModel(best_model)
            prompt = f"Analyze this repository scan: {scan_data}\n\nMANDATORY PROTOCOL:\n1. Use 'cloned_path'.\n2. Verbatim report all [CRITICAL] findings.\n3. Create a dark terminal 'Code Evidence' section in HTML.\nOutput professional Tailwind CSS HTML."
            
            # --- RETRY LOGIC FOR QUOTA ---
            response = None
            max_retries = 3
            for i in range(max_retries):
                try:
                    response = model.generate_content(prompt)
                    break
                except Exception as e:
                    if "429" in str(e) and i < max_retries - 1:
                        st.warning(f"⚠️ Quota hit. Waiting 30s to retry... (Attempt {i+1}/{max_retries})")
                        time.sleep(31)
                    else:
                        raise e

            if response:
                report_html = response.text.replace("```html", "").replace("```", "")
                status.update(label=f"✅ AUDIT COMPLETE ({best_model})", state="complete", expanded=False)
                st.components.v1.html(report_html, height=800, scrolling=True)
                st.download_button("📥 Download Report", data=report_html, file_name="Nexus_Audit.html", mime="text/html")
            
    except Exception as e:
        st.error(f"❌ Error during scan: {e}")
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
