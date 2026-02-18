import streamlit as st
import google.generativeai as genai
import nexus_agent_logic
import os
import ast
import json
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

    /* ANIMATED BACKGROUND */
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

    /* TEXT STYLES */
    h1, h2, h3, p, div, span {
        font-family: 'Outfit', sans-serif !important;
        color: #ffffff !important;
        text-align: center;
        text-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    /* LOGO */
    .logo-container {
        display: flex;
        justify-content: center;
        margin-bottom: 20px;
    }
    
    .nexus-logo {
        width: 140px;
        height: 140px;
        background: rgba(255, 255, 255, 0.2);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
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

    /* TITLE */
    .agent-title {
        font-size: 3.5rem;
        font-weight: 800;
        margin-bottom: 0px;
        letter-spacing: 1px;
    }

    .agent-subtitle {
        font-size: 1.2rem;
        font-weight: 600;
        opacity: 0.95;
        margin-bottom: 40px;
        text-transform: uppercase;
        letter-spacing: 2px;
    }

    /* --- ENHANCED INPUT FIELD (Text Area) --- */
    /* FIX: Force Dark Text on White Background */
    .stTextArea > div > div > textarea {
        background-color: #ffffff !important; /* Solid White */
        border: 2px solid #e2e8f0;
        color: #000000 !important; /* PURE BLACK TEXT */
        caret-color: #000000; /* Black blinking cursor */
        font-weight: 600;
        border-radius: 12px;
        padding: 15px;
        font-size: 16px;
        box-shadow: 0 4px 10px rgba(0,0,0,0.1);
    }
    
    .stTextArea > div > div > textarea:focus {
        border-color: #2563eb;
        box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.2);
    }

    /* SUBMIT BUTTON */
    .stButton > button {
        width: 100%;
        background: linear-gradient(90deg, #4f46e5 0%, #7c3aed 100%);
        color: white !important;
        font-weight: 800;
        border-radius: 12px;
        padding: 15px 30px;
        border: none;
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        transition: all 0.3s ease;
        font-size: 1.1rem;
        cursor: pointer !important;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(124, 58, 237, 0.4);
    }
    
    /* UI CLEANUP */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
</style>
""", unsafe_allow_html=True)

# --- 3. SAST TOOLS ---

def list_all_python_files(root_dir):
    """Recursively finds all .py files in the directory tree."""
    python_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for file in filenames:
            if file.endswith(".py"):
                full_path = os.path.join(dirpath, file)
                python_files.append(full_path)
    return python_files

def read_code_file(filepath, base_dir=None):
    """Safely reads file content (first 300 lines) for analysis."""
    if base_dir is None:
        base_dir = os.getcwd()
    
    abs_base = os.path.abspath(base_dir)
    abs_target = os.path.abspath(filepath)
    
    if not os.path.exists(abs_target):
        return f"# Error: File {filepath} not found."

    content = []
    MAX_LINES = 300
    try:
        with open(abs_target, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= MAX_LINES:
                    content.append(f"\n# ... [TRUNCATED after {MAX_LINES} lines] ...")
                    break
                content.append(line)
        return "".join(content)
    except Exception as e:
        return f"# Error reading file: {e}"

def scan_code_for_patterns(filepath, library_name):
    """Scans Python code using AST to find dangerous function calls."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.splitlines()
    except:
        return ""

    findings = []
    try:
        tree = ast.parse(content)
        
        class SecurityVisitor(ast.NodeVisitor):
            def visit_Call(self, node):
                msg = None
                # Check 1: PyYAML
                if library_name.lower() == 'pyyaml':
                    if isinstance(node.func, ast.Attribute) and node.func.attr == 'load':
                         if isinstance(node.func.value, ast.Name) and node.func.value.id == 'yaml':
                             msg = "Unsafe yaml.load() detected. RCE Risk."

                # Check 2: Pickle
                elif library_name.lower() == 'pickle':
                    if isinstance(node.func, ast.Attribute) and node.func.attr in ['load', 'loads']:
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'pickle':
                             msg = "Insecure pickle deserialization detected."

                # Check 3: Subprocess/OS
                elif library_name.lower() in ['subprocess', 'os']:
                    for keyword in node.keywords:
                        if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            msg = "shell=True detected. Command Injection Risk."

                if msg:
                    line_no = node.lineno
                    code_snippet = lines[line_no-1].strip()
                    findings.append(f"Line {line_no}: {msg}\n   Code: `{code_snippet}`")
                
                self.generic_visit(node)
        
        SecurityVisitor().visit(tree)
    except:
        pass 
    
    if findings:
        return "\n".join(findings)
    return ""

# --- 4. UI LAYOUT ---

st.markdown("""
<div class="logo-container">
    <div class="nexus-logo">
        🛡️
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown('<h1 class="agent-title">NEXUS DEVSECOPS AGENT</h1>', unsafe_allow_html=True)
st.markdown('<div class="agent-subtitle">Autonomous SAST & SCA Auditor • Built by Ganesh</div>', unsafe_allow_html=True)

# --- INPUT FORM ---
with st.form(key="nexus_input_form"):
    repo_url = st.text_area(
        "Target Repository URL", 
        height=100,
        placeholder="Paste GitHub URL (e.g., https://github.com/owner/repo) or error logs here...",
        label_visibility="collapsed"
    )
    
    st.write("") 
    
    c1, c2 = st.columns([4, 1])
    with c2:
        scan_btn = st.form_submit_button("🚀 LAUNCH")

# --- 5. SECRETS & SETUP ---
api_key = None
if "GEMINI_API_KEY" in st.secrets:
    api_key = st.secrets["GEMINI_API_KEY"]
if "GITHUB_TOKEN" in st.secrets:
    os.environ["GITHUB_TOKEN"] = st.secrets["GITHUB_TOKEN"]

if api_key:
    genai.configure(api_key=api_key)

# --- 6. EXECUTION LOGIC ---
if scan_btn and repo_url:
    if not api_key:
        st.error("❌ API Key Error: Please check Streamlit Secrets.")
        st.stop()
        
    st.markdown("<br>", unsafe_allow_html=True)
    
    with st.status("⚙️ **NEXUS CORE ACTIVE**", expanded=True) as status:
        
        try:
            lib_ver = importlib.metadata.version("google-generativeai")
            st.write(f"ℹ️ Library Version: {lib_ver}")
        except:
            st.write("ℹ️ Library Version: Unknown")
            
        st.write("📡 Scanning Repository Manifest...")
        
        raw_scan_output = nexus_agent_logic.scan_repo_manifest(repo_url)
        
        # Convert to Dict
        if isinstance(raw_scan_output, str):
            try:
                scan_data = json.loads(raw_scan_output)
            except json.JSONDecodeError:
                scan_data = {"raw_scan_output": raw_scan_output}
        elif isinstance(raw_scan_output, dict):
            scan_data = raw_scan_output
        else:
            scan_data = {"error": "Unknown scan output format"}

        # --- SAST LOGIC ---
        st.write("🔬 Performing Recursive Static Code Analysis (SAST)...")
        sast_findings = ""
        
        # NOTE: nexus_agent_logic MUST clone repo to 'repo_clone' for this to work
        if os.path.exists("repo_clone"): 
            all_py_files = list_all_python_files("repo_clone")
            st.write(f"ℹ️ Analyzing {len(all_py_files)} Python files...")
            
            for full_path in all_py_files:
                rel_path = os.path.relpath(full_path, "repo_clone")
                
                # Check patterns
                for lib in ["PyYAML", "pickle", "subprocess"]:
                    patterns = scan_code_for_patterns(full_path, lib)
                    if patterns:
                        sast_findings += f"\nFile: {rel_path}\n{patterns}\n"

        if sast_findings:
            scan_data["sast_analysis"] = sast_findings
        else:
            scan_data["sast_analysis"] = "No critical static patterns found."

        
        with st.expander("Show Diagnostic Data", expanded=False):
            st.code(json.dumps(scan_data, indent=2), language='json')
            
        st.write("🛡️ Cross-referencing CVE Database...")
        
        # --- MODEL FINDER ---
        response = None
        used_model = "Unknown"
        
        try:
            all_models = list(genai.list_models())
            available_models = [m.name for m in all_models if 'generateContent' in m.supported_generation_methods]
            
            if not available_models:
                st.error("❌ Critical: Your API Key has NO access to any text models.")
                st.stop()
                
            if any('flash' in m for m in available_models):
                used_model = next(m for m in available_models if 'flash' in m)
            elif any('pro' in m for m in available_models):
                used_model = next(m for m in available_models if 'pro' in m)
            else:
                used_model = available_models[0]
            
            model = genai.GenerativeModel(used_model)
            
            prompt = f"""
            You are Nexus, a DevSecOps AI.
            Analyze this repository scan: {scan_data}
            
            Task:
            1. Identify critical vulnerabilities (dependencies AND code patterns).
            2. Explain the risk (RCE, XSS, etc.).
            3. Provide remediation.
            4. Output a professional HTML report using Tailwind CSS. 
            5. IMPORTANT: Include a "Code Evidence" section in the HTML if 'sast_analysis' contains data.
            6. Design the report to be clean, white, and corporate.
            """
            
            response = model.generate_content(prompt)
        
        except Exception as e:
            st.error(f"❌ API Connection Failed: {e}")
            st.stop()
        
        if response:
            report_html = response.text
            if "```html" in report_html:
                report_html = report_html.replace("```html", "").replace("```", "")
            
            status.update(label=f"✅ **AUDIT COMPLETE (Model: {used_model})**", state="complete", expanded=False)
            
            # DISPLAY REPORT
            st.markdown("### 📊 VULNERABILITY REPORT")
            st.components.v1.html(report_html, height=800, scrolling=True)
            
            # --- HTML DOWNLOAD ---
            st.markdown("---")
            col_dl1, col_dl2 = st.columns([3, 2])
            with col_dl2:
                st.download_button(
                    label="📥 Download Full Report (.html)",
                    data=report_html,
                    file_name=f"Nexus_Audit_Report_{datetime.now().strftime('%Y%m%d')}.html",
                    mime="text/html",
                    help="Download the report with full visual formatting (colors, layout)."
                )
