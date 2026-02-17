import streamlit as st
import google.generativeai as genai
import nexus_agent_logic
import os

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Nexus DevSecOps Agent",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# --- 2. CUSTOM CSS (Dark, Sharp, Professional) ---
st.markdown("""
<style>
    /* IMPORT FONT */
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;800&family=Inter:wght@400;600&display=swap');

    /* BACKGROUND: Deep Cyber-Black Gradient */
    .stApp {
        background: radial-gradient(circle at center, #1e293b 0%, #020617 100%);
        background-attachment: fixed;
    }

    /* TYPOGRAPHY */
    h1, h2, h3, div, span, p {
        text-align: center;
        color: #ffffff !important;
    }

    /* 🛡️ CUSTOM LOGO STYLING */
    .logo-container {
        display: flex;
        justify-content: center;
        margin-bottom: 25px;
        margin-top: 20px;
    }
    
    .nexus-logo {
        width: 140px;
        height: 140px;
        background: linear-gradient(145deg, #0f172a, #334155);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 0 50px rgba(37, 99, 235, 0.5); /* Blue Glow */
        border: 2px solid #3b82f6;
        font-size: 70px;
        animation: pulse 3s infinite ease-in-out;
    }
    
    @keyframes pulse {
        0% { box-shadow: 0 0 30px rgba(37, 99, 235, 0.4); }
        50% { box-shadow: 0 0 60px rgba(37, 99, 235, 0.7); }
        100% { box-shadow: 0 0 30px rgba(37, 99, 235, 0.4); }
    }

    /* TITLE STYLING */
    .agent-title {
        font-family: 'Orbitron', sans-serif !important;
        font-size: 3.5rem;
        font-weight: 800;
        letter-spacing: 2px;
        background: linear-gradient(90deg, #ffffff, #94a3b8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 5px;
        text-transform: uppercase;
    }

    .agent-subtitle {
        font-family: 'Inter', sans-serif !important;
        font-size: 1.1rem;
        color: #94a3b8 !important;
        letter-spacing: 3px;
        margin-bottom: 40px;
        text-transform: uppercase;
    }

    /* INPUT FIELD (Transparent & Clean) */
    .stTextInput > div > div > input {
        background-color: rgba(15, 23, 42, 0.8); /* Dark Blue-Black */
        border: 2px solid #334155;
        color: #e2e8f0 !important;
        border-radius: 12px;
        padding: 25px 20px; /* Taller input */
        font-size: 18px;
        text-align: center;
        transition: border-color 0.3s;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #3b82f6; /* Blue border on click */
        box-shadow: 0 0 20px rgba(59, 130, 246, 0.3);
    }

    /* BUTTON (Bright Blue - Fixed Visibility) */
    .stButton > button {
        width: 100%;
        background: linear-gradient(90deg, #2563eb 0%, #06b6d4 100%);
        color: white !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 700;
        border-radius: 12px;
        padding: 15px 30px;
        border: none;
        margin-top: 15px;
        letter-spacing: 1px;
        box-shadow: 0 10px 25px rgba(6, 182, 212, 0.4); /* Glow effect */
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: translateY(-3px);
        box-shadow: 0 15px 35px rgba(6, 182, 212, 0.6);
    }
    
    /* HIDE DEFAULT UI */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

</style>
""", unsafe_allow_html=True)

# --- 3. UI LAYOUT ---

# 🛡️ LOGO SECTION
st.markdown("""
<div class="logo-container">
    <div class="nexus-logo">
        🛡️
    </div>
</div>
""", unsafe_allow_html=True)

# TEXT SECTION
st.markdown('<h1 class="agent-title">NEXUS AGENT</h1>', unsafe_allow_html=True)
st.markdown('<div class="agent-subtitle">Autonomous DevSecOps Auditor • Built by Ganesh</div>', unsafe_allow_html=True)

# INPUT FORM
with st.form("scan_form"):
    repo_url = st.text_input("TARGET REPOSITORY URL", placeholder="https://github.com/owner/repo")
    st.write("") # Spacer
    
    # Centered Button
    c1, c2, c3 = st.columns([1, 4, 1]) # Wider button column
    with c2:
        scan_btn = st.form_submit_button("🚀 INITIATE SECURITY SCAN")

# --- 4. SECRETS & SETUP ---
api_key = None
if "GEMINI_API_KEY" in st.secrets:
    api_key = st.secrets["GEMINI_API_KEY"]
if "GITHUB_TOKEN" in st.secrets:
    os.environ["GITHUB_TOKEN"] = st.secrets["GITHUB_TOKEN"]

if api_key:
    genai.configure(api_key=api_key)

# --- 5. EXECUTION LOGIC ---
if scan_btn and repo_url:
    if not api_key:
        st.error("❌ API Key Error: Please check Streamlit Secrets.")
        st.stop()
        
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Status Container
    with st.status("⚙️ **NEXUS CORE ACTIVE**", expanded=True) as status:
        
        st.write("📡 Scanning Repository Manifest...")
        scan_data = nexus_agent_logic.scan_repo_manifest(repo_url)
        
        # DEBUG (Hidden)
        with st.expander("Show Diagnostic Data", expanded=False):
            st.code(scan_data, language='json')
            
        st.write("🛡️ Cross-referencing CVE Database...")
        
        # STEP 2: AI ANALYSIS (Smart Fallback System)
        try:
            # 1. Try FLASH first (Fastest)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = f"""
            You are Nexus, a DevSecOps AI.
            Analyze this repository scan: {scan_data}
            
            Task:
            1. Identify critical vulnerabilities.
            2. Explain the risk (RCE, XSS, etc.).
            3. Provide remediation commands.
            4. Output a professional HTML report using Tailwind CSS. 
            5. Design the report to be clean, white, and corporate.
            """
            
            response = model.generate_content(prompt)
            report_html = response.text
            
            if "```html" in report_html:
                report_html = report_html.replace("```html", "").replace("```", "")
            
            status.update(label="✅ **AUDIT COMPLETE**", state="complete", expanded=False)
            
        except Exception:
            # 2. Fallback to PRO (Most Compatible) if Flash fails (404)
            try:
                model = genai.GenerativeModel('gemini-pro')
                response = model.generate_content(prompt)
                report_html = response.text
                if "```html" in report_html:
                    report_html = report_html.replace("```html", "").replace("```", "")
                status.update(label="✅ **AUDIT COMPLETE**", state="complete", expanded=False)
            except Exception as e:
                st.error(f"AI Engine Error: {e}")
                st.stop()

    # DISPLAY REPORT
    st.markdown("### 📊 VULNERABILITY REPORT")
    st.components.v1.html(report_html, height=800, scrolling=True)
