import streamlit as st
import google.generativeai as genai
import nexus_agent_logic
import os
import importlib.metadata

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Nexus DevSecOps Agent",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# --- 2. CUSTOM CSS (Cursor Fix + Professional UI) ---
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

    /* INPUT FIELD */
    .stTextInput > div > div > input {
        background-color: #ffffff !important;
        border: 2px solid #e2e8f0;
        color: #0f172a !important;
        font-weight: 500;
        border-radius: 12px;
        padding: 15px 20px;
        font-size: 16px;
        text-align: left;
        box-shadow: 0 4px 10px rgba(0,0,0,0.1);
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #2563eb;
        box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.2);
    }

    /* SUBMIT BUTTON (Cursor Fix) */
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
        margin-top: 5px;
        cursor: pointer !important; /* Forces the "Hand" cursor */
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

# --- 3. UI LAYOUT ---

st.markdown("""
<div class="logo-container">
    <div class="nexus-logo">
        🛡️
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown('<h1 class="agent-title">NEXUS DEVSECOPS AGENT</h1>', unsafe_allow_html=True)
st.markdown('<div class="agent-subtitle">Autonomous Security Auditor • Built by Ganesh</div>', unsafe_allow_html=True)

with st.form("scan_form"):
    repo_url = st.text_input("Target Repository URL", placeholder="https://github.com/owner/repo")
    st.write("") 
    
    c1, c2, c3 = st.columns([1, 4, 1])
    with c2:
        scan_btn = st.form_submit_button("🚀 LAUNCH AUDIT")

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
    
    with st.status("⚙️ **NEXUS CORE ACTIVE**", expanded=True) as status:
        
        # VERSION CHECK
        try:
            lib_ver = importlib.metadata.version("google-generativeai")
            st.write(f"ℹ️ Library Version: {lib_ver}")
        except:
            st.write("ℹ️ Library Version: Unknown")
            
        st.write("📡 Scanning Repository Manifest...")
        scan_data = nexus_agent_logic.scan_repo_manifest(repo_url)
        
        with st.expander("Show Diagnostic Data", expanded=False):
            st.code(scan_data, language='json')
            
        st.write("🛡️ Cross-referencing CVE Database...")
        
        # --- 🔍 DEBUGGER MODEL SELECTOR ---
        response = None
        used_model = None
        error_log = [] # Capture actual errors
        
        models_to_try = [
            'gemini-1.5-flash',
            'gemini-pro',
            'gemini-1.5-pro-latest'
        ]
        
        for m_name in models_to_try:
            try:
                model = genai.GenerativeModel(m_name)
                prompt = f"Analyze this scan and list vulnerabilities: {scan_data}"
                response = model.generate_content(prompt)
                used_model = m_name
                break 
            except Exception as e:
                error_log.append(f"{m_name} failed: {str(e)}") # LOG THE REAL ERROR
                continue 
        
        if response:
            # IT WORKED! Generate the full report now
            try:
                full_prompt = f"""
                You are Nexus, a DevSecOps AI.
                Analyze this repository scan: {scan_data}
                
                Task:
                1. Identify critical vulnerabilities.
                2. Explain the risk.
                3. Provide remediation.
                4. Output a professional HTML report using Tailwind CSS. 
                5. Design the report to be clean, white, and corporate.
                """
                report_html = response.text # Use previous response or regenerate
                if "<html>" not in report_html: # If first response was short, regenerate
                     report_html = model.generate_content(full_prompt).text

                if "```html" in report_html:
                    report_html = report_html.replace("```html", "").replace("```", "")
                
                status.update(label=f"✅ **AUDIT COMPLETE ({used_model})**", state="complete", expanded=False)
                st.markdown("### 📊 VULNERABILITY REPORT")
                st.components.v1.html(report_html, height=800, scrolling=True)
            except Exception as e:
                st.error(f"Report Generation Failed: {e}")

        else:
            # FAILURE - SHOW THE REAL REASON
            st.error("❌ CRITICAL ERROR: API Key Rejected.")
            st.error("👇 READ THE ERROR LOG BELOW TO FIX IT:")
            for err in error_log:
                st.warning(err)
            
            if "403" in str(error_log):
                st.info("💡 FIX: Your API Key is invalid. Get a new key from aistudio.google.com")
            elif "429" in str(error_log):
                st.info("💡 FIX: You ran out of free queries (Quota Exceeded).")
            elif "location" in str(error_log):
                st.info("💡 FIX: Gemini is not available in your server's region.")
            
            st.stop()
