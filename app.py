import streamlit as st
import google.generativeai as genai
import nexus_agent_logic
import os

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Nexus DevSecOps Agent",
    page_icon="🛡️",
    layout="centered", # Centered layout focuses attention
    initial_sidebar_state="collapsed"
)

# --- 2. CUSTOM CSS (Colorful & Sharp) ---
st.markdown("""
<style>
    /* IMPORT FONT */
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&display=swap');

    /* BACKGROUND: Vibrant Gradient (No Image, just pure colorful CSS) */
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

    /* THE MAIN CARD (Solid White, No Blur) */
    .main-card {
        background-color: #ffffff;
        padding: 3rem;
        border-radius: 24px;
        box-shadow: 0 20px 50px rgba(0,0,0,0.3);
        margin-top: 2rem;
        border: 1px solid #e0e0e0;
    }

    /* TYPOGRAPHY */
    h1, h2, h3, p, div, span {
        font-family: 'Outfit', sans-serif !important;
        color: #1e293b; /* Dark Slate for high readability */
    }

    .agent-title {
        font-size: 3rem;
        font-weight: 800;
        text-align: center;
        background: linear-gradient(90deg, #2563eb, #db2777);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
    }

    .agent-subtitle {
        text-align: center;
        font-size: 1.1rem;
        color: #64748b;
        font-weight: 600;
        margin-bottom: 2rem;
        text-transform: uppercase;
        letter-spacing: 2px;
    }

    /* INPUT FIELD (Big & Clean) */
    .stTextInput > div > div > input {
        background-color: #f8fafc;
        border: 2px solid #e2e8f0;
        color: #0f172a;
        border-radius: 12px;
        padding: 16px;
        font-size: 18px;
    }
    .stTextInput > div > div > input:focus {
        border-color: #2563eb;
        box-shadow: 0 0 0 4px rgba(37, 99, 235, 0.1);
    }

    /* BUTTON (Pill Shape) */
    .stButton > button {
        width: 100%;
        background-color: #0f172a; /* Midnight Blue */
        color: white !important;
        font-weight: 700;
        border-radius: 50px; /* Pill shape */
        padding: 12px 24px;
        border: none;
        transition: all 0.3s ease;
        font-size: 1.1rem;
    }
    .stButton > button:hover {
        background-color: #2563eb; /* Bright Blue on Hover */
        transform: translateY(-2px);
        box-shadow: 0 10px 20px rgba(37, 99, 235, 0.2);
    }

    /* HIDE STREAMLIT UI */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# --- 3. UI LAYOUT ---

# START WHITE CARD CONTAINER
st.markdown('<div class="main-card">', unsafe_allow_html=True)

# FULL AGENT NAME
st.markdown('<h1 class="agent-title">NEXUS DEVSECOPS AGENT</h1>', unsafe_allow_html=True)
st.markdown('<div class="agent-subtitle">Autonomous Security Auditor • Built by Ganesh</div>', unsafe_allow_html=True)

st.markdown("""
<div style="text-align: center; margin-bottom: 25px; color: #475569;">
    Enter a public GitHub repository URL below. Nexus will perform a deep manifest scan 
    and cross-reference dependencies against the CVE database.
</div>
""", unsafe_allow_html=True)

# INPUT FORM
with st.form("scan_form"):
    repo_url = st.text_input("Repository URL", placeholder="https://github.com/owner/repo")
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Centered Button
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        scan_btn = st.form_submit_button("🚀 START SECURITY AUDIT")

st.markdown('</div>', unsafe_allow_html=True)
# END WHITE CARD CONTAINER


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
    
    # Use a container for the status to keep it clean
    with st.status("⚙️ **Nexus Operations Active**", expanded=True) as status:
        
        # STEP 1: SCAN TOOL
        st.write("📡 Scanning Repository Structure...")
        scan_data = nexus_agent_logic.scan_repo_manifest(repo_url)
        
        # DEBUG DATA (Hidden - Clean UI)
        with st.expander("Show Diagnostic Data (Debug)", expanded=False):
            st.code(scan_data, language='json')
            
        st.write("🛡️ Analyzing Vulnerabilities...")
        
        # STEP 2: AI ANALYSIS (FIXED MODEL)
        try:
            # FIX: We use 'gemini-pro' which is the standard stable model.
            # This fixes the "404 Not Found" error for Flash.
            model = genai.GenerativeModel('gemini-pro')
            
            prompt = f"""
            You are Nexus, a DevSecOps AI.
            Analyze this repository scan: {scan_data}
            
            Task:
            1. Identify critical vulnerabilities.
            2. Explain the risk (RCE, XSS, etc.).
            3. Provide remediation commands.
            4. Output a professional HTML report using Tailwind CSS. 
            5. Design the report to be clean, white, and corporate (Light Mode).
            """
            
            response = model.generate_content(prompt)
            report_html = response.text
            
            # Clean Markdown wrappers
            if "```html" in report_html:
                report_html = report_html.replace("```html", "").replace("```", "")
            
            status.update(label="✅ **Audit Successfully Completed**", state="complete", expanded=False)
            
        except Exception as e:
            st.error(f"AI Engine Error: {e}")
            st.stop()

    # DISPLAY REPORT
    st.markdown("### 📊 Vulnerability Report")
    st.components.v1.html(report_html, height=800, scrolling=True)
