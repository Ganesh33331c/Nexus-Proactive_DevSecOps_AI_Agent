import streamlit as st
import google.generativeai as genai
import nexus_agent_logic
import os

# --- CONFIGURATION ---
st.set_page_config(page_title="Nexus DevSecOps Agent", page_icon="🛡️", layout="wide")

# --- SECRETS MANAGEMENT (Cloud Compatible) ---
# Try to get keys from Environment (Local .env) OR Streamlit Secrets (Cloud)
api_key = os.environ.get("GEMINI_API_KEY")
if not api_key and "GEMINI_API_KEY" in st.secrets:
    api_key = st.secrets["GEMINI_API_KEY"]

if not api_key:
    api_key = st.sidebar.text_input("Enter Gemini API Key", type="password")

if api_key:
    genai.configure(api_key=api_key)

# --- UI HEADER ---
st.title("🛡️ Nexus: Proactive Security Agent")
st.markdown("""
<style>
    .stButton>button { width: 100%; border-radius: 8px; background-color: #2563eb; color: white; }
</style>
""", unsafe_allow_html=True)

st.caption("Capstone Project | Powered by Google Gemini 2.5 & Opal")

# --- MAIN INTERFACE ---
col1, col2 = st.columns([3, 1])
with col1:
    repo_url = st.text_input("GitHub Repository URL", placeholder="https://github.com/username/repo")

with col2:
    st.write("") # Spacer
    st.write("") # Spacer
    scan_btn = st.button("🚀 Run Security Audit")

# --- AGENT LOGIC ---
if scan_btn and repo_url and api_key:
    with st.status("🕵️ Nexus is working...", expanded=True) as status:
        
        # STEP 1: EXECUTE TOOL
        st.write("Targeting repository manifest...")
        try:
            # Pass the GitHub Token if available in secrets
            if "GITHUB_TOKEN" in st.secrets:
                os.environ["GITHUB_TOKEN"] = st.secrets["GITHUB_TOKEN"]
                
            scan_data = nexus_agent_logic.scan_repo_manifest(repo_url)
            st.success("Repository manifest scanned successfully!")
        except Exception as e:
            st.error(f"Tool Error: {e}")
            st.stop()

        # STEP 2: REASONING (GEMINI)
        st.write("Correlating CVE database with findings...")
        model = genai.GenerativeModel('gemini-1.5-flash') 
        
        prompt = f"""
        You are Nexus, a DevSecOps AI. 
        Analyze this repository scan data: {scan_data}
        
        Cross-reference these dependencies with known CVEs.
        Generate a full HTML report using Tailwind CSS. 
        Use the exact HTML format/style that was successful in previous tests.
        Ensure you include 'Remediation Patches' for every vulnerability.
        """
        
        try:
            response = model.generate_content(prompt)
            report_html = response.text
            # Clean markdown wrappers
            if "```html" in report_html:
                report_html = report_html.replace("```html", "").replace("```", "")
            st.success("Report generated!")
        except Exception as e:
            st.error(f"Gemini Error: {e}")
            st.stop()
            
        status.update(label="Audit Complete!", state="complete", expanded=False)

    # --- DISPLAY REPORT ---
    st.subheader("📊 Audit Results")
    st.components.v1.html(report_html, height=800, scrolling=True)
    
    st.download_button(
        label="Download Report HTML",
        data=report_html,
        file_name="nexus_audit_report.html",
        mime="text/html"
    )

elif scan_btn and not api_key:

    st.warning("Please provide a Gemini API Key to proceed.")
