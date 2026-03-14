import os
import json
import time
import shutil
import tempfile
import asyncio
import re
from datetime import datetime
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from git import Repo
import google.generativeai as genai

# Import your existing SCA logic
import nexus_agent_logic  

# --- 1. CONFIGURATION & AI SETUP ---
# Ensure your API key is set in your environment variables
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "YOUR_GEMINI_API_KEY_HERE")
if GEMINI_API_KEY != "YOUR_GEMINI_API_KEY_HERE":
    genai.configure(api_key=GEMINI_API_KEY)

app = FastAPI(title="Nexus DevSecOps API")

# Allow Next.js frontend (port 3000) to talk to this backend (port 8000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 2. DATABASE SETUP ---
Base = declarative_base()
class SecurityAudit(Base):
    __tablename__ = 'audits'
    id = Column(Integer, primary_key=True)
    repo_name = Column(String(255))
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50))
    report_data = Column(Text) # Saving raw JSON data for the frontend to render

engine = create_engine('sqlite:///nexus_history.db', connect_args={'check_same_thread': False})
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

# --- 3. PYDANTIC MODELS (Data Validation) ---
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]

class ScanRequest(BaseModel):
    repo_url: str
    webhook_url: Optional[str] = None

# --- 4. SAST LOGIC (Nuclear Regex Engine) ---
def find_python_root(start_path):
    """Recursively finds the first folder containing .py files."""
    for dirpath, _, filenames in os.walk(start_path):
        if any(f.endswith(".py") for f in filenames):
            return dirpath
    return start_path

def scan_code_for_patterns(base_dir):
    """Path-intelligent recursive Regex scan for RCE, Secrets, and Injection."""
    actual_path = find_python_root(base_dir)
    findings = []
    
    patterns = {
        r'yaml\.load\(': "RCE Risk (Unsafe Deserialization)",
        r'pickle\.load\(': "RCE Risk (Unsafe Deserialization)",
        r'eval\(': "Arbitrary Code Execution",
        r'exec\(': "Arbitrary Code Execution",
        r'os\.system\(': "Command Injection",
        r'subprocess\.Popen.*shell=True': "Command Injection",
        r'(?i)(api_key|secret_key|password|token)\s*=\s*[\'"][a-zA-Z0-9_\-]{16,}[\'"]': "Hardcoded Secret",
        r'app\.run\(.*debug=True': "Flask Debug Enabled",
        r'verify=False': "SSL Verification Disabled (MITM Risk)"
    }
    
    for dirpath, _, filenames in os.walk(actual_path):
        for filename in filenames:
            if filename.startswith('.') or filename.lower().endswith(('.png', '.jpg', '.pyc', '.exe')):
                continue
            filepath = os.path.join(dirpath, filename)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f):
                        for pattern, risk in patterns.items():
                            if re.search(pattern, line):
                                clean_line = line.strip()[:100]
                                rel_path = os.path.relpath(filepath, base_dir)
                                findings.append(f"[CRITICAL] Found '{risk}' in {rel_path} at line {i+1}: \"{clean_line}\"")
            except Exception:
                continue
                
    return "\n".join(findings) if findings else "SAFE: No critical SAST patterns found."

# --- 5. ENDPOINTS ---

@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    """Streams AI responses back to the Next.js ChatPanel (SSE format)"""
    async def event_generator():
        try:
            history = [{"role": "user" if m.role == "user" else "model", "parts": [m.content]} for m in request.messages[:-1]]
            latest_message = request.messages[-1].content

            available_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
            best_model_name = next((m for m in available_models if "flash" in m.lower()), "models/gemini-1.5-flash")
            
            model = genai.GenerativeModel(best_model_name)
            chat = model.start_chat(history=history)
            
            response = chat.send_message(latest_message, stream=True)
            for chunk in response:
                if chunk.text:
                    safe_text = chunk.text.replace("\n", "\\n")
                    yield f"data: {safe_text}\n\n"
                    await asyncio.sleep(0.02)
            
            yield "data: [DONE]\n\n"
        except Exception as e:
            yield f"data: Error: {str(e)}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/scan/stream")
async def scan_stream_endpoint(request: ScanRequest):
    """Streams the real-time execution log to the Next.js TerminalWidget"""
    async def execution_generator():
        def emit(type_str, content):
            timestamp = datetime.now().strftime("%H:%M:%S")
            data = json.dumps({"type": type_str, "content": content, "timestamp": timestamp})
            return f"data: {data}\n\n"

        repo_url = request.repo_url
        temp_dir = None
        
        try:
            yield emit("info", f"Target locked: {repo_url}")
            await asyncio.sleep(0.5)
            
            # 1. SAST Cloning Phase
            yield emit("prompt", "Initializing dynamic workspace...")
            temp_dir = tempfile.mkdtemp()
            yield emit("debug", f"Workspace created at {temp_dir}")
            
            yield emit("info", "Cloning remote repository...")
            Repo.clone_from(repo_url, temp_dir)
            yield emit("success", "Clone successful. Source code loaded.")
            
            # 2. SAST Execution
            yield emit("prompt", "Engaging SAST Regex Engine...")
            await asyncio.sleep(1)
            sast_results = scan_code_for_patterns(temp_dir)
            if "SAFE" in sast_results:
                yield emit("success", "SAST phase complete. No critical hardcoded patterns detected.")
            else:
                yield emit("critical", f"SAST identified potential vulnerabilities. {len(sast_results.split('[CRITICAL]'))-1} flags raised.")
            
            # 3. SCA Execution
            yield emit("prompt", "Fetching manifest via GitHub API (SCA)...")
            await asyncio.sleep(1)
            raw_sca_json = nexus_agent_logic.scan_repo_manifest(repo_url)
            sca_results = json.loads(raw_sca_json) if raw_sca_json else {}
            if "error" in sca_results:
                yield emit("warning", f"SCA API notice: {sca_results['error']}")
            else:
                yield emit("success", f"Manifest parsed. Extracted dependencies.")

            # 4. AI Generation Phase
            yield emit("info", "Aggregating data streams for Gemini AI analysis...")
            
            available_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
            best_model_name = next((m for m in available_models if "flash" in m.lower()), "models/gemini-1.5-flash")
            model = genai.GenerativeModel(best_model_name)
            
            prompt = f"""
            Analyze this data for {repo_url}. SAST: {sast_results}. SCA: {sca_results}.
            Return ONLY a raw JSON array of finding objects, exactly like this (NO markdown blocks):
            [ {{"title": "Unsafe YAML", "severity": "Critical", "description": "...", "poc": "...", "fix": "..."}} ]
            """
            
            response = model.generate_content(prompt)
            clean_json = response.text.replace("```json", "").replace("```", "").strip()
            findings = json.loads(clean_json)
            
            yield emit("success", "AI analysis complete. Report generated.")
            
            # 5. Save to Database
            crit_count = sum(1 for f in findings if f.get('severity', '').lower() == 'critical')
            status = "Failed" if crit_count > 0 else "Passed"
            repo_name = repo_url.split("/")[-1]
            
            with SessionLocal() as session:
                audit = SecurityAudit(
                    repo_name=repo_name, 
                    status=status, 
                    report_data=json.dumps(findings)
                )
                session.add(audit)
                session.commit()
                yield emit("debug", f"Audit archived to nexus_history.db (ID: {audit.id})")

            yield "data: [DONE]\n\n"
            
        except Exception as e:
            yield emit("critical", f"System Failure: {str(e)}")
            yield "data: [DONE]\n\n"
            
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    return StreamingResponse(execution_generator(), media_type="text/event-stream")


@app.get("/history")
def get_history():
    """Returns past audits for the frontend dropdown"""
    with SessionLocal() as session:
        audits = session.query(SecurityAudit).order_by(SecurityAudit.timestamp.desc()).limit(15).all()
        return [{"id": a.id, "repo_name": a.repo_name, "status": a.status, "timestamp": a.timestamp.isoformat()} for a in audits]

@app.get("/report/{report_id}")
def get_report(report_id: int):
    """Fetches a specific report by ID"""
    with SessionLocal() as session:
        audit = session.query(SecurityAudit).filter(SecurityAudit.id == report_id).first()
        if not audit:
            raise HTTPException(status_code=404, detail="Report not found")
        return {
            "id": audit.id,
            "repo_name": audit.repo_name,
            "status": audit.status,
            "timestamp": audit.timestamp.isoformat(),
            "findings": json.loads(audit.report_data) if audit.report_data else []
        }
