import os
import json
import asyncio
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
import google.generativeai as genai

# Import your newly updated logic engine
import nexus_agent_logic  

# --- 1. CONFIGURATION & AI SETUP ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "YOUR_GEMINI_API_KEY_HERE")
if GEMINI_API_KEY != "YOUR_GEMINI_API_KEY_HERE":
    genai.configure(api_key=GEMINI_API_KEY)

app = FastAPI(title="Nexus DevSecOps API")

# Allow live Vercel frontend to talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    report_data = Column(Text) # Saving raw deterministic JSON data

engine = create_engine('sqlite:///nexus_history.db', connect_args={'check_same_thread': False})
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

# --- 3. PYDANTIC ROUTE MODELS ---
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]

class ScanRequest(BaseModel):
    repo_url: str


# --- 4. ENDPOINTS ---
@app.get("/")
def read_root():
    return {"status": "Nexus JSON-First Backend is Live"}

@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    """Streams AI responses back to the Next.js ChatPanel (SSE format)"""
    async def event_generator():
        try:
            history = [{"role": "user" if m.role == "user" else "model", "parts": [m.content]} for m in request.messages[:-1]]
            latest_message = request.messages[-1].content

            model = genai.GenerativeModel("gemini-1.5-flash")
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
    """Streams the real-time execution log AND generates the strict JSON report."""
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
            temp_dir = nexus_agent_logic.clone_repository(repo_url)
            if not temp_dir:
                yield emit("critical", "Failed to clone repository.")
                return
            yield emit("debug", f"Workspace created at {temp_dir}")
            yield emit("success", "Clone successful. Source code loaded.")
            
            # 2. SAST Execution
            yield emit("prompt", "Engaging SAST Regex Engine...")
            await asyncio.sleep(1)
            sast_results = nexus_agent_logic.run_sast(temp_dir)
            yield emit("success", "SAST phase complete.")
            
            # 3. SCA Execution
            yield emit("prompt", "Fetching manifest via GitHub API (SCA)...")
            await asyncio.sleep(1)
            sca_results = nexus_agent_logic.run_sca(repo_url)
            yield emit("success", "SCA phase complete.")

            # 4. Deterministic AI Generation Phase
            yield emit("info", "Aggregating data streams for JSON-First AI analysis...")
            json_report = nexus_agent_logic.analyze_with_ai(sast_results, sca_results, repo_url)
            yield emit("success", "AI analysis complete. Deterministic JSON generated.")
            
            # 5. Save to Database
            crit_count = json_report.get("critical_count", 0)
            status = "Failed" if crit_count > 0 else "Passed"
            repo_name = repo_url.rstrip("/").rstrip(".git").split("/")[-1]
            
            with SessionLocal() as session:
                audit = SecurityAudit(
                    repo_name=repo_name, 
                    status=status, 
                    report_data=json.dumps(json_report)
                )
                session.add(audit)
                session.commit()
                yield emit("debug", f"Audit archived to nexus_history.db (ID: {audit.id})")

            yield "data: [DONE]\n\n"
            
        except Exception as e:
            yield emit("critical", f"System Failure: {str(e)}")
            yield "data: [DONE]\n\n"
            
        finally:
            nexus_agent_logic.cleanup(temp_dir)

    return StreamingResponse(execution_generator(), media_type="text/event-stream")


@app.post("/api/scan")
async def run_full_scan_sync(repo_url: str):
    """Direct JSON endpoint for triggering a scan without the SSE stream."""
    try:
        temp_dir = nexus_agent_logic.clone_repository(repo_url)
        sast_data = nexus_agent_logic.run_sast(temp_dir)
        sca_data = nexus_agent_logic.run_sca(repo_url)
        json_report = nexus_agent_logic.analyze_with_ai(sast_data, sca_data, repo_url)
        nexus_agent_logic.cleanup(temp_dir)
        return json_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/history")
def get_history():
    """Returns past audits for the frontend dropdown"""
    with SessionLocal() as session:
        audits = session.query(SecurityAudit).order_by(SecurityAudit.timestamp.desc()).limit(15).all()
        return [{"id": a.id, "repo_name": a.repo_name, "status": a.status, "timestamp": a.timestamp.isoformat()} for a in audits]

@app.get("/report/{report_id}")
def get_report(report_id: int):
    """Fetches a specific report by ID and maps it to the frontend's expected format"""
    with SessionLocal() as session:
        audit = session.query(SecurityAudit).filter(SecurityAudit.id == report_id).first()
        if not audit:
            raise HTTPException(status_code=404, detail="Report not found")
            
        report_data = json.loads(audit.report_data) if audit.report_data else {}
        
        return {
            "id": audit.id,
            "repo_name": audit.repo_name,
            "status": audit.status,
            "timestamp": audit.timestamp.isoformat(),
            "findings": report_data.get("vulnerabilities", []),
            "critical_count": report_data.get("critical_count", 0),
            "scan_status": report_data.get("scan_status", audit.status)
        }
