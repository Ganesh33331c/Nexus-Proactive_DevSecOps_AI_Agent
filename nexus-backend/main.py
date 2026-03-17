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

# --- LANGCHAIN IMPORTS FOR CHAT (GEMINI) ---
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

import nexus_agent_logic

app = FastAPI(title="Nexus DevSecOps API")

# Allow live Vercel frontend to talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DATABASE SETUP ---
Base = declarative_base()

class SecurityAudit(Base):
    __tablename__ = 'audits'
    id = Column(Integer, primary_key=True)
    repo_name = Column(String(255))
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50))
    report_data = Column(Text)

engine = create_engine('sqlite:///nexus_history.db', connect_args={'check_same_thread': False})
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

# --- PYDANTIC ROUTE MODELS ---
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]

class ScanRequest(BaseModel):
    repo_url: str


# --- ENDPOINTS ---
@app.get("/")
def read_root():
    return {"status": "Nexus Backend is Live", "model": nexus_agent_logic._resolve_model()}


@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    """Streams Gemini responses back to the Next.js ChatPanel (SSE format)."""
    async def event_generator():
        try:
            langchain_messages = [
                SystemMessage(
                    content=(
                        "You are Nexus, an elite DevSecOps AI Assistant. "
                        "Provide concise, expert cybersecurity advice. "
                        "When the user provides a GitHub URL, confirm you will initiate "
                        "a scan via the /scan/stream endpoint."
                    )
                )
            ]

            for msg in request.messages:
                if msg.role == "user":
                    langchain_messages.append(HumanMessage(content=msg.content))
                else:
                    langchain_messages.append(AIMessage(content=msg.content))

            # Use the shared model resolver — same model everywhere
            model_name = nexus_agent_logic._resolve_model()

            llm = ChatGoogleGenerativeAI(
                model=model_name,
                temperature=0.7,
                google_api_key=os.environ.get("GEMINI_API_KEY"),
            )

            for chunk in llm.stream(langchain_messages):
                if chunk.content:
                    # Escape newlines so SSE framing isn't broken
                    safe_text = chunk.content.replace("\n", "\\n")
                    yield f"data: {safe_text}\n\n"
                    await asyncio.sleep(0.01)

            yield "data: [DONE]\n\n"

        except Exception as e:
            error_msg = str(e).replace("\n", " ")
            yield f"data: ⚠ Backend Error: {error_msg}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/scan/stream")
async def scan_stream_endpoint(request: ScanRequest):
    """Streams real-time terminal output for a full repo scan."""
    async def execution_generator():
        def emit(type_str: str, content: str) -> str:
            timestamp = datetime.now().strftime("%H:%M:%S")
            data = json.dumps({
                "type": type_str,
                "content": content,
                "timestamp": timestamp,
            })
            return f"data: {data}\n\n"

        repo_url = request.repo_url
        temp_dir = None

        try:
            yield emit("info", f"Target locked: {repo_url}")
            await asyncio.sleep(0.3)

            yield emit("prompt", "Initializing dynamic sandbox workspace...")
            temp_dir = nexus_agent_logic.clone_repository(repo_url)
            if not temp_dir:
                yield emit("critical", "Failed to clone repository. Verify the URL is a valid public Git repo.")
                yield "data: [DONE]\n\n"
                return

            yield emit("debug", f"Sandbox ready: {temp_dir}")
            yield emit("success", "Repository cloned successfully.")

            yield emit("prompt", "Engaging SAST Regex Engine (20 pattern classes)...")
            await asyncio.sleep(0.5)
            sast_results = nexus_agent_logic.run_sast(temp_dir)
            sast_summary = json.loads(sast_results)
            yield emit(
                "success",
                f"SAST complete — {sast_summary.get('files_scanned', '?')} files scanned, "
                f"{sast_summary.get('total_findings', '?')} raw findings.",
            )

            yield emit("prompt", "Parsing dependency manifests (SCA deep search)...")
            await asyncio.sleep(0.5)
            sca_results = nexus_agent_logic.run_sca(temp_dir)
            sca_summary = json.loads(sca_results)
            yield emit(
                "success",
                f"SCA complete — {sca_summary.get('manifests_found', '?')} manifest(s) found, "
                f"{len(sca_summary.get('vulnerability_hints', []))} dependency hints.",
            )

            model_name = nexus_agent_logic._resolve_model()
            yield emit("info", f"Invoking AI analysis engine (model: {model_name})...")
            await asyncio.sleep(0.3)

            json_report = nexus_agent_logic.analyze_with_ai(sast_results, sca_results, repo_url)
            yield emit("success", "AI analysis complete. Structured JSON report generated.")

            crit_count = json_report.get("critical_count", 0)
            high_count = json_report.get("high_count", 0)
            total_vulns = len(json_report.get("vulnerabilities", []))
            status = "Failed" if crit_count > 0 else "Passed"

            yield emit(
                "critical" if crit_count > 0 else "success",
                f"Scan result: {status} — {total_vulns} vulnerabilities "
                f"({crit_count} critical, {high_count} high).",
            )

            repo_name = repo_url.rstrip("/").rstrip(".git").split("/")[-1]
            with SessionLocal() as session:
                audit = SecurityAudit(
                    repo_name=repo_name,
                    status=status,
                    report_data=json.dumps(json_report),
                )
                session.add(audit)
                session.commit()
                yield emit("debug", f"Audit archived to DB (ID: {audit.id})")

            yield "data: [DONE]\n\n"

        except Exception as e:
            yield emit("critical", f"System Failure: {str(e)}")
            yield "data: [DONE]\n\n"

        finally:
            nexus_agent_logic.cleanup(temp_dir)

    return StreamingResponse(execution_generator(), media_type="text/event-stream")


@app.post("/api/scan")
async def run_full_scan_sync(repo_url: str):
    """Synchronous scan endpoint — returns the full report JSON in one response."""
    try:
        temp_dir = nexus_agent_logic.clone_repository(repo_url)
        if not temp_dir:
            raise HTTPException(status_code=400, detail="Failed to clone repository.")
        sast_data = nexus_agent_logic.run_sast(temp_dir)
        sca_data = nexus_agent_logic.run_sca(temp_dir)
        json_report = nexus_agent_logic.analyze_with_ai(sast_data, sca_data, repo_url)
        nexus_agent_logic.cleanup(temp_dir)
        return json_report
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/history")
def get_history():
    with SessionLocal() as session:
        audits = (
            session.query(SecurityAudit)
            .order_by(SecurityAudit.timestamp.desc())
            .limit(15)
            .all()
        )
        return [
            {
                "id": a.id,
                "repo_name": a.repo_name,
                "status": a.status,
                "timestamp": a.timestamp.isoformat(),
            }
            for a in audits
        ]


@app.get("/report/{report_id}")
def get_report(report_id: int):
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
            "high_count": report_data.get("high_count", 0),
            "medium_count": report_data.get("medium_count", 0),
            "scan_status": report_data.get("scan_status", audit.status),
        }
