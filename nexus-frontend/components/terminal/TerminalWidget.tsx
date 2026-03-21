"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Terminal as TerminalIcon,
  Play,
  Square,
  Trash2,
  Download,
  ChevronRight,
  FileText,
  X,
  AlertTriangle,
  ExternalLink,
  Loader2,
} from "lucide-react";
import { streamScan, TerminalLine } from "@/lib/api";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ─── Types ────────────────────────────────────────────────────────────────────

type PdfStatus =
  | { status: "idle" }
  | { status: "loading"; message: string }
  | { status: "ready"; url: string; filename: string; isError: boolean }
  | { status: "error"; message: string };

// Extended SSE event shapes the backend emits.
// They share the TerminalLine shape but carry extra fields.
interface RawSseEvent {
  type: string;
  content: string;
  timestamp?: string;
  // pdf_ready
  report_id?: number;
  // pdf_error
  error_message?: string;
  repo_name?: string;
  stage?: string;
}

// ─── Syntax Highlighter ──────────────────────────────────────────────────────

function colorize(line: TerminalLine): React.ReactNode {
  const { type, content, timestamp } = line;

  const colorMap: Record<string, string> = {
    critical: "#ff4757",
    warning:  "#ffa502",
    success:  "#2ed573",
    info:     "#00f5ff",
    debug:    "#747d8c",
    prompt:   "#a855f7",
  };

  const color = colorMap[type] ?? "#cbd5e1";
  const ts = timestamp
    ? `[${timestamp}] `
    : `[${new Date().toLocaleTimeString("en-US", { hour12: false })}] `;

  const highlighted = content
    .replace(/\b(CRITICAL|FATAL|ERROR|RCE)\b/g,
      '<span style="color:#ff4757;font-weight:600">$1</span>')
    .replace(/\b(WARNING|WARN|HIGH)\b/g,
      '<span style="color:#ffa502;font-weight:600">$1</span>')
    .replace(/\b(SUCCESS|PASS|CLEAN|SAFE)\b/g,
      '<span style="color:#2ed573;font-weight:600">$1</span>')
    .replace(/\b(INFO|SCAN|FETCH)\b/g,
      '<span style="color:#00f5ff">$1</span>')
    .replace(/("[^"]*")/g,
      '<span style="color:#eccc68">$1</span>')
    .replace(/\b(\d+\.\d+\.\d+\.\d+)\b/g,
      '<span style="color:#70a1ff">$1</span>')
    .replace(/(\/[^\s]+)/g,
      '<span style="color:#a4b0be">$1</span>')
    .replace(/\b(CVE-\d{4}-\d+)/g,
      '<span style="color:#ff6b81;font-weight:600">$1</span>');

  return (
    <span>
      <span style={{ color: "rgba(148,163,184,0.4)", fontWeight: 300 }}>{ts}</span>
      <span style={{ color }} dangerouslySetInnerHTML={{ __html: highlighted }} />
    </span>
  );
}

const DEMO_LINES: TerminalLine[] = [
  { type: "success", content: "NEXUS Terminal v2.4.1 initialized",                  timestamp: "00:00:01" },
  { type: "info",    content: "Awaiting target repository...",                       timestamp: "00:00:01" },
  { type: "debug",   content: "SAST engine: READY | SCA engine: READY | AI: READY", timestamp: "00:00:02" },
  { type: "prompt",  content: "Enter a GitHub URL below to begin scanning.",         timestamp: "00:00:02" },
];

// ─── PDF Viewer ───────────────────────────────────────────────────────────────

interface PdfViewerProps {
  pdfState: PdfStatus;
  onClose: () => void;
}

function PdfViewer({ pdfState, onClose }: PdfViewerProps) {
  if (pdfState.status === "idle") return null;

  const isReady       = pdfState.status === "ready";
  const isErrorReport = isReady && (pdfState as Extract<PdfStatus, { status: "ready" }>).isError;

  const headerLabel =
    pdfState.status === "loading"
      ? (pdfState as Extract<PdfStatus, { status: "loading" }>).message.toUpperCase()
      : isErrorReport
      ? "SCAN FAILURE REPORT"
      : isReady
      ? "SECURITY AUDIT REPORT"
      : "REPORT ERROR";

  const headerColor = isErrorReport ? "#ff4757" : "#00f5ff";

  const handleDownload = () => {
    if (pdfState.status !== "ready") return;
    const readyState = pdfState as Extract<PdfStatus, { status: "ready" }>;
    const a = document.createElement("a");
    a.href     = readyState.url;
    a.download = readyState.filename;
    a.click();
  };

  const pdfUrl = isReady
    ? (pdfState as Extract<PdfStatus, { status: "ready" }>).url
    : null;

  const loadingMessage =
    pdfState.status === "loading"
      ? (pdfState as Extract<PdfStatus, { status: "loading" }>).message
      : "";

  const errorMessage =
    pdfState.status === "error"
      ? (pdfState as Extract<PdfStatus, { status: "error" }>).message
      : "";

  return (
    <motion.div
      initial={{ opacity: 0, y: 32 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 32 }}
      transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
      style={{
        width: "100%",
        background: "rgba(2,4,9,0.98)",
        borderTop: "1px solid rgba(0,245,255,0.15)",
        display: "flex",
        flexDirection: "column",
        flex: "1 1 0",
        minHeight: 0,
        overflow: "hidden",
      }}
    >
      {/* ── Header ── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 16px",
          background: "rgba(6,13,26,0.95)",
          borderBottom: "1px solid rgba(0,245,255,0.08)",
          flexShrink: 0,
          gap: 8,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {pdfState.status === "loading" ? (
            <Loader2 size={13} style={{ color: "#00f5ff", animation: "spin 1s linear infinite" }} />
          ) : isErrorReport ? (
            <AlertTriangle size={13} style={{ color: "#ff4757" }} />
          ) : (
            <FileText size={13} style={{ color: "#00f5ff" }} />
          )}
          <span
            style={{
              fontFamily: "'Orbitron', monospace",
              fontSize: "0.58rem",
              letterSpacing: "0.12em",
              color: headerColor,
            }}
          >
            {headerLabel}
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {isReady && pdfUrl && (
            <>
              <a
                href={pdfUrl}
                target="_blank"
                rel="noreferrer"
                style={{
                  display: "flex", alignItems: "center", gap: 5,
                  padding: "4px 10px",
                  background: "rgba(0,245,255,0.06)",
                  border: "1px solid rgba(0,245,255,0.2)",
                  borderRadius: 5, cursor: "pointer", color: "#00f5ff",
                  fontFamily: "'Orbitron', monospace",
                  fontSize: "0.5rem", letterSpacing: "0.08em",
                  textDecoration: "none",
                }}
              >
                <ExternalLink size={9} />
                OPEN TAB
              </a>

              <button
                onClick={handleDownload}
                style={{
                  display: "flex", alignItems: "center", gap: 5,
                  padding: "4px 10px",
                  background: "rgba(0,245,255,0.1)",
                  border: "1px solid rgba(0,245,255,0.3)",
                  borderRadius: 5, cursor: "pointer", color: "#00f5ff",
                  fontFamily: "'Orbitron', monospace",
                  fontSize: "0.5rem", letterSpacing: "0.08em",
                }}
              >
                <Download size={9} />
                DOWNLOAD PDF
              </button>
            </>
          )}

          {/* X — fully destroys the viewer */}
          <button
            onClick={onClose}
            title="Close report"
            style={{
              display: "flex", alignItems: "center", justifyContent: "center",
              width: 26, height: 26,
              background: "rgba(255,71,87,0.08)",
              border: "1px solid rgba(255,71,87,0.25)",
              borderRadius: 5, cursor: "pointer", color: "#ff4757", flexShrink: 0,
            }}
          >
            <X size={12} />
          </button>
        </div>
      </div>

      {/* ── Body ── */}
      <div style={{ flex: 1, minHeight: 0, position: "relative", background: "#020617" }}>

        {pdfState.status === "loading" && (
          <div style={{
            position: "absolute", inset: 0,
            display: "flex", flexDirection: "column",
            alignItems: "center", justifyContent: "center", gap: 16,
          }}>
            <div style={{
              width: 48, height: 48, borderRadius: "50%",
              border: "2px solid rgba(0,245,255,0.1)",
              borderTop: "2px solid #00f5ff",
              animation: "spin 0.9s linear infinite",
            }} />
            <span style={{
              fontFamily: "'Orbitron', monospace",
              fontSize: "0.62rem", letterSpacing: "0.1em",
              color: "rgba(0,245,255,0.6)",
            }}>
              {loadingMessage}
            </span>
          </div>
        )}

        {pdfState.status === "ready" && pdfUrl && (
          <iframe
            key={pdfUrl}
            src={pdfUrl}
            style={{ width: "100%", height: "100%", border: "none", background: "#020617" }}
            title="Nexus Security Report"
          />
        )}

        {pdfState.status === "error" && (
          <div style={{
            position: "absolute", inset: 0,
            display: "flex", flexDirection: "column",
            alignItems: "center", justifyContent: "center",
            gap: 12, padding: 24,
          }}>
            <AlertTriangle size={32} style={{ color: "#ff4757" }} />
            <p style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: "0.7rem", color: "#ff4757",
              textAlign: "center", maxWidth: 400,
            }}>
              {errorMessage}
            </p>
          </div>
        )}
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </motion.div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

interface TerminalWidgetProps {
  externalLines?: TerminalLine[];
  isScanning?: boolean;
}

export default function TerminalWidget({
  externalLines,
  isScanning = false,
}: TerminalWidgetProps) {
  const [lines, setLines]               = useState<TerminalLine[]>(DEMO_LINES);
  const [localRepoUrl, setLocalRepoUrl] = useState<string>("");
  const [localScanning, setLocalScanning] = useState<boolean>(false);
  const [pdfState, setPdfState]         = useState<PdfStatus>({ status: "idle" });

  const abortRef  = useRef<AbortController | null>(null);
  const blobRef   = useRef<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (externalLines && externalLines.length > 0) setLines(externalLines);
  }, [externalLines]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines]);

  useEffect(() => {
    return () => {
      if (blobRef.current) URL.revokeObjectURL(blobRef.current);
    };
  }, []);

  const setBlobUrl = (url: string) => {
    if (blobRef.current) URL.revokeObjectURL(blobRef.current);
    blobRef.current = url;
  };

  // ── Fetch success PDF ────────────────────────────────────────────────────
  const fetchReportPdf = useCallback(async (reportId: number) => {
    setPdfState({ status: "loading", message: "Generating PDF report..." });
    try {
      const res = await fetch(`${BASE_URL}/pdf-report/${reportId}`);
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Server returned ${res.status}: ${errText}`);
      }
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      setBlobUrl(url);
      setPdfState({ status: "ready", url, filename: `Nexus_Audit_${reportId}.pdf`, isError: false });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setPdfState({ status: "error", message: `PDF generation failed: ${msg}` });
    }
  }, []);

  // ── Fetch error PDF ──────────────────────────────────────────────────────
  const fetchErrorPdf = useCallback(async (
    errorMessage: string,
    repoUrl: string,
    stage: string,
  ) => {
    setPdfState({ status: "loading", message: "Building failure report..." });
    try {
      const res = await fetch(`${BASE_URL}/pdf-error`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error_message: errorMessage, repo_url: repoUrl, stage }),
      });
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      setBlobUrl(url);
      setPdfState({ status: "ready", url, filename: `Nexus_Error_Report_${Date.now()}.pdf`, isError: true });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setPdfState({ status: "error", message: `Error report generation failed: ${msg}` });
    }
  }, []);

  // ── Close viewer completely ──────────────────────────────────────────────
  const handleClosePdf = useCallback(() => {
    if (blobRef.current) {
      URL.revokeObjectURL(blobRef.current);
      blobRef.current = null;
    }
    setPdfState({ status: "idle" });
  }, []);

  // ── Start scan ───────────────────────────────────────────────────────────
  const startScan = useCallback(() => {
    if (!localRepoUrl.trim() || localScanning) return;
    setLocalScanning(true);
    setLines([]);
    handleClosePdf();

    abortRef.current = streamScan(
      localRepoUrl,
      (line) => {
        const raw = line as unknown as RawSseEvent;

        if (raw.type === "pdf_ready" && typeof raw.report_id === "number") {
          fetchReportPdf(raw.report_id);
          setLines((prev) => [
            ...prev,
            { type: "success" as const, content: `PDF report ready (audit ID: ${raw.report_id})`, timestamp: raw.timestamp },
          ]);
          return;
        }

        if (raw.type === "pdf_error") {
          fetchErrorPdf(
            String(raw.error_message ?? "Unknown error"),
            String(raw.repo_name   ?? localRepoUrl),
            String(raw.stage       ?? "unknown"),
          );
          setLines((prev) => [
            ...prev,
            { type: "critical" as const, content: raw.content || "Scan failed — generating error report...", timestamp: raw.timestamp },
          ]);
          return;
        }

        setLines((prev) => [...prev, line]);
      },
      () => {
        setLocalScanning(false);
        setLines((prev) => [...prev, { type: "success" as const, content: "Scan pipeline complete." }]);
      },
      (err) => {
        setLocalScanning(false);
        setLines((prev) => [...prev, { type: "critical" as const, content: `Scan error: ${err.message}` }]);
        // Fallback if no pdf_error signal was received
        setPdfState((prev) => {
          if (prev.status === "idle") {
            void fetchErrorPdf(err.message, localRepoUrl, "unknown");
          }
          return prev;
        });
      },
    );
  }, [localRepoUrl, localScanning, handleClosePdf, fetchReportPdf, fetchErrorPdf]);

  const stopScan = () => {
    abortRef.current?.abort();
    setLocalScanning(false);
    setLines((prev) => [...prev, { type: "warning" as const, content: "Scan aborted by user." }]);
  };

  const clearTerminal = () => { setLines(DEMO_LINES); handleClosePdf(); };

  const downloadLog = () => {
    const text = lines.map((l) => `[${l.timestamp ?? ""}] [${l.type.toUpperCase()}] ${l.content}`).join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = `nexus_scan_${Date.now()}.log`; a.click();
    URL.revokeObjectURL(url);
  };

  const pdfVisible = pdfState.status !== "idle";

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0, overflow: "hidden" }}>

      {/* ══════════════════════════════════════════════════════
          TERMINAL SECTION
      ══════════════════════════════════════════════════════ */}
      <div
        className="terminal-window"
        style={{
          display: "flex", flexDirection: "column",
          flex: pdfVisible ? "0 0 45%" : "1 1 0",
          minHeight: 0, overflow: "hidden",
          transition: "flex 0.35s ease",
        }}
      >
        {/* Header */}
        <div className="terminal-header justify-between">
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div className="terminal-dot" style={{ background: "#ff5f57" }} />
            <div className="terminal-dot" style={{ background: "#febc2e" }} />
            <div className="terminal-dot" style={{ background: "#28c840" }} />
            <div style={{ width: 1, height: 12, background: "rgba(255,255,255,0.1)", margin: "0 4px" }} />
            <TerminalIcon size={11} style={{ color: "#00f5ff" }} />
            <span style={{ fontFamily: "'Orbitron', monospace", fontSize: "0.6rem", letterSpacing: "0.1em", color: "#00f5ff" }}>
              NEXUS EXECUTION ENGINE
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <AnimatePresence>
              {(localScanning || isScanning) && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.8 }}
                  style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 8px", borderRadius: 4, background: "rgba(255,71,87,0.1)", border: "1px solid rgba(255,71,87,0.3)" }}
                >
                  <motion.div animate={{ scale: [1, 1.4, 1] }} transition={{ duration: 0.8, repeat: Infinity }}
                    style={{ width: 6, height: 6, borderRadius: "50%", background: "#ff4757" }} />
                  <span style={{ fontFamily: "'Orbitron', monospace", fontSize: "0.5rem", color: "#ff4757", letterSpacing: "0.1em" }}>SCANNING</span>
                </motion.div>
              )}
            </AnimatePresence>

            {pdfVisible && (
              <button
                onClick={() => { if (pdfState.status === "ready") window.open((pdfState as Extract<PdfStatus, {status:"ready"}>).url, "_blank"); }}
                style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", background: "rgba(0,245,255,0.1)", border: "1px solid rgba(0,245,255,0.3)", borderRadius: 4, cursor: "pointer", color: "#00f5ff", fontFamily: "'Orbitron', monospace", fontSize: "0.5rem" }}
              >
                <FileText size={9} /> REPORT BELOW
              </button>
            )}

            <button onClick={clearTerminal} title="Clear" style={{ background: "transparent", border: "none", cursor: "pointer", color: "rgba(148,163,184,0.5)", padding: 4, borderRadius: 4, display: "flex" }}><Trash2 size={11} /></button>
            <button onClick={downloadLog}   title="Download log" style={{ background: "transparent", border: "none", cursor: "pointer", color: "rgba(148,163,184,0.5)", padding: 4, borderRadius: 4, display: "flex" }}><Download size={11} /></button>
          </div>
        </div>

        {/* Output */}
        <div className="terminal-output" style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>
          <AnimatePresence initial={false}>
            {lines.map((line, i) => (
              <motion.div key={i} initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.15 }}
                style={{ display: "flex", gap: 4, paddingBottom: 1, alignItems: "flex-start" }}>
                <ChevronRight size={10} style={{ color: "rgba(0,245,255,0.3)", marginTop: 3, flexShrink: 0 }} />
                <span style={{ wordBreak: "break-all" }}>{colorize(line)}</span>
              </motion.div>
            ))}
          </AnimatePresence>

          {(localScanning || isScanning) && (
            <motion.div style={{ display: "flex", alignItems: "center", gap: 4, marginTop: 4, fontFamily: "'JetBrains Mono', monospace", fontSize: "0.7rem" }}>
              <ChevronRight size={10} style={{ color: "rgba(0,245,255,0.3)" }} />
              <span style={{ color: "rgba(148,163,184,0.5)" }}>nexus@scanner:~$</span>
              <motion.span animate={{ opacity: [1, 0, 1] }} transition={{ duration: 0.6, repeat: Infinity }}
                style={{ display: "inline-block", width: 6, height: 12, background: "#00f5ff", borderRadius: 1 }} />
            </motion.div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Input bar */}
        <div style={{ padding: "8px 12px", borderTop: "1px solid rgba(0,245,255,0.08)", flexShrink: 0 }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.65rem", color: "rgba(0,245,255,0.5)", flexShrink: 0 }}>$</span>
            <input
              value={localRepoUrl}
              onChange={(e) => setLocalRepoUrl(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") startScan(); }}
              placeholder="github.com/user/repo"
              style={{ flex: 1, background: "transparent", border: "none", outline: "none", fontFamily: "'JetBrains Mono', monospace", fontSize: "0.65rem", color: "#a4b0be", minWidth: 0 }}
            />
            {localScanning
              ? <button onClick={stopScan}  style={{ background: "none", border: "none", cursor: "pointer", padding: 2 }}><Square size={11} style={{ color: "#ff4757" }} /></button>
              : <button onClick={startScan} style={{ background: "none", border: "none", cursor: "pointer", padding: 2 }}><Play   size={11} style={{ color: "#2ed573" }} /></button>
            }
          </div>
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════
          PDF VIEWER  (slides in below the terminal)
      ══════════════════════════════════════════════════════ */}
      <AnimatePresence>
        {pdfVisible && <PdfViewer pdfState={pdfState} onClose={handleClosePdf} />}
      </AnimatePresence>

    </div>
  );
}
