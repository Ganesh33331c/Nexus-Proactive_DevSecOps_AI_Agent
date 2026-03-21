"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Terminal as TerminalIcon,
  Play, Square, Trash2, Download,
  ChevronRight, FileText,
} from "lucide-react";
import { streamScan, TerminalLine } from "@/lib/api";
import type { PdfStatus } from "@/app/page";   // ← shared type from page.tsx

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ─── Extended SSE event shapes ────────────────────────────────────────────────
interface RawSseEvent {
  type: string;
  content: string;
  timestamp?: string;
  report_id?: number;
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

// ─── Props ────────────────────────────────────────────────────────────────────
interface TerminalWidgetProps {
  externalLines?:    TerminalLine[];
  isScanning?:       boolean;
  /**
   * Called whenever PDF state changes.
   * page.tsx listens here to render the full-width ReportPanel below both panels.
   */
  onPdfStateChange?: (state: PdfStatus) => void;
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function TerminalWidget({
  externalLines,
  isScanning = false,
  onPdfStateChange,
}: TerminalWidgetProps) {
  const [lines, setLines]                 = useState<TerminalLine[]>(DEMO_LINES);
  const [localRepoUrl, setLocalRepoUrl]   = useState<string>("");
  const [localScanning, setLocalScanning] = useState<boolean>(false);
  const [hasPdf, setHasPdf]              = useState(false);   // just for the "REPORT BELOW" hint

  const abortRef  = useRef<AbortController | null>(null);
  const blobRef   = useRef<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (externalLines && externalLines.length > 0) setLines(externalLines);
  }, [externalLines]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines]);

  // Revoke blob URL on unmount
  useEffect(() => {
    return () => { if (blobRef.current) URL.revokeObjectURL(blobRef.current); };
  }, []);

  const pushPdf = useCallback((state: PdfStatus) => {
    setHasPdf(state.status !== "idle");
    onPdfStateChange?.(state);
  }, [onPdfStateChange]);

  // ── Fetch success PDF ────────────────────────────────────────────────────
  const fetchReportPdf = useCallback(async (reportId: number) => {
    pushPdf({ status: "loading", message: "Generating PDF report..." });
    try {
      const res = await fetch(`${BASE_URL}/pdf-report/${reportId}`);
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Server returned ${res.status}: ${errText}`);
      }
      const blob = await res.blob();
      if (blobRef.current) URL.revokeObjectURL(blobRef.current);
      const url = URL.createObjectURL(blob);
      blobRef.current = url;
      pushPdf({ status: "ready", url, filename: `Nexus_Audit_${reportId}.pdf`, isError: false });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      pushPdf({ status: "error", message: `PDF generation failed: ${msg}` });
    }
  }, [pushPdf]);

  // ── Fetch error PDF ──────────────────────────────────────────────────────
  const fetchErrorPdf = useCallback(async (
    errorMessage: string,
    repoUrl: string,
    stage: string,
  ) => {
    pushPdf({ status: "loading", message: "Building failure report..." });
    try {
      const res = await fetch(`${BASE_URL}/pdf-error`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ error_message: errorMessage, repo_url: repoUrl, stage }),
      });
      if (!res.ok) throw new Error(`Server returned ${res.status}: ${await res.text()}`);
      const blob = await res.blob();
      if (blobRef.current) URL.revokeObjectURL(blobRef.current);
      const url = URL.createObjectURL(blob);
      blobRef.current = url;
      pushPdf({ status: "ready", url, filename: `Nexus_Error_Report_${Date.now()}.pdf`, isError: true });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      pushPdf({ status: "error", message: `Error report generation failed: ${msg}` });
    }
  }, [pushPdf]);

  // ── Reset PDF (e.g. when starting a new scan) ────────────────────────────
  const resetPdf = useCallback(() => {
    if (blobRef.current) { URL.revokeObjectURL(blobRef.current); blobRef.current = null; }
    pushPdf({ status: "idle" });
  }, [pushPdf]);

  // ── Start scan ───────────────────────────────────────────────────────────
  const startScan = useCallback(() => {
    if (!localRepoUrl.trim() || localScanning) return;
    setLocalScanning(true);
    setLines([]);
    resetPdf();

    abortRef.current = streamScan(
      localRepoUrl,
      (line) => {
        const raw = line as unknown as RawSseEvent;

        if (raw.type === "pdf_ready" && typeof raw.report_id === "number") {
          fetchReportPdf(raw.report_id);
          setLines((prev) => [
            ...prev,
            {
              type: "success" as const,
              content: `✔ PDF report ready (audit ID: ${raw.report_id}) — scroll down to view`,
              timestamp: raw.timestamp,
            },
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
            {
              type: "critical" as const,
              content: raw.content || "Scan failed — generating error report... scroll down to view",
              timestamp: raw.timestamp,
            },
          ]);
          return;
        }

        setLines((prev) => [...prev, line]);
      },
      () => {
        setLocalScanning(false);
        setLines((prev) => [
          ...prev,
          { type: "success" as const, content: "Scan pipeline complete." },
        ]);
      },
      (err) => {
        setLocalScanning(false);
        setLines((prev) => [
          ...prev,
          { type: "critical" as const, content: `Scan error: ${err.message}` },
        ]);
        // Fallback error PDF if no pdf_error SSE came through
        if (!hasPdf) {
          void fetchErrorPdf(err.message, localRepoUrl, "unknown");
        }
      },
    );
  }, [localRepoUrl, localScanning, resetPdf, fetchReportPdf, fetchErrorPdf, pushPdf]);

  const stopScan = () => {
    abortRef.current?.abort();
    setLocalScanning(false);
    setLines((prev) => [...prev, { type: "warning" as const, content: "Scan aborted by user." }]);
  };

  const clearTerminal = () => { setLines(DEMO_LINES); resetPdf(); };

  const downloadLog = () => {
    const text = lines.map((l) => `[${l.timestamp ?? ""}] [${l.type.toUpperCase()}] ${l.content}`).join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = `nexus_scan_${Date.now()}.log`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className="terminal-window"
      style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}
    >
      {/* ── Terminal header ────────────────────────────────────────────────── */}
      <div className="terminal-header justify-between">
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div className="terminal-dot" style={{ background: "#ff5f57" }} />
          <div className="terminal-dot" style={{ background: "#febc2e" }} />
          <div className="terminal-dot" style={{ background: "#28c840" }} />
          <div style={{ width: 1, height: 12, background: "rgba(255,255,255,0.1)", margin: "0 4px" }} />
          <TerminalIcon size={11} style={{ color: "#00f5ff" }} />
          <span style={{
            fontFamily: "'Orbitron', monospace", fontSize: "0.6rem",
            letterSpacing: "0.1em", color: "#00f5ff",
          }}>
            NEXUS EXECUTION ENGINE
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <AnimatePresence>
            {(localScanning || isScanning) && (
              <motion.div
                initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.8 }}
                style={{
                  display: "flex", alignItems: "center", gap: 6,
                  padding: "3px 8px", borderRadius: 4,
                  background: "rgba(255,71,87,0.1)", border: "1px solid rgba(255,71,87,0.3)",
                }}
              >
                <motion.div
                  animate={{ scale: [1, 1.4, 1] }}
                  transition={{ duration: 0.8, repeat: Infinity }}
                  style={{ width: 6, height: 6, borderRadius: "50%", background: "#ff4757" }}
                />
                <span style={{ fontFamily: "'Orbitron', monospace", fontSize: "0.5rem", color: "#ff4757", letterSpacing: "0.1em" }}>
                  SCANNING
                </span>
              </motion.div>
            )}
          </AnimatePresence>

          {/* "Report below" hint — just a label, no viewer inside the terminal */}
          {hasPdf && (
            <div style={{
              display: "flex", alignItems: "center", gap: 4,
              padding: "3px 8px",
              background: "rgba(0,245,255,0.06)", border: "1px solid rgba(0,245,255,0.2)",
              borderRadius: 4, color: "#00f5ff",
              fontFamily: "'Orbitron', monospace", fontSize: "0.5rem",
              letterSpacing: "0.06em",
            }}>
              <FileText size={9} /> REPORT BELOW ↓
            </div>
          )}

          <button onClick={clearTerminal} title="Clear"
            style={{ background: "transparent", border: "none", cursor: "pointer", color: "rgba(148,163,184,0.5)", padding: 4, borderRadius: 4, display: "flex" }}>
            <Trash2 size={11} />
          </button>
          <button onClick={downloadLog} title="Download log"
            style={{ background: "transparent", border: "none", cursor: "pointer", color: "rgba(148,163,184,0.5)", padding: 4, borderRadius: 4, display: "flex" }}>
            <Download size={11} />
          </button>
        </div>
      </div>

      {/* ── Terminal output ───────────────────────────────────────────────── */}
      <div className="terminal-output" style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>
        <AnimatePresence initial={false}>
          {lines.map((line, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.15 }}
              style={{ display: "flex", gap: 4, paddingBottom: 1, alignItems: "flex-start" }}
            >
              <ChevronRight size={10} style={{ color: "rgba(0,245,255,0.3)", marginTop: 3, flexShrink: 0 }} />
              <span style={{ wordBreak: "break-all" }}>{colorize(line)}</span>
            </motion.div>
          ))}
        </AnimatePresence>

        {(localScanning || isScanning) && (
          <motion.div style={{
            display: "flex", alignItems: "center", gap: 4, marginTop: 4,
            fontFamily: "'JetBrains Mono', monospace", fontSize: "0.7rem",
          }}>
            <ChevronRight size={10} style={{ color: "rgba(0,245,255,0.3)" }} />
            <span style={{ color: "rgba(148,163,184,0.5)" }}>nexus@scanner:~$</span>
            <motion.span
              animate={{ opacity: [1, 0, 1] }}
              transition={{ duration: 0.6, repeat: Infinity }}
              style={{ display: "inline-block", width: 6, height: 12, background: "#00f5ff", borderRadius: 1 }}
            />
          </motion.div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* ── URL input bar ─────────────────────────────────────────────────── */}
      <div style={{ padding: "8px 12px", borderTop: "1px solid rgba(0,245,255,0.08)", flexShrink: 0 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <span style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: "0.65rem",
            color: "rgba(0,245,255,0.5)", flexShrink: 0,
          }}>
            $
          </span>
          <input
            value={localRepoUrl}
            onChange={(e) => setLocalRepoUrl(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") startScan(); }}
            placeholder="https://github.com/user/repo"
            style={{
              flex: 1, background: "transparent", border: "none", outline: "none",
              fontFamily: "'JetBrains Mono', monospace", fontSize: "0.65rem",
              color: "#a4b0be", minWidth: 0,
            }}
          />
          {localScanning
            ? <button onClick={stopScan}  style={{ background: "none", border: "none", cursor: "pointer", padding: 2 }}>
                <Square size={11} style={{ color: "#ff4757" }} />
              </button>
            : <button onClick={startScan} style={{ background: "none", border: "none", cursor: "pointer", padding: 2 }}>
                <Play size={11} style={{ color: "#2ed573" }} />
              </button>
          }
        </div>
      </div>
    </div>
  );
}
