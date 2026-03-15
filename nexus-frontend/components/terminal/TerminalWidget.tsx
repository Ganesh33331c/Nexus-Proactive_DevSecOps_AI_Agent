"use client";

import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Terminal as TerminalIcon,
  Play,
  Square,
  Trash2,
  Download,
  ChevronRight,
  FileText
} from "lucide-react";
import { streamScan, TerminalLine, getScanReport } from "@/lib/api";

// ─── Syntax Highlighter ─────────────────────────────────────
function colorize(line: TerminalLine): React.ReactNode {
  const { type, content, timestamp } = line;

  const colorMap: Record<TerminalLine["type"], string> = {
    critical: "#ff4757",
    warning: "#ffa502",
    success: "#2ed573",
    info: "#00f5ff",
    debug: "#747d8c",
    prompt: "#a855f7",
  };

  const color = colorMap[type] || "#cbd5e1";
  const ts = timestamp
    ? `[${timestamp}] `
    : `[${new Date().toLocaleTimeString("en-US", { hour12: false })}] `;

  const highlighted = content
    .replace(/\b(CRITICAL|FATAL|ERROR|RCE)\b/g, '<span style="color:#ff4757;font-weight:600">$1</span>')
    .replace(/\b(WARNING|WARN|HIGH)\b/g, '<span style="color:#ffa502;font-weight:600">$1</span>')
    .replace(/\b(SUCCESS|PASS|CLEAN|SAFE)\b/g, '<span style="color:#2ed573;font-weight:600">$1</span>')
    .replace(/\b(INFO|SCAN|FETCH)\b/g, '<span style="color:#00f5ff">$1</span>')
    .replace(/("[^"]*")/g, '<span style="color:#eccc68">$1</span>')
    .replace(/\b(\d+\.\d+\.\d+\.\d+)\b/g, '<span style="color:#70a1ff">$1</span>')
    .replace(/(\/[^\s]+)/g, '<span style="color:#a4b0be">$1</span>')
    .replace(/\b(CVE-\d{4}-\d+)/g, '<span style="color:#ff6b81;font-weight:600">$1</span>');

  return (
    <span>
      <span style={{ color: "rgba(148,163,184,0.4)", fontWeight: 300 }}>{ts}</span>
      <span style={{ color }} dangerouslySetInnerHTML={{ __html: highlighted }} />
    </span>
  );
}

const DEMO_LINES: TerminalLine[] = [
  { type: "success", content: "NEXUS Terminal v2.4.1 initialized", timestamp: "00:00:01" },
  { type: "info", content: "Awaiting target repository...", timestamp: "00:00:01" },
  { type: "debug", content: "SAST engine: READY | SCA engine: READY | AI model: READY", timestamp: "00:00:02" },
  { type: "prompt", content: "Enter a GitHub URL in the chat to begin scanning.", timestamp: "00:00:02" },
];

interface TerminalWidgetProps {
  externalLines?: TerminalLine[];
  isScanning?: boolean;
}

export default function TerminalWidget({ externalLines, isScanning = false }: TerminalWidgetProps) {
  const [lines, setLines] = useState<TerminalLine[]>(DEMO_LINES);
  const [localRepoUrl, setLocalRepoUrl] = useState("");
  const [localScanning, setLocalScanning] = useState(false);
  const [auditId, setAuditId] = useState<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (externalLines && externalLines.length > 0) setLines(externalLines);
  }, [externalLines]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines]);

  const startScan = () => {
    if (!localRepoUrl.trim() || localScanning) return;
    setLocalScanning(true);
    setLines([]);
    setAuditId(null); 

    abortRef.current = streamScan(
      localRepoUrl,
      (line) => {
        setLines((prev) => [...prev, line]);
        if (line.content.includes("Audit archived to nexus_history.db")) {
          const match = line.content.match(/ID:\s*(\d+)/);
          if (match) setAuditId(parseInt(match[1], 10));
        }
      },
      () => {
        setLocalScanning(false);
        setLines((prev) => [...prev, { type: "success", content: "Scan complete. Report generated." }]);
      },
      (err) => {
        setLocalScanning(false);
        setLines((prev) => [...prev, { type: "critical", content: `Scan error: ${err.message}` }]);
      }
    );
  };

  const stopScan = () => {
    abortRef.current?.abort();
    setLocalScanning(false);
    setLines((prev) => [...prev, { type: "warning", content: "Scan aborted by user." }]);
  };

  const clearTerminal = () => {
      setLines(DEMO_LINES);
      setAuditId(null);
  }

  const downloadLog = () => {
    const text = lines.map((l) => `[${l.timestamp || ""}] [${l.type.toUpperCase()}] ${l.content}`).join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nexus_scan_${Date.now()}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ─── DYNAMIC HTML REPORT GENERATOR ───
  const downloadHtmlReport = async () => {
    if (!auditId) return;
    try {
      const res = await getScanReport(auditId);
      const data = res.data;
      const findings = data.findings || [];
      const counts = { critical: 0, high: 0, medium: 0, low: 0 };
      
      findings.forEach((f: any) => {
        const sev = (f.severity || "low").toLowerCase();
        if (counts[sev as keyof typeof counts] !== undefined) {
          counts[sev as keyof typeof counts]++;
        }
      });

     // --- PREMIUM HTML LAYOUT GENERATOR ---
      const cardsHtml = findings.map((f: any) => {
        const sev = (f.severity || "low").toLowerCase();
        let badgeColor = "bg-green-500/20 text-green-400 border-green-500/30";
        if (sev === "critical") badgeColor = "bg-red-500/20 text-red-400 border-red-500/30";
        if (sev === "high") badgeColor = "bg-orange-500/20 text-orange-400 border-orange-500/30";
        if (sev === "medium") badgeColor = "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";

        return `
        <div class="f-card glass-panel p-8 mb-6 sev-${sev}" data-sev="${sev}">
            <div class="flex justify-between items-start mb-4">
                <h3 class="text-2xl font-bold text-white font-display tracking-wide">${f.title || 'Unknown Finding'}</h3>
                <span class="badge border ${badgeColor}">${sev}</span>
            </div>
            <p class="text-base text-slate-300 mb-6 leading-relaxed">${f.description || ''}</p>
            
            <div class="grid grid-cols-1 gap-4">
                <div class="glass-card p-5 border-l-2 border-l-pink-500/50">
                    <span class="text-xs text-pink-400 font-mono font-bold uppercase tracking-widest block mb-2">Proof of Concept</span>
                    <code class="text-sm text-pink-100 font-mono block whitespace-pre-wrap">${f.poc || 'N/A'}</code>
                </div>
                <div class="glass-card p-5 border-l-2 border-l-emerald-500/50">
                    <span class="text-xs text-emerald-400 font-mono font-bold uppercase tracking-widest block mb-2">Remediation Guide</span>
                    <code class="text-sm text-emerald-100 font-mono block whitespace-pre-wrap">${f.fix || 'N/A'}</code>
                </div>
            </div>
        </div>`;
      }).join("");

      const htmlString = `<!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Nexus Security Audit: ${data.repo_name}</title>
          <script src="https://cdn.tailwindcss.com"></script>
          <link href="https://fonts.googleapis.com/css2?family=Exo+2:wght@300;400;600;700&family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@500;700;900&display=swap" rel="stylesheet">
          <style>
              body { background-color: #020409; color: #cbd5e1; font-family: 'Exo 2', sans-serif; }
              h1, h2, h3, .font-display { font-family: 'Orbitron', sans-serif; }
              code, pre, .font-mono { font-family: 'JetBrains Mono', monospace; }
              
              .glass-panel { background: rgba(10, 18, 35, 0.75); backdrop-filter: blur(12px); border: 1px solid rgba(0, 245, 255, 0.1); border-radius: 12px; }
              .glass-card { background: rgba(15, 23, 42, 0.5); backdrop-filter: blur(8px); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 8px; }
              
              .sev-critical { border-left: 4px solid #ff4757; box-shadow: -4px 0 15px -5px rgba(255, 71, 87, 0.3); }
              .sev-high { border-left: 4px solid #ffa502; box-shadow: -4px 0 15px -5px rgba(255, 165, 2, 0.3); }
              .sev-medium { border-left: 4px solid #eccc68; box-shadow: -4px 0 15px -5px rgba(236, 204, 104, 0.3); }
              .sev-low { border-left: 4px solid #2ed573; box-shadow: -4px 0 15px -5px rgba(46, 213, 115, 0.3); }
              
              .text-neon-cyan { color: #00f5ff; text-shadow: 0 0 10px rgba(0, 245, 255, 0.5); }
              .badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.7rem; font-weight: bold; text-transform: uppercase; letter-spacing: 0.05em; }
              .hidden { display: none !important; }
          </style>
          <script>
              function filterSev(level) {
                  document.querySelectorAll('.f-card').forEach(c => {
                      c.classList.toggle('hidden', level !== 'all' && c.dataset.sev !== level);
                  });
              }
          </script>
      </head>
      <body class="p-8 antialiased">
          <div class="max-w-6xl mx-auto">
              <div class="glass-panel p-8 mb-8 flex justify-between items-center border-b-4 border-b-[#00f5ff]">
                  <div>
                      <h1 class="text-4xl font-black text-white tracking-wider mb-2">NEXUS <span class="text-neon-cyan">CORE</span></h1>
                      <p class="text-sm text-slate-400 font-mono tracking-widest uppercase">Automated Vulnerability Intelligence Report</p>
                  </div>
                  <div class="text-right">
                      <p class="text-xs text-slate-500 font-mono mb-1">TARGET REPOSITORY</p>
                      <p class="text-lg font-bold text-white bg-slate-800/50 px-4 py-2 rounded border border-slate-700 font-mono">${data.repo_name}</p>
                  </div>
              </div>

              <div class="flex gap-3 mb-6 font-mono text-sm">
                  <button onclick="filterSev('all')" class="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded transition border border-slate-600">ALL</button>
                  <button onclick="filterSev('critical')" class="px-5 py-2 bg-red-900/30 hover:bg-red-900/50 text-red-400 rounded transition border border-red-900/50">CRITICAL</button>
                  <button onclick="filterSev('high')" class="px-5 py-2 bg-orange-900/30 hover:bg-orange-900/50 text-orange-400 rounded transition border border-orange-900/50">HIGH</button>
                  <button onclick="filterSev('medium')" class="px-5 py-2 bg-yellow-900/30 hover:bg-yellow-900/50 text-yellow-400 rounded transition border border-yellow-900/50">MEDIUM</button>
              </div>

              <div class="grid grid-cols-4 gap-6 mb-10">
                  <div class="glass-panel p-6 text-center border-t-2 border-t-[#ff4757]">
                      <div class="text-[#ff4757] font-mono text-xs font-bold uppercase tracking-widest mb-2">Critical</div>
                      <div class="text-5xl font-display font-bold text-white">${counts.critical}</div>
                  </div>
                  <div class="glass-panel p-6 text-center border-t-2 border-t-[#ffa502]">
                      <div class="text-[#ffa502] font-mono text-xs font-bold uppercase tracking-widest mb-2">High</div>
                      <div class="text-5xl font-display font-bold text-white">${counts.high}</div>
                  </div>
                  <div class="glass-panel p-6 text-center border-t-2 border-t-[#eccc68]">
                      <div class="text-[#eccc68] font-mono text-xs font-bold uppercase tracking-widest mb-2">Medium</div>
                      <div class="text-5xl font-display font-bold text-white">${counts.medium}</div>
                  </div>
                  <div class="glass-panel p-6 text-center border-t-2 border-t-[#2ed573]">
                      <div class="text-[#2ed573] font-mono text-xs font-bold uppercase tracking-widest mb-2">Low</div>
                      <div class="text-5xl font-display font-bold text-white">${counts.low}</div>
                  </div>
              </div>

              <h2 class="text-2xl font-display font-bold text-white mb-6 flex items-center gap-3">
                  <span class="text-neon-cyan">/</span> DETAILED FINDINGS
              </h2>
              <div class="space-y-6">
                  ${cardsHtml}
              </div>
              
              <div class="mt-12 text-center text-xs text-slate-600 font-mono">
                  Generated autonomously by Nexus DevSecOps Agent • ${new Date().toUTCString()}
              </div>
          </div>
      </body>
      </html>`;

      const blob = new Blob([htmlString], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `Nexus_Audit_${data.repo_name}.html`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to fetch report", err);
    }
  };

  return (
    <div className="terminal-window flex flex-col h-full">
      <div className="terminal-header justify-between">
        <div className="flex items-center gap-2">
          <div className="terminal-dot" style={{ background: "#ff5f57" }} />
          <div className="terminal-dot" style={{ background: "#febc2e" }} />
          <div className="terminal-dot" style={{ background: "#28c840" }} />
          <div className="w-px h-3 bg-white/10 mx-1" />
          <TerminalIcon size={11} style={{ color: "#00f5ff" }} />
          <span style={{ fontFamily: "'Orbitron', monospace", fontSize: "0.6rem", letterSpacing: "0.1em", color: "#00f5ff" }}>
            NEXUS EXECUTION ENGINE
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <AnimatePresence>
            {(localScanning || isScanning) && (
              <motion.div initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.8 }} className="flex items-center gap-1.5 px-2 py-1 rounded" style={{ background: "rgba(255,71,87,0.1)", border: "1px solid rgba(255,71,87,0.3)" }}>
                <motion.div animate={{ scale: [1, 1.4, 1] }} transition={{ duration: 0.8, repeat: Infinity }} className="w-1.5 h-1.5 rounded-full" style={{ background: "#ff4757" }} />
                <span style={{ fontFamily: "'Orbitron', monospace", fontSize: "0.5rem", color: "#ff4757", letterSpacing: "0.1em" }}>SCANNING</span>
              </motion.div>
            )}
          </AnimatePresence>

          {auditId && (
            <button
              onClick={downloadHtmlReport}
              title="Download HTML Report"
              style={{ background: "rgba(0, 245, 255, 0.1)", border: "1px solid rgba(0, 245, 255, 0.3)", cursor: "pointer", color: "#00f5ff", padding: "3px 8px", borderRadius: "4px", display: "flex", alignItems: "center", gap: "4px", fontSize: "0.55rem", fontFamily: "'Orbitron', monospace", marginRight: "4px" }}
            >
              <FileText size={10} /> HTML REPORT
            </button>
          )}

          <button onClick={clearTerminal} title="Clear terminal" style={{ background: "transparent", border: "none", cursor: "pointer", color: "rgba(148,163,184,0.5)", padding: "4px", borderRadius: "4px", display: "flex", alignItems: "center" }}><Trash2 size={11} /></button>
          <button onClick={downloadLog} title="Download log" style={{ background: "transparent", border: "none", cursor: "pointer", color: "rgba(148,163,184,0.5)", padding: "4px", borderRadius: "4px", display: "flex", alignItems: "center" }}><Download size={11} /></button>
        </div>
      </div>

      <div className="terminal-output flex-1 overflow-y-auto min-h-0">
        <AnimatePresence initial={false}>
          {lines.map((line, i) => (
            <motion.div key={i} initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.15 }} style={{ display: "flex", gap: "4px", paddingBottom: "1px", alignItems: "flex-start" }}>
              <ChevronRight size={10} style={{ color: "rgba(0,245,255,0.3)", marginTop: "3px", flexShrink: 0 }} />
              <span style={{ wordBreak: "break-all" }}>{colorize(line)}</span>
            </motion.div>
          ))}
        </AnimatePresence>
        {(localScanning || isScanning) && (
          <motion.div className="flex items-center gap-1 mt-1" style={{ color: "#00f5ff", fontFamily: "'JetBrains Mono', monospace", fontSize: "0.7rem" }}>
            <ChevronRight size={10} style={{ color: "rgba(0,245,255,0.3)" }} />
            <span style={{ color: "rgba(148,163,184,0.5)" }}>nexus@scanner:~$</span>
            <motion.span animate={{ opacity: [1, 0, 1] }} transition={{ duration: 0.6, repeat: Infinity }} style={{ display: "inline-block", width: "6px", height: "12px", background: "#00f5ff", borderRadius: "1px" }} />
          </motion.div>
        )}
        <div ref={bottomRef} />
      </div>

      <div className="px-3 py-2.5 border-t" style={{ borderColor: "rgba(0,245,255,0.08)" }}>
        <div className="flex gap-2 items-center">
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.65rem", color: "rgba(0,245,255,0.5)", flexShrink: 0 }}>$</span>
          <input value={localRepoUrl} onChange={(e) => setLocalRepoUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && startScan()} placeholder="github.com/user/repo" style={{ flex: 1, background: "transparent", border: "none", outline: "none", fontFamily: "'JetBrains Mono', monospace", fontSize: "0.65rem", color: "#a4b0be", minWidth: 0 }} />
          {localScanning ? (
            <button onClick={stopScan} title="Stop scan"><Square size={11} style={{ color: "#ff4757", cursor: "pointer" }} /></button>
          ) : (
            <button onClick={startScan} title="Start scan"><Play size={11} style={{ color: "#2ed573", cursor: "pointer" }} /></button>
          )}
        </div>
      </div>
    </div>
  );
}
