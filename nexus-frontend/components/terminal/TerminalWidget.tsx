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

  // ─── PREMIUM HTML REPORT GENERATOR ───
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

      const cardsHtml = findings.map((f: any) => {
        const sev = (f.severity || "low").toLowerCase();
        
        // Semantic color mapping for UI elements
        let badgeStyle = "bg-green-100 text-green-800 border-green-200";
        let cardBorder = "border-l-[6px] border-l-green-500";
        let iconColor = "text-green-500";
        
        if (sev === "critical") {
          badgeStyle = "bg-red-100 text-red-800 border-red-200";
          cardBorder = "border-l-[6px] border-l-red-600";
          iconColor = "text-red-600";
        } else if (sev === "high") {
          badgeStyle = "bg-orange-100 text-orange-800 border-orange-200";
          cardBorder = "border-l-[6px] border-l-orange-500";
          iconColor = "text-orange-500";
        } else if (sev === "medium") {
          badgeStyle = "bg-yellow-100 text-yellow-800 border-yellow-200";
          cardBorder = "border-l-[6px] border-l-yellow-400";
          iconColor = "text-yellow-500";
        }

        return `
        <div class="f-card bg-white rounded-xl shadow-sm border border-slate-200 ${cardBorder} overflow-hidden mb-6 transition-all hover:shadow-md" data-sev="${sev}">
            <div class="p-6 border-b border-slate-100 bg-slate-50/50 flex justify-between items-center">
                <div class="flex items-center gap-3">
                    <svg class="w-6 h-6 ${iconColor}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                    <h3 class="text-xl font-bold text-slate-800 m-0">${f.title || 'Unknown Finding'}</h3>
                </div>
                <span class="px-3 py-1 text-xs font-bold uppercase tracking-wider rounded-full border ${badgeStyle}">${sev}</span>
            </div>
            
            <div class="p-6">
                <p class="text-slate-600 text-sm leading-relaxed mb-6">${f.description || 'No description provided.'}</p>
                
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="bg-slate-900 rounded-lg overflow-hidden flex flex-col">
                        <div class="bg-slate-800 px-4 py-2 flex items-center gap-2 border-b border-slate-700">
                            <div class="w-3 h-3 rounded-full bg-red-500"></div>
                            <span class="text-xs text-slate-300 font-mono uppercase tracking-wider">Proof of Concept</span>
                        </div>
                        <div class="p-4 overflow-x-auto flex-1">
                            <code class="text-sm text-pink-400 font-mono whitespace-pre-wrap">${f.poc || 'N/A'}</code>
                        </div>
                    </div>
                    
                    <div class="bg-slate-900 rounded-lg overflow-hidden flex flex-col">
                        <div class="bg-slate-800 px-4 py-2 flex items-center gap-2 border-b border-slate-700">
                            <div class="w-3 h-3 rounded-full bg-green-500"></div>
                            <span class="text-xs text-slate-300 font-mono uppercase tracking-wider">Remediation Guide</span>
                        </div>
                        <div class="p-4 overflow-x-auto flex-1">
                            <code class="text-sm text-emerald-400 font-mono whitespace-pre-wrap">${f.fix || 'N/A'}</code>
                        </div>
                    </div>
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
          <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
          <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
          <style>
              body { font-family: 'Inter', sans-serif; background-color: #f8fafc; color: #334155; }
              .font-mono { font-family: 'JetBrains Mono', monospace; }
              .bg-grid-pattern {
                  background-image: linear-gradient(to right, #e2e8f0 1px, transparent 1px), linear-gradient(to bottom, #e2e8f0 1px, transparent 1px);
                  background-size: 24px 24px;
              }
              .hidden-card { display: none !important; }
          </style>
          <script>
              function filterSev(level, btnElement) {
                  // Toggle cards
                  document.querySelectorAll('.f-card').forEach(c => {
                      if (level === 'all') {
                          c.classList.remove('hidden-card');
                      } else {
                          c.classList.toggle('hidden-card', c.dataset.sev !== level);
                      }
                  });
                  
                  // Update active button styling
                  document.querySelectorAll('.filter-btn').forEach(b => {
                      b.classList.remove('ring-2', 'ring-offset-2', 'ring-slate-400');
                  });
                  btnElement.classList.add('ring-2', 'ring-offset-2', 'ring-slate-400');
              }
          </script>
      </head>
      <body class="antialiased min-h-screen pb-12">
          
          <div class="bg-slate-900 text-white w-full py-4 px-8 shadow-md">
              <div class="max-w-7xl mx-auto flex justify-between items-center">
                  <div class="flex items-center gap-3">
                      <div class="w-8 h-8 rounded bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center font-bold text-white shadow-lg shadow-cyan-500/30">N</div>
                      <h1 class="text-xl font-bold tracking-tight">NEXUS <span class="text-cyan-400 font-normal">DevSecOps Engine</span></h1>
                  </div>
                  <div class="text-right flex items-center gap-4">
                      <div class="text-sm text-slate-400 border-r border-slate-700 pr-4">
                          Generated: <span class="text-white font-mono">${new Date().toLocaleString()}</span>
                      </div>
                      <div class="text-sm font-medium bg-slate-800 px-3 py-1 rounded border border-slate-700">
                          CONFIDENTIAL
                      </div>
                  </div>
              </div>
          </div>

          <div class="max-w-7xl mx-auto px-8 mt-10">
              
              <div class="bg-white rounded-2xl shadow-sm border border-slate-200 p-8 mb-10 bg-grid-pattern relative overflow-hidden">
                  <div class="absolute inset-0 bg-white/80 backdrop-blur-[2px]"></div>
                  
                  <div class="relative z-10 flex flex-col md:flex-row gap-8 items-center">
                      <div class="flex-1">
                          <h2 class="text-xs font-bold text-slate-400 uppercase tracking-widest mb-1">Target Repository</h2>
                          <p class="text-3xl font-bold text-slate-800 mb-6 font-mono">${data.repo_name}</p>
                          <p class="text-slate-600 mb-6 max-w-xl">
                              This executive report details the security vulnerabilities discovered during the automated static and software composition analysis. Vulnerabilities are categorized by severity based on potential business impact.
                          </p>
                          
                          <div class="flex gap-2">
                              <button onclick="filterSev('all', this)" class="filter-btn ring-2 ring-offset-2 ring-slate-400 px-6 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-sm font-semibold rounded-lg transition-all border border-slate-300 shadow-sm">All Findings</button>
                              <button onclick="filterSev('critical', this)" class="filter-btn px-6 py-2 bg-red-50 hover:bg-red-100 text-red-700 text-sm font-semibold rounded-lg transition-all border border-red-200 shadow-sm">Critical</button>
                              <button onclick="filterSev('high', this)" class="filter-btn px-6 py-2 bg-orange-50 hover:bg-orange-100 text-orange-700 text-sm font-semibold rounded-lg transition-all border border-orange-200 shadow-sm">High</button>
                          </div>
                      </div>
                      
                      <div class="w-full md:w-auto bg-slate-50 p-6 rounded-xl border border-slate-200 shadow-inner flex items-center gap-8">
                          <div class="w-40 h-40">
                              <canvas id="severityChart"></canvas>
                          </div>
                          <div class="flex flex-col gap-3 min-w-[120px]">
                              <div class="flex justify-between items-center"><span class="text-sm font-medium text-slate-600 flex items-center gap-2"><div class="w-2 h-2 rounded-full bg-red-600"></div>Critical</span> <span class="font-bold text-slate-800">${counts.critical}</span></div>
                              <div class="flex justify-between items-center"><span class="text-sm font-medium text-slate-600 flex items-center gap-2"><div class="w-2 h-2 rounded-full bg-orange-500"></div>High</span> <span class="font-bold text-slate-800">${counts.high}</span></div>
                              <div class="flex justify-between items-center"><span class="text-sm font-medium text-slate-600 flex items-center gap-2"><div class="w-2 h-2 rounded-full bg-yellow-400"></div>Medium</span> <span class="font-bold text-slate-800">${counts.medium}</span></div>
                              <div class="flex justify-between items-center"><span class="text-sm font-medium text-slate-600 flex items-center gap-2"><div class="w-2 h-2 rounded-full bg-green-500"></div>Low</span> <span class="font-bold text-slate-800">${counts.low}</span></div>
                          </div>
                      </div>
                  </div>
              </div>

              <h2 class="text-xl font-bold text-slate-800 mb-6 flex items-center gap-2">
                  <svg class="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"></path></svg>
                  Detailed Vulnerability Breakdown
              </h2>
              
              <div class="space-y-2">
                  ${cardsHtml}
              </div>
              
              <div class="mt-16 pt-8 border-t border-slate-200 text-center text-sm text-slate-500">
                  <p>Automated security intelligence provided by the <strong>Nexus Core System</strong>.</p>
                  <p class="mt-1 opacity-70">Strictly confidential. Unauthorized distribution is prohibited.</p>
              </div>
          </div>

          <script>
              document.addEventListener('DOMContentLoaded', function() {
                  const ctx = document.getElementById('severityChart');
                  new Chart(ctx, {
                      type: 'doughnut',
                      data: {
                          labels: ['Critical', 'High', 'Medium', 'Low'],
                          datasets: [{
                              data: [${counts.critical}, ${counts.high}, ${counts.medium}, ${counts.low}],
                              backgroundColor: [
                                  '#dc2626', // red-600
                                  '#f97316', // orange-500
                                  '#facc15', // yellow-400
                                  '#22c55e'  // green-500
                              ],
                              borderWidth: 0,
                              hoverOffset: 4
                          }]
                      },
                      options: {
                          responsive: true,
                          cutout: '75%',
                          plugins: {
                              legend: {
                                  display: false // We built a custom legend next to it
                              },
                              tooltip: {
                                  callbacks: {
                                      label: function(context) {
                                          return ' ' + context.label + ': ' + context.raw;
                                      }
                                  }
                              }
                          }
                      }
                  });
              });
          </script>
      </body>
      </html>`;

      const blob = new Blob([htmlString], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `Nexus_Security_Audit_${data.repo_name}.html`;
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
              title="Download Executive HTML Report"
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
