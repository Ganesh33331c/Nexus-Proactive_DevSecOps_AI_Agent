"use client";

import React, { useRef } from "react";
import { motion } from "framer-motion";
import { X, Download, ShieldAlert } from "lucide-react";

// Matches the Python Pydantic Schema
export interface Vulnerability {
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  file_path: string;
  poc: string;
  remediation: string;
}

export interface ReportData {
  scan_status: string;
  critical_count: number;
  vulnerabilities: Vulnerability[];
}

interface ReportViewerProps {
  data: ReportData;
  repoName: string;
  onClose: () => void;
}

export default function ReportViewer({ data, repoName, onClose }: ReportViewerProps) {
  const reportRef = useRef<HTMLDivElement>(null);

  // ─── DOM TO HTML DOWNLOAD UTILITY ───
  const handleDownload = () => {
    if (!reportRef.current) return;

    // Grab the inner HTML of the report container
    const content = reportRef.current.innerHTML;

    // Wrap it in a standalone HTML boilerplate with Tailwind CDN for offline styling
    const htmlString = `
      <!DOCTYPE html>
      <html lang="en" class="dark">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Nexus Security Audit | ${repoName}</title>
          <script src="https://cdn.tailwindcss.com"></script>
          <style>
            body { background-color: #020617; color: #f8fafc; font-family: sans-serif; padding: 2rem; }
            .glass-panel { background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(255,255,255,0.1); border-radius: 1rem; padding: 1.5rem; }
            pre { background: #000; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
          </style>
      </head>
      <body>
          <div class="max-w-5xl mx-auto">
             ${content}
          </div>
      </body>
      </html>
    `;

    const blob = new Blob([htmlString], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `Nexus_Audit_${repoName.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.html`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical": return "text-red-500 border-red-500/30 bg-red-500/10";
      case "high": return "text-orange-500 border-orange-500/30 bg-orange-500/10";
      case "medium": return "text-yellow-400 border-yellow-400/30 bg-yellow-400/10";
      default: return "text-emerald-400 border-emerald-400/30 bg-emerald-400/10";
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 20 }}
      className="fixed inset-0 z-[100] flex flex-col bg-slate-950/95 backdrop-blur-md overflow-hidden"
    >
      {/* Fixed Header */}
      <div className="flex justify-between items-center p-6 border-b border-white/10 bg-slate-900/50">
        <div className="flex items-center gap-3">
          <ShieldAlert className="text-cyan-400 h-6 w-6" />
          <h1 className="text-xl font-bold text-white tracking-widest">
            NEXUS <span className="text-cyan-400">AUDIT</span>
          </h1>
        </div>
        <div className="flex items-center gap-4">
          <button
            onClick={handleDownload}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded-md hover:bg-cyan-500/20 transition-all font-bold text-sm"
          >
            <Download size={16} /> EXPORT HTML
          </button>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors">
            <X size={24} />
          </button>
        </div>
      </div>

      {/* Scrollable Report Content (This ref is what gets exported) */}
      <div className="flex-1 overflow-y-auto p-6 md:p-12">
        <div ref={reportRef} className="max-w-5xl mx-auto space-y-8">
          
          {/* Executive Summary */}
          <div className="glass-panel p-8 rounded-2xl border border-white/10 bg-slate-900/40">
            <h2 className="text-2xl font-bold text-white mb-4">Executive Summary</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-4 bg-slate-950 rounded-lg border border-white/5">
                <p className="text-slate-400 text-xs uppercase tracking-wider mb-1">Target</p>
                <p className="text-white font-mono text-sm truncate">{repoName}</p>
              </div>
              <div className="p-4 bg-slate-950 rounded-lg border border-white/5">
                <p className="text-slate-400 text-xs uppercase tracking-wider mb-1">Status</p>
                <p className="text-emerald-400 font-bold">{data.scan_status}</p>
              </div>
              <div className="p-4 bg-red-950/30 rounded-lg border border-red-500/20">
                <p className="text-red-400 text-xs uppercase tracking-wider mb-1">Critical Risks</p>
                <p className="text-red-500 font-bold text-2xl">{data.critical_count}</p>
              </div>
              <div className="p-4 bg-slate-950 rounded-lg border border-white/5">
                <p className="text-slate-400 text-xs uppercase tracking-wider mb-1">Total Findings</p>
                <p className="text-white font-bold text-2xl">{data.vulnerabilities.length}</p>
              </div>
            </div>
          </div>

          {/* Vulnerability Mapping */}
          <h3 className="text-xl font-bold text-white border-b border-white/10 pb-2 mt-12 mb-6">Detailed Findings</h3>
          
          <div className="space-y-6">
            {data.vulnerabilities.map((vuln, idx) => (
              <div key={idx} className="glass-panel p-6 rounded-xl border border-white/10 bg-slate-900/40">
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h4 className="text-lg font-bold text-white mb-1">{vuln.title}</h4>
                    <p className="text-xs text-slate-400 font-mono">Location: {vuln.file_path}</p>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase border ${getSeverityColor(vuln.severity)}`}>
                    {vuln.severity}
                  </span>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
                  <div className="bg-slate-950 p-4 rounded-lg border border-white/5">
                    <p className="text-xs text-pink-400 font-bold uppercase tracking-widest mb-2">Proof of Concept</p>
                    <pre className="text-sm text-slate-300 font-mono whitespace-pre-wrap">{vuln.poc}</pre>
                  </div>
                  <div className="bg-slate-950 p-4 rounded-lg border border-white/5">
                    <p className="text-xs text-emerald-400 font-bold uppercase tracking-widest mb-2">Remediation</p>
                    <pre className="text-sm text-slate-300 font-mono whitespace-pre-wrap">{vuln.remediation}</pre>
                  </div>
                </div>
              </div>
            ))}
          </div>

        </div>
      </div>
    </motion.div>
  );
}
