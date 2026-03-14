"use client";

import { motion } from "framer-motion";
import { Shield, Activity, Database, Zap } from "lucide-react";

const STATS = [
  { label: "THREATS DETECTED", value: "2,847", icon: Shield, color: "#ff4757" },
  { label: "REPOS SCANNED", value: "1,204", icon: Database, color: "#00f5ff" },
  { label: "UPTIME", value: "99.9%", icon: Activity, color: "#2ed573" },
  { label: "AI QUERIES", value: "48.2K", icon: Zap, color: "#a855f7" },
];

export default function TopNav() {
  return (
    <motion.header
      initial={{ y: -20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.5, ease: "easeOut" }}
      className="flex-shrink-0 flex items-center justify-between px-6 py-3"
      style={{
        background: "rgba(6,13,26,0.9)",
        backdropFilter: "blur(20px)",
        borderBottom: "1px solid rgba(0,245,255,0.08)",
        height: "56px",
      }}
    >
      {/* Logo */}
      <div className="flex items-center gap-3">
        <motion.div
          animate={{ rotate: [0, 360] }}
          transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
          style={{
            width: "28px",
            height: "28px",
            borderRadius: "6px",
            background: "linear-gradient(135deg, rgba(0,245,255,0.2), rgba(168,85,247,0.3))",
            border: "1px solid rgba(0,245,255,0.3)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Shield size={14} style={{ color: "#00f5ff" }} />
        </motion.div>

        <div>
          <div className="flex items-baseline gap-2">
            <span
              style={{
                fontFamily: "'Orbitron', monospace",
                fontWeight: 900,
                fontSize: "1rem",
                letterSpacing: "0.15em",
                background: "linear-gradient(135deg, #00f5ff 0%, #a855f7 100%)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                backgroundClip: "text",
              }}
            >
              NEXUS
            </span>
            <span
              style={{
                fontFamily: "'Exo 2', sans-serif",
                fontSize: "0.55rem",
                letterSpacing: "0.12em",
                color: "rgba(148,163,184,0.5)",
                fontWeight: 600,
                textTransform: "uppercase",
              }}
            >
              DevSecOps Agent
            </span>
          </div>
        </div>

        {/* Divider */}
        <div
          style={{
            width: "1px",
            height: "20px",
            background:
              "linear-gradient(180deg, transparent, rgba(0,245,255,0.3), transparent)",
            margin: "0 4px",
          }}
        />

        {/* Status */}
        <div className="badge-online" style={{ fontSize: "0.55rem" }}>
          ONLINE
        </div>
      </div>

      {/* Stats */}
      <div className="hidden md:flex items-center gap-2">
        {STATS.map(({ label, value, icon: Icon, color }, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 * i + 0.3 }}
            className="stat-card flex items-center gap-2"
          >
            <Icon size={10} style={{ color, flexShrink: 0 }} />
            <div>
              <div
                style={{
                  fontFamily: "'Orbitron', monospace",
                  fontSize: "0.65rem",
                  fontWeight: 700,
                  color,
                  lineHeight: 1,
                }}
              >
                {value}
              </div>
              <div
                style={{
                  fontFamily: "'Exo 2', sans-serif",
                  fontSize: "0.45rem",
                  color: "rgba(148,163,184,0.4)",
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  marginTop: "2px",
                }}
              >
                {label}
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Version tag */}
      <div
        style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: "0.55rem",
          color: "rgba(0,245,255,0.3)",
          letterSpacing: "0.06em",
          border: "1px solid rgba(0,245,255,0.1)",
          padding: "3px 8px",
          borderRadius: "4px",
          background: "rgba(0,245,255,0.03)",
        }}
      >
        v2.4.1-alpha
      </div>
    </motion.header>
  );
}
