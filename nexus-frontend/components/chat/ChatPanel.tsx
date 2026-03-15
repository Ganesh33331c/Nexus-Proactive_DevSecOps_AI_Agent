"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Send, Shield, User, Cpu, RotateCcw } from "lucide-react";
import { streamChat, ChatMessage } from "@/lib/api";
import TemporalLoader from "./TemporalLoader";
import ReactMarkdown from "react-markdown";

const WELCOME: ChatMessage = {
  role: "assistant",
  content:
    "NEXUS ONLINE. I am your autonomous DevSecOps AI. Submit a repository URL or ask me anything about vulnerabilities, OWASP threats, CVEs, or secure code patterns. How can I assist your security mission today?",
};

const SUGGESTIONS = [
  "Scan github.com/user/repo for critical CVEs",
  "Explain SQL injection with a PoC example",
  "What is OWASP Top 10 for 2024?",
  "How do I remediate XSS in React?",
];

export default function ChatPanel() {
  const [messages, setMessages] = useState<ChatMessage[]>([WELCOME]);
  const [input, setInput] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMessage = useCallback(
    (text: string) => {
      if (!text.trim() || isStreaming) return;

      const userMsg: ChatMessage = { role: "user", content: text.trim() };
      const history = [...messages, userMsg];
      setMessages(history);
      setInput("");
      setIsStreaming(true);

      // Placeholder for streaming response
      const assistantMsg: ChatMessage = { role: "assistant", content: "" };
      setMessages((prev) => [...prev, assistantMsg]);

      abortRef.current = streamChat(
        history,
        (chunk) => {
          setMessages((prev) => {
            const updated = [...prev];
            updated[updated.length - 1] = {
              role: "assistant",
              content: updated[updated.length - 1].content + chunk,
            };
            return updated;
          });
        },
        () => setIsStreaming(false),
        (err) => {
          setMessages((prev) => {
            const updated = [...prev];
            updated[updated.length - 1] = {
              role: "assistant",
              content: `⚠ Connection error: ${err.message}. Ensure FastAPI backend is running on localhost:8000.`,
            };
            return updated;
          });
          setIsStreaming(false);
        }
      );
    },
    [messages, isStreaming]
  );

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  };

  const handleReset = () => {
    abortRef.current?.abort();
    setMessages([WELCOME]);
    setIsStreaming(false);
    setInput("");
  };

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 120)}px`;
    }
  }, [input]);

  return (
    <div className="flex flex-col h-full">
      {/* ─── Header ─── */}
      <div className="px-5 py-4 flex items-center justify-between border-b border-white/5">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{
                background:
                  "linear-gradient(135deg, rgba(0,245,255,0.15), rgba(168,85,247,0.15))",
                border: "1px solid rgba(0,245,255,0.3)",
              }}
            >
              <Cpu size={14} className="text-cyan-400" />
            </div>
            <div
              className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-emerald-400"
              style={{ boxShadow: "0 0 6px #34d399" }}
            />
          </div>
          <div>
            <p
              style={{
                fontFamily: "'Orbitron', monospace",
                fontSize: "0.7rem",
                letterSpacing: "0.1em",
                color: "#00f5ff",
              }}
            >
              NEXUS AI
            </p>
            <div className="badge-online" style={{ fontSize: "0.55rem" }}>
              OPERATIONAL
            </div>
          </div>
        </div>

        <button
          onClick={handleReset}
          className="btn-cyber flex items-center gap-1.5"
          title="Reset conversation"
        >
          <RotateCcw size={10} />
          RESET
        </button>
      </div>

      {/* ─── Message List ─── */}
      <div className="flex-1 overflow-y-auto px-4 py-4 space-y-3 min-h-0">
        <AnimatePresence initial={false}>
          {messages.map((msg, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25 }}
              className={`flex gap-3 ${
                msg.role === "user" ? "flex-row-reverse" : "flex-row"
              }`}
            >
              {/* Avatar */}
              <div
                className="w-7 h-7 rounded-full flex-shrink-0 flex items-center justify-center mt-1"
                style={{
                  background:
                    msg.role === "assistant"
                      ? "linear-gradient(135deg, rgba(168,85,247,0.3), rgba(0,245,255,0.2))"
                      : "linear-gradient(135deg, rgba(0,245,255,0.2), rgba(0,245,255,0.1))",
                  border:
                    msg.role === "assistant"
                      ? "1px solid rgba(168,85,247,0.4)"
                      : "1px solid rgba(0,245,255,0.3)",
                }}
              >
                {msg.role === "assistant" ? (
                  <Shield size={12} className="text-violet-400" />
                ) : (
                  <User size={12} className="text-cyan-400" />
                )}
              </div>

              {/* Bubble */}
              <div
                className={`max-w-[80%] px-4 py-3 text-sm leading-relaxed ${
                  msg.role === "user" ? "msg-user" : "msg-nexus"
                }`}
                style={{
                  fontFamily: "'Exo 2', sans-serif",
                  color: "#cbd5e1",
                  fontSize: "0.8rem",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                <div className="prose-sm max-w-none">
  <ReactMarkdown>{msg.content}</ReactMarkdown>
</div>
                {/* Streaming cursor on last assistant message */}
                {msg.role === "assistant" &&
                  i === messages.length - 1 &&
                  isStreaming && (
                    <motion.span
                      animate={{ opacity: [1, 0, 1] }}
                      transition={{ duration: 0.6, repeat: Infinity }}
                      style={{
                        display: "inline-block",
                        width: "5px",
                        height: "11px",
                        background: "#a855f7",
                        borderRadius: "1px",
                        marginLeft: "3px",
                        verticalAlign: "middle",
                      }}
                    />
                  )}
              </div>
            </motion.div>
          ))}
        </AnimatePresence>

        {/* Temporal Loader below messages when streaming starts */}
        {isStreaming && messages[messages.length - 1]?.content === "" && (
          <div className="px-10">
            <TemporalLoader visible={true} />
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* ─── Suggestions ─── */}
      <AnimatePresence>
        {messages.length === 1 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="px-4 pb-2 flex flex-wrap gap-2"
          >
            {SUGGESTIONS.map((s, i) => (
              <button
                key={i}
                onClick={() => sendMessage(s)}
                className="glass-card px-3 py-1.5 text-left transition-all"
                style={{
                  fontSize: "0.65rem",
                  color: "rgba(0,245,255,0.7)",
                  fontFamily: "'Exo 2', sans-serif",
                  cursor: "pointer",
                }}
              >
                {s}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ─── Input Bar ─── */}
      <div className="px-4 pb-4 pt-2">
        <div
          className="flex items-end gap-2 p-2 rounded-xl"
          style={{
            background: "rgba(6,13,26,0.9)",
            border: "1px solid rgba(0,245,255,0.2)",
            boxShadow: isStreaming
              ? "0 0 15px rgba(0,245,255,0.1)"
              : "none",
            transition: "box-shadow 0.3s ease",
          }}
        >
          <textarea
            ref={textareaRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask Nexus about vulnerabilities, CVEs, or enter a repo URL..."
            disabled={isStreaming}
            rows={1}
            style={{
              flex: 1,
              background: "transparent",
              border: "none",
              outline: "none",
              color: "#e2e8f0",
              fontFamily: "'Exo 2', sans-serif",
              fontSize: "0.8rem",
              lineHeight: "1.5",
              resize: "none",
              padding: "6px 8px",
            }}
          />
          <button
            onClick={() => sendMessage(input)}
            disabled={!input.trim() || isStreaming}
            className="btn-send p-2.5 flex items-center justify-center flex-shrink-0 disabled:opacity-30 disabled:cursor-not-allowed"
            style={{ borderRadius: "8px" }}
          >
            <Send size={14} className="text-cyan-400" />
          </button>
        </div>
        <p
          className="text-center mt-2"
          style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "0.55rem",
            color: "rgba(148,163,184,0.3)",
            letterSpacing: "0.05em",
          }}
        >
          SHIFT+ENTER for newline · ENTER to send · Powered by Gemini
        </p>
      </div>
    </div>
  );
}
