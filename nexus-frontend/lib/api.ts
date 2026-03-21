import axios from "axios";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface ScanRequest {
  repo_url: string;
  webhook_url?: string;
}

/**
 * Core terminal line type.
 * Note: the backend also emits `pdf_ready` and `pdf_error` events.
 * Those share this shape but carry extra fields — the TerminalWidget
 * reads them via the raw object cast pattern.
 */
export interface TerminalLine {
  type: "info" | "critical" | "warning" | "success" | "debug" | "prompt";
  content: string;
  timestamp?: string;
}

/** Extended event emitted when the backend PDF signal fires */
export interface PdfReadyEvent extends TerminalLine {
  type: never;       // not a normal TerminalLine type
  _type: "pdf_ready";
  report_id: number;
}

export interface PdfErrorEvent extends TerminalLine {
  type: never;
  _type: "pdf_error";
  error_message: string;
  repo_name: string;
  stage: string;
}

// ─── Standard REST client ─────────────────────────────────────────────────────
export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 60_000,
  headers: { "Content-Type": "application/json" },
});

// ─── Streaming Chat via SSE ───────────────────────────────────────────────────
export function streamChat(
  messages: ChatMessage[],
  onChunk: (chunk: string) => void,
  onDone: () => void,
  onError: (err: Error) => void
): AbortController {
  const controller = new AbortController();

  (async () => {
    try {
      const response = await fetch(`${BASE_URL}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const reader  = response.body?.getReader();
      const decoder = new TextDecoder("utf-8");
      if (!reader) throw new Error("Response body is null");

      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            const payload = line.slice(6).trim();
            if (payload === "[DONE]") { onDone(); return; }
            if (payload) onChunk(payload.replace(/\\n/g, "\n"));
          }
        }
      }
      onDone();
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") return;
      onError(err instanceof Error ? err : new Error(String(err)));
    }
  })();

  return controller;
}

// ─── Scan REST helpers ────────────────────────────────────────────────────────
export const scanRepo        = (payload: ScanRequest) => apiClient.post("/scan", payload);
export const getScanHistory  = ()                      => apiClient.get("/history");
export const getScanReport   = (id: number)            => apiClient.get(`/report/${id}`);

// ─── Streaming Terminal Output ────────────────────────────────────────────────
/**
 * Connects to /scan/stream.
 *
 * Special events the callback may receive (cast the raw object):
 *   { type: "pdf_ready", report_id: number, ... }
 *   { type: "pdf_error",  error_message: string, repo_name: string, stage: string, ... }
 *
 * These are passed through onLine so the component can handle them
 * without adding a new callback signature.
 */
export function streamScan(
  repoUrl: string,
  onLine: (line: TerminalLine) => void,
  onDone: () => void,
  onError: (err: Error) => void
): AbortController {
  const controller = new AbortController();

  (async () => {
    try {
      const response = await fetch(`${BASE_URL}/scan/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: repoUrl }),
        signal: controller.signal,
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const reader  = response.body?.getReader();
      const decoder = new TextDecoder();
      if (!reader) throw new Error("No response body");

      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const raw of lines) {
          if (!raw.startsWith("data: ")) continue;
          const payload = raw.slice(6).trim();
          if (payload === "[DONE]") { onDone(); return; }

          try {
            // Parse every event as JSON.
            // Normal events have { type, content, timestamp }.
            // Special events additionally have { report_id } or { error_message, stage }.
            // We pass all of them through onLine — the component checks the type field.
            const parsed = JSON.parse(payload);
            onLine(parsed as TerminalLine);
          } catch {
            // Fallback for any non-JSON data line
            onLine({ type: "info", content: payload });
          }
        }
      }
      onDone();
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") return;
      onError(err instanceof Error ? err : new Error(String(err)));
    }
  })();

  return controller;
}
