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

export interface TerminalLine {
  type: "info" | "critical" | "warning" | "success" | "debug" | "prompt";
  content: string;
  timestamp?: string;
}

// ─── Standard REST client ────────────────────────────────────
export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 60000,
  headers: {
    "Content-Type": "application/json",
  },
});

// ─── Streaming Chat via SSE ──────────────────────────────────
/**
 * Sends a chat message to /chat and streams the response back
 * via Server-Sent Events.
 *
 * @param messages  Full conversation history
 * @param onChunk   Callback for each streamed text chunk
 * @param onDone    Callback when the stream is complete
 * @param onError   Callback on error
 * @returns AbortController — call .abort() to cancel the stream
 *
 * Backend contract (FastAPI):
 *   POST /chat
 *   Body: { messages: ChatMessage[] }
 *   Response: text/event-stream
 *   Each event: data: <chunk>\n\n
 *   End event:  data: [DONE]\n\n
 */
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

      const reader = response.body?.getReader();
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
            if (payload === "[DONE]") {
              onDone();
              return;
            }
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

// ─── Scan Endpoints ──────────────────────────────────────────
export const scanRepo = (payload: ScanRequest) =>
  apiClient.post("/scan", payload);

export const getScanHistory = () => apiClient.get("/history");

export const getScanReport = (id: number) => apiClient.get(`/report/${id}`);

// ─── Streaming Terminal Output ───────────────────────────────
/**
 * Connects to /scan/stream for real-time terminal output
 * during a repository scan.
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

      const reader = response.body?.getReader();
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
            const parsed: TerminalLine = JSON.parse(payload);
            onLine(parsed);
          } catch {
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
