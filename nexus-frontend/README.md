# NEXUS Frontend — Next.js DevSecOps UI

> **Midnight Cyber** aesthetic · Split-screen workspace · Streaming AI chat · Real-time terminal

## 🚀 Quick Start

```bash
cd nexus-frontend

# 1. Install dependencies
npm install

# 2. (Optional) create .env.local to point at your FastAPI backend
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local

# 3. Start dev server
npm run dev
```

Open **http://localhost:3000**.

---

## 📁 Project Structure

```
nexus-frontend/
├── app/
│   ├── globals.css          # Glassmorphism 2.0, cyber grid, custom scrollbars
│   ├── layout.tsx           # Root layout + Google Fonts (Orbitron, JetBrains Mono, Exo 2)
│   └── page.tsx             # ← MAIN PAGE: split-screen workspace
│
├── components/
│   ├── chat/
│   │   ├── ChatPanel.tsx    # Conversational AI chat (streaming SSE)
│   │   └── TemporalLoader.tsx # Glowing text wave loading animation (Framer Motion)
│   ├── terminal/
│   │   └── TerminalWidget.tsx # Syntax-highlighted terminal output
│   ├── ui/
│   │   └── NexusCorePanel.tsx # Spline 3D iframe + animated SVG fallback
│   └── layout/
│       └── TopNav.tsx       # Header with live stats
│
└── lib/
    └── api.ts               # Axios client + streamChat() + streamScan() SSE utilities
```

---

## 🔌 Backend Integration (`lib/api.ts`)

The frontend connects to your **FastAPI** backend on `http://localhost:8000`.

### Required endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/chat` | Stream chat response (SSE) |
| `POST` | `/scan` | Trigger repo scan |
| `POST` | `/scan/stream` | Stream terminal scan output (SSE) |
| `GET`  | `/history` | Fetch audit history |
| `GET`  | `/report/:id` | Fetch specific report |

### SSE Event Format (FastAPI)

```python
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
import asyncio

@app.post("/chat")
async def chat(body: dict):
    async def stream():
        for chunk in your_gemini_stream(body["messages"]):
            yield f"data: {chunk}\n\n"
        yield "data: [DONE]\n\n"
    return StreamingResponse(stream(), media_type="text/event-stream")
```

---

## 🎨 Design System

### Fonts (loaded via Google Fonts)
- **Orbitron** — headings, labels, monospace UI elements
- **JetBrains Mono** — terminal output, code
- **Exo 2** — body text, chat bubbles

### Color Palette
| Token | Hex | Usage |
|-------|-----|-------|
| `--cyan-neon` | `#00f5ff` | Primary accent, borders, scan active |
| `--violet-neon` | `#a855f7` | AI response bubbles, secondary |
| `--void-900` | `#060d1a` | Background panels |
| `#ff4757` | red | CRITICAL findings |
| `#ffa502` | orange | WARNING |
| `#2ed573` | green | SUCCESS / SAFE |

### Glassmorphism classes
```css
.glass-panel  /* Full frosted panel — main containers */
.glass-card   /* Lighter card — suggestions, stats */
.cyber-input  /* Form inputs with cyan glow */
.btn-cyber    /* Orbitron uppercase buttons */
.btn-send     /* Pulsing send button */
```

---

## 🌐 Embedding Your Spline 3D Core

1. Create your scene at [spline.design](https://spline.design)
2. Export → "Embed on website" → copy the iframe URL
3. Open `app/page.tsx` and set:

```ts
const SPLINE_URL = "https://my.spline.design/your-scene-id/";
```

The animated SVG fallback renders automatically when no URL is provided.

---

## 🔧 Environment Variables

```bash
# .env.local
NEXT_PUBLIC_API_URL=http://localhost:8000   # FastAPI backend
```

---

## 📦 Dependencies

```json
{
  "next": "14.2.3",
  "framer-motion": "^11",
  "lucide-react": "^0.383",
  "axios": "^1.7"
}
```

---

## 🛠 Build for Production

```bash
npm run build
npm start
```

---

Built with ⚡ by Nexus DevSecOps Agent
