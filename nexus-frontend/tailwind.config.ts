import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Midnight Cyber Palette
        void: {
          950: "#020409",
          900: "#060d1a",
          800: "#0a1628",
          700: "#0d1f38",
          600: "#112847",
        },
        abyss: {
          900: "#07041a",
          800: "#0e0830",
          700: "#160c46",
        },
        cyan: {
          neon: "#00f5ff",
          glow: "#06b6d4",
          dim: "#0891b2",
          pulse: "#22d3ee",
        },
        violet: {
          neon: "#a855f7",
          glow: "#7c3aed",
          dim: "#6d28d9",
          soft: "#c084fc",
        },
        slate: {
          glass: "rgba(15, 23, 42, 0.6)",
        },
      },
      fontFamily: {
        display: ["'Orbitron'", "monospace"],
        mono: ["'JetBrains Mono'", "'Fira Code'", "monospace"],
        body: ["'Exo 2'", "sans-serif"],
      },
      backgroundImage: {
        "cyber-grid":
          "linear-gradient(rgba(0,245,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,245,255,0.03) 1px, transparent 1px)",
        "glow-radial":
          "radial-gradient(ellipse at center, rgba(0,245,255,0.08) 0%, transparent 70%)",
        "violet-glow":
          "radial-gradient(ellipse at top right, rgba(168,85,247,0.12) 0%, transparent 60%)",
        "panel-glass":
          "linear-gradient(135deg, rgba(15,23,42,0.8) 0%, rgba(10,16,40,0.9) 100%)",
      },
      backgroundSize: {
        grid: "40px 40px",
      },
      boxShadow: {
        "cyan-glow": "0 0 20px rgba(0,245,255,0.3), 0 0 60px rgba(0,245,255,0.1)",
        "cyan-subtle": "0 0 10px rgba(0,245,255,0.15)",
        "violet-glow": "0 0 20px rgba(168,85,247,0.3), 0 0 60px rgba(168,85,247,0.1)",
        "glass-border": "inset 0 1px 0 rgba(255,255,255,0.05)",
        "panel": "0 25px 50px rgba(0,0,0,0.8), 0 0 0 1px rgba(255,255,255,0.04)",
      },
      animation: {
        "pulse-cyan": "pulse-cyan 2s ease-in-out infinite",
        "scan-line": "scan-line 3s linear infinite",
        "text-shimmer": "text-shimmer 2.5s linear infinite",
        "border-flow": "border-flow 4s linear infinite",
        "float": "float 6s ease-in-out infinite",
        "grid-scroll": "grid-scroll 20s linear infinite",
      },
      keyframes: {
        "pulse-cyan": {
          "0%, 100%": { boxShadow: "0 0 10px rgba(0,245,255,0.2)" },
          "50%": { boxShadow: "0 0 30px rgba(0,245,255,0.6), 0 0 60px rgba(0,245,255,0.3)" },
        },
        "scan-line": {
          "0%": { top: "0%" },
          "100%": { top: "100%" },
        },
        "text-shimmer": {
          "0%": { backgroundPosition: "-200% center" },
          "100%": { backgroundPosition: "200% center" },
        },
        "border-flow": {
          "0%, 100%": { borderColor: "rgba(0,245,255,0.3)" },
          "50%": { borderColor: "rgba(168,85,247,0.5)" },
        },
        "float": {
          "0%, 100%": { transform: "translateY(0px)" },
          "50%": { transform: "translateY(-8px)" },
        },
        "grid-scroll": {
          "0%": { backgroundPosition: "0 0" },
          "100%": { backgroundPosition: "40px 40px" },
        },
      },
    },
  },
  plugins: [],
};
export default config;
