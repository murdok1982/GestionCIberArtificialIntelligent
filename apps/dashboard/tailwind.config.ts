import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // CyberGuard Security Dark Theme
        bg: {
          primary: "#0A0E1A",
          surface: "#0F1629",
          card: "#141B2D",
          hover: "#1A2540",
        },
        border: {
          DEFAULT: "#1E2D47",
          subtle: "#152035",
        },
        accent: {
          blue: "#3B82F6",
          "blue-dark": "#1D4ED8",
          purple: "#8B5CF6",
          cyan: "#06B6D4",
        },
        severity: {
          critical: "#EF4444",
          "critical-bg": "#451A1A",
          high: "#F97316",
          "high-bg": "#431B0F",
          medium: "#F59E0B",
          "medium-bg": "#3D2D0A",
          low: "#10B981",
          "low-bg": "#0A2E20",
          info: "#6B7280",
        },
        status: {
          online: "#10B981",
          offline: "#4B5563",
          warning: "#F59E0B",
          critical: "#EF4444",
        },
        text: {
          primary: "#F1F5F9",
          secondary: "#94A3B8",
          muted: "#64748B",
          disabled: "#374151",
        },
      },
      backgroundImage: {
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
        "gradient-cyber": "linear-gradient(135deg, #3B82F6 0%, #8B5CF6 100%)",
        "gradient-danger": "linear-gradient(135deg, #EF4444 0%, #F97316 100%)",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "fade-in": "fadeIn 0.3s ease-in-out",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0", transform: "translateY(4px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
