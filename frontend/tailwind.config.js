/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#080c14",
          surface: "#0f172a",
          card: "#131d36",
          cardBorder: "#1e293b",
          primary: "#06b6d4",
          cyanGlow: "#00f0ff",
          blue: "#3b82f6",
          accent: "#0ea5e9",
          danger: "#ef4444",
          warning: "#f59e0b",
          success: "#10b981",
          muted: "#94a3b8"
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'cyan-glow': '0 0 15px -3px rgba(6, 182, 212, 0.35)',
        'blue-glow': '0 0 15px -3px rgba(59, 130, 246, 0.35)',
      }
    },
  },
  plugins: [],
}

