/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        darkBg: "#090d16",       // Deep Microsoft Sentinel style background
        darkCard: "#111827",     // Slick gray cards
        darkBorder: "#1f2937",   // Thin card borders
        glowBlue: "#3b82f6",     // Live feed logs
        glowGreen: "#10b981",    // Normal status
        glowOrange: "#f97316",   // Medium/High alerts
        glowRed: "#ef4444"       // Critical threats
      },
      fontFamily: {
        sans: ["Outfit", "Inter", "sans-serif"],
        mono: ["JetBrains Mono", "Courier New", "monospace"]
      }
    },
  },
  plugins: [],
}
