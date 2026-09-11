/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/features/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        apple: {
          bg: "#FBFBFD",
          surface: "#FFFFFF",
          subtle: "#F5F5F7",
          border: "rgba(0, 0, 0, 0.08)",
          text: "#1D1D1F",
          secondary: "#6E6E73",
          tertiary: "#86868B",
          blue: "#0071E3",
          green: "#34C759",
          orange: "#FF9500",
          red: "#FF3B30",
          purple: "#AF52DE",
          indigo: "#5856D6",
        },
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          '"SF Pro Display"',
          '"SF Pro Text"',
          '"Inter"',
          '"Segoe UI"',
          "Roboto",
          "Helvetica",
          "Arial",
          "sans-serif",
        ],
        mono: [
          '"SF Mono"',
          "ui-monospace",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      boxShadow: {
        "apple-card": "0 2px 8px -1px rgba(0, 0, 0, 0.04), 0 1px 3px -1px rgba(0, 0, 0, 0.02)",
        "apple-hover": "0 8px 24px -4px rgba(0, 0, 0, 0.08), 0 2px 6px -1px rgba(0, 0, 0, 0.04)",
        "apple-modal": "0 24px 48px -12px rgba(0, 0, 0, 0.18), 0 4px 16px -2px rgba(0, 0, 0, 0.08)",
        "apple-glow": "0 0 20px -2px rgba(0, 113, 227, 0.25)",
      },
      borderRadius: {
        "apple-sm": "8px",
        "apple": "12px",
        "apple-lg": "16px",
        "apple-xl": "20px",
        "apple-2xl": "24px",
      },
    },
  },
  plugins: [],
};
