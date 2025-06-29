/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        artemis: {
          primary: '#dc2626',
          secondary: '#1f2937',
          accent: '#3b82f6',
          success: '#10b981',
          warning: '#f59e0b',
          danger: '#ef4444'
        },
        dark: {
          primary: '#0f172a',    // Very dark blue
          secondary: '#1e293b',  // Dark blue
          accent: '#334155',     // Medium dark blue
          surface: '#475569',    // Light dark blue
          orange: '#ff6b35',     // Electric orange
          'orange-light': '#ff8c42', // Lighter electric orange
          'orange-dark': '#e55a2b',  // Darker electric orange
        }
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Consolas', 'Monaco', 'monospace']
      }
    },
  },
  plugins: [],
}