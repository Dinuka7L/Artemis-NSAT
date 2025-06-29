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
          orange: '#ea580c',     // Darker orange
          'orange-light': '#f97316', // Medium orange
          'orange-dark': '#c2410c',  // Very dark orange
        }
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Consolas', 'Monaco', 'monospace']
      }
    },
  },
  plugins: [],
}