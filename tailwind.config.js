/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
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
        }
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Consolas', 'Monaco', 'monospace']
      }
    },
  },
  plugins: [],
}