/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'metalbg-main': '#0E0E10',
        'metalbg-secondary': '#1A1A1D',
        'metalbg-elevated': '#222326',
        'metalsilver-main': '#C0C0C0',
        'metalsilver-soft': '#D9D9D9',
        'metalsilver-muted': '#8F8F8F',
        'metalgold-main': '#D4AF37',
        'metalgold-hover': '#C9A227',
        'metalgold-glow': '#FFD700',
        'metaltxt-primary': '#F5F5F5',
        'metaltxt-secondary': '#B0B0B0',
        'metaltxt-muted': '#7A7A7A',
        
        // Severity (Muted/Metallic adaptation)
        'm-critical': '#A94442',
        'm-high': '#C9A227',
        'm-medium': '#8F8F8F',
        'm-low': '#D4AF37',
        
        'metal-border': 'rgba(143, 143, 143, 0.2)',
        'metal-glass': 'rgba(26, 26, 29, 0.7)',
      }
    },
  },
  plugins: [],
}
