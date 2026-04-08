/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bgMain: 'var(--bg-main)',
        bgSecondary: 'var(--bg-secondary)',
        bgElevated: 'var(--bg-elevated)',
        silverMain: 'var(--silver-main)',
        silverSoft: 'var(--silver-soft)',
        silverMuted: 'var(--silver-muted)',
        goldMain: 'var(--gold-main)',
        goldHover: 'var(--gold-hover)',
        goldGlow: 'var(--gold-glow)',
        textPrimary: 'var(--text-primary)',
        textSecondary: 'var(--text-secondary)',
        textMuted: 'var(--text-muted)',
      }
    },
  },
  plugins: [],
}
