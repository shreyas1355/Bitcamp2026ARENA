import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        arena: {
          bg:       '#0d1117',
          surface:  '#161b22',
          border:   '#30363d',
          text:     '#e6edf3',
          muted:    '#8b949e',
          red:      '#f85149',
          orange:   '#d29922',
          yellow:   '#e3b341',
          green:    '#3fb950',
          blue:     '#58a6ff',
          purple:   '#bc8cff',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
} satisfies Config
