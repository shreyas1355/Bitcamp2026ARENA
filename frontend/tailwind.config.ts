import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        arena: {
          bg: '#f5f5f4',
          surface: '#ffffff',
          'muted-bg': '#e7e5e4',
          border: '#d6d3d1',
          text: '#1c1917',
          muted: '#57534e',
          red: '#b91c1c',
          'red-soft': '#fef2f2',
          blue: '#1d4ed8',
          'blue-soft': '#eff6ff',
          green: '#15803d',
          'green-soft': '#f0fdf4',
          orange: '#c2410c',
          accent: '#2563eb',
          'table-header': '#e7e5e4',
        },
      },
      fontFamily: {
        serif: [
          'Cambria',
          'Palatino Linotype',
          'Palatino',
          'Liberation Serif',
          'Georgia',
          'Times New Roman',
          'serif',
        ],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
} satisfies Config
