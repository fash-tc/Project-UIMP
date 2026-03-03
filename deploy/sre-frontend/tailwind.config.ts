import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#0a0a0f',
        surface: '#12121a',
        'surface-hover': '#1a1a2e',
        border: '#2a2a3e',
        accent: '#6c5ce7',
        'accent-hover': '#7d6ff0',
        green: '#00b894',
        red: '#ff6b6b',
        orange: '#fdcb6e',
        yellow: '#ffeaa7',
        blue: '#74b9ff',
        muted: '#8892b0',
        text: '#ccd6f6',
        'text-bright': '#e6f1ff',
      },
    },
  },
  plugins: [],
};

export default config;
