/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        ace: {
          bg: '#020408',       // Ace's deep black background
          card: '#0F1218',     // Slightly lighter card bg
          border: '#1F242F',   // Subtle borders
          primary: '#7F56D9',  // Ace Purple
          secondary: '#D946EF',// Ace Pink
          blue: '#2E90FA',     // Ace Blue
          text: '#F9FAFB',     // Off-white text
          muted: '#98A2B3',    // Muted text
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'], // Ace uses a clean geometric sans
      },
      backgroundImage: {
        'ace-gradient': 'linear-gradient(to right, #2E90FA, #7F56D9, #D946EF)',
        'ace-glass': 'linear-gradient(180deg, rgba(255, 255, 255, 0.08) 0%, rgba(255, 255, 255, 0.03) 100%)',
      }
    },
  },
  plugins: [],
}