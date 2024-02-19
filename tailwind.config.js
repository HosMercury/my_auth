// const defaultTheme = require('tailwindcss/defaultTheme');

module.exports = {
  content: ['./templates/**/*.html', './templates/*.html'],
  theme: {
    extend: {
      fontFamily: {
        primary: ['Roboto'],
      },
    },
  },
  plugins: [],
};
