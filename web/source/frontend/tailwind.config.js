/** @type {import('tailwindcss').Config} */
module.exports = {
  content: {
    relative: true,
    files: ["../../templates/**/*.html", "../../js/app.js"],
  },
  theme: {
    borderRadius: {
      none: "0",
      sm: "0.25rem",
      DEFAULT: "0.375rem",
      md: "0.5rem",
      lg: "0.625rem",
      xl: "0.75rem",
      "2xl": "1rem",
      "3xl": "1.25rem",
      full: "9999px",
    },
    boxShadow: {
      sm: "0 1px 3px rgb(17 36 58 / 0.04)",
      DEFAULT: "0 2px 8px rgb(17 36 58 / 0.06)",
      md: "0 6px 18px rgb(17 36 58 / 0.08)",
      lg: "0 12px 28px rgb(17 36 58 / 0.1)",
      xl: "0 18px 40px rgb(17 36 58 / 0.12)",
      "2xl": "0 24px 64px rgb(17 36 58 / 0.14)",
      inner: "inset 0 1px 2px rgb(17 36 58 / 0.06)",
      none: "none",
    },
    extend: {},
  },
  plugins: [],
}
