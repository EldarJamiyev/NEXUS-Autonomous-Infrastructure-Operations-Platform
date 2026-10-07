/** @type {import('tailwindcss').Config} */
const token = (name) => `rgb(var(--${name}) / <alpha-value>)`;
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: token("bg"), panel: token("panel"), inset: token("inset"), line: token("line"), ink: token("ink"), muted: token("muted"),
        accent: token("accent"), ok: token("ok"), info: token("info"), warn: token("warn"), high: token("high"), crit: token("crit"), unk: token("unk"),
      },
      fontFamily: {
        sans: ['"Barlow"', "system-ui", "Segoe UI", "Roboto", "sans-serif"],
        cond: ['"Barlow Semi Condensed"', '"Barlow"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      fontSize: { "2xs": ["11px", "14px"], xs: ["12px", "16px"], sm: ["13px", "18px"], base: ["14px", "20px"] },
    },
  },
  plugins: [],
};
