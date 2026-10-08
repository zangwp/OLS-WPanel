# Frontend source assets

This directory contains the Tailwind CSS source and its build configuration.
The generated stylesheet used by the embedded panel remains under
`web/css/`; release builds do not download frontend tooling or rebuild it.

From the repository root, run the pinned/reviewed Tailwind **3.4.19** binary explicitly:

```sh
bin/tailwindcss -c web/source/frontend/tailwind.config.js \
  -i web/source/frontend/input.css -o web/css/main.css --minify
```

Review the generated `web/css/main.css` diff before committing it. Release
builds intentionally do not download a live Tailwind binary.

The content scan includes the templates and `web/js/app.js`, which also emits
utility classes when rendering Markdown. Include any new runtime rendering
sources in the scan before regenerating the stylesheet.

## Shared appearance

The panel and login use `data-theme="light"`. CSS is loaded in this order:

1. `main.css`: compiled utilities and baseline component rules.
2. `palette.css`: maps existing dark utility markup to semantic light colors, including hover states.
3. `theme.css`: shared color/font tokens, navigation, cards, controls, tables, dialogs, and responsive layouts.
4. `overview.css` for the dashboard and website list, or `login.css` for the login page.
5. `security.css` on the security center, for account enrollment, sessions, audit tables and grouped navigation.

Use the `--panel-*` tokens for new components instead of hard-coded colors.
The sidebar and login brand area set their own dark foreground tokens. Filled
primary buttons keep white text; status labels use tinted backgrounds and dark
text. New utility colors must also be covered in `palette.css` if they were
originally intended for a dark surface.

Page titles use `.page-title`. Keep wide tables in a horizontal scroll container,
and preserve table headers and all actions at narrow widths. Fonts come from the
system stack; no external font request is required. Check both Chinese and
English layouts and `prefers-reduced-motion` when changing shared styles.
