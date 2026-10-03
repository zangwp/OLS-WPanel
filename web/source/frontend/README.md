# Frontend source assets

This directory contains the Tailwind CSS source and its build configuration.
The generated stylesheet used by the embedded panel remains under
`web/css/`; release builds do not download frontend tooling or rebuild it.

From the repository root, run the pinned/reviewed Tailwind binary explicitly:

```sh
bin/tailwindcss -c web/source/frontend/tailwind.config.js \
  -i web/source/frontend/input.css -o web/css/main.css --minify
```

Review the generated `web/css/main.css` diff before committing it. Release
builds intentionally do not download a live Tailwind binary.
