# site

The landing page at <https://eetu.github.io/luoto/>, published by
`.github/workflows/pages.yaml`. No build step beyond `build.sh`, which copies the page and
what it shows from the rest of the repo (the hello cast, the screenshots, the UI's favicon)
into one folder.

Preview:

```sh
bash -c 'sh site/build.sh && python3 -m http.server -d target/site'
```

`og.png` is the share image (1200x627). `python3 site/og/make.py` writes it (needs
`rsvg-convert`); its island mirrors the still frame of `cli/src/splash.rs`, so a change to
the splash is a change to `PIXELS` there.

`fonts/` holds the latin subsets of Inter and Space Grotesk (SIL Open Font License 1.1).
