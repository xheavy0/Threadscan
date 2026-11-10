# Threadscan mark and look

Threadscan is part of the Thread ecosystem.

**Mark.** Thread Space Icon Design System v1.0 geometry: the folded-ribbon silhouette,
the near-black `#090B10` inset at (72, 152) in a 512×512 view box, and an outlined white
**TS** monogram drawn as paths (no font dependency). Accent **#84C21F** (lime; ribbon
gradient `#a6d84a` → `#84C21F` → `#5e9112`). TS is already used by ThreadShot (`#F42B59`)
and ThreadStorage (`#00C5E5`); as with Threadflow's TF, the accent tells them apart.
Master: `threadscan/static/threadscan.svg`, also served as the dashboard favicon.
To list Threadscan in ThreadBox, add `{key: "threadscan", name: "Threadscan", monogram: "TS",
accent: "#84C21F"}` to its catalog.

**Dashboard (Trellis look, as in Threadflow and Threadmap).**

- Type: Inter (UI), Source Serif 4 (headings and figures), JetBrains Mono (code, paths, ids).
  Latin subsets are self-hosted in `threadscan/static/fonts/` (SIL OFL 1.1, licences beside
  them). The dashboard never calls a font CDN and works offline.
- Colour: ivory `#faf9f5` app, white cards, an always-dark `#1f1e1d` sidebar, terracotta
  brand `#b5532f` (`#d97757` in dark mode). Other colour carries status only: green
  `#6c8b63`, red `#a76058`, gold `#9a8351`, blue `#6286a8`.
- Eyebrow labels in small letter-spaced capitals; metrics as a hairline-divided strip with
  serif figures.
