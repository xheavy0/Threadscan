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

**Dashboard.** At the owner's request the dashboard uses a cloud-security-console layout
(in the style of Wiz, without its name, logo or assets) rather than the Trellis look of
Threadflow and Threadmap: navy side navigation (`#0b1533`), light work area (`#f4f6fb`),
primary blue `#1f5eff`, severity colours critical `#b4123a`, high `#e0452a`, medium
`#e88400`, low `#b98f00`, info `#5b6b8c`; an issues table with filter pills and a detail
drawer. Type: Inter (UI) and JetBrains Mono (code, paths, ids), self-hosted Latin subsets
in `threadscan/static/fonts/` (SIL OFL 1.1, licences beside them); no font CDN. The
Threadscan mark and the lime `scan` in the wordmark keep it recognisably a Thread app.
