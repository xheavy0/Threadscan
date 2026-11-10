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

**Dashboard.** At the owner's request the dashboard follows Wiz's product design system
(from Wiz's public product screenshots) rather than the Trellis look of Threadflow and
Threadmap: a white icon rail with labels, a white top bar with a scope selector and search
pill, rounded filter pills (blue `#1b5cff` when active), a GROUP BY segmented control, round
letter severity badges (C `#d1242f` on `#ffe4e6`, H `#c2410c` on `#ffedd5`, M `#a16207` on
`#fef3c7`, L `#475467` on `#eef1f5`), pill statuses, cards with a title and grey subtitle,
and a dotted-canvas graph. Type: DM Sans (text) and Poppins (titles), the open fonts Wiz's
site uses, plus JetBrains Mono; Latin subsets self-hosted in `threadscan/static/fonts/`
(SIL OFL 1.1, licences beside them). Icons: Lucide (ISC, `threadscan/static/LICENSE-Lucide.txt`),
inlined as SVG; Wiz's own icon set, name and logo are not used. No font or icon CDN.
The Threadscan mark keeps it recognisably a Thread app.
