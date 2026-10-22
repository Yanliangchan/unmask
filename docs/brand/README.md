# UNMASK mark

## The idea
Type **U-N-M-A-S-K** on a phone keypad: U=8, N=6, M=6, A=2, S=7, K=5. Join the keys in that order, the way an
unlock pattern is drawn, and drop the repeated 6. The result is one stroke, 8 → 6 → 2 → 7 → 5, that ends on the
centre key.

The mark is the name, encoded. It's the kind of trace an investigator reads: a path through known points that
ends at the answer. Because the shape comes from the name and not from a stock shape, nobody else will arrive at it.

Keys used, on the 3×3 keypad grid:

| | | |
|---|---|---|
| 1 | **2** ← A | 3 |
| 4 | **5** ← K, the end | **6** ← N, M |
| **7** ← S | **8** ← U, the start | 9 |

## Construction
- 32-unit grid, keys at 6 / 16 / 26.
- Path `M16 26 L26 16 L16 6 L6 26 L16 16`, stroke 4.4, round caps and joins, no fill.
- In the product: a single colour, ink (`--text-strong`), so it follows the light and dark themes.
- Highlight colour (used beside the mark, never on it): highlighter yellow `--mark` (`#F2D34B`).
- Older gradient version (emerald `#10B981` → `#0EA5E9`) is kept in `mark.svg` for existing uses.

## Files
| File | Use |
|---|---|
| `mark.svg` | gradient mark, any size |
| `mark-mono.svg` | single colour (change the stroke colour) |
| `app/static/img/favicon.svg` | browser tab |
| `app/static/img/icon-192.png`, `icon-512.png`, `apple-touch-icon.png` | app icons: mark at 66% on `#0B1417` (safe for maskable crops) |
| `app/static/img/og-image.png` | link previews, 1200×630 |
| `ui.mark()` in `app/templates/components/ui.html` | in the app (`currentColor`, or pass `gid` for the gradient) |

## Usage
- Clear space: at least a quarter of the mark's width on every side.
- Lockup: mark, then **UNMASK** in IBM Plex Mono 500 with 0.22em tracking. The mark is about 1.4× the cap height.
- Don't: rotate or mirror it (the path order is the name), add the keypad dots, outline it, put it in a
  shield or circle, change the stroke weight, or set it on a busy photo.
