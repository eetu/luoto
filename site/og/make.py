#!/usr/bin/env python3
"""The share image: writes og.svg here and rasterizes it to ../og.png (1200x627).

    python3 site/og/make.py        # needs rsvg-convert

PIXELS mirrors the still frame of cli/src/splash.rs (`pixels(FRAMES, true)`): the same
36x22 grid and inks, on the dark palette of the UI. When the splash changes, change it here.
glyphs.json holds the outlines of the page's Inter (Copyright 2016 The Inter Project Authors,
SIL Open Font License 1.1; glyphs.py writes it), so no font has to be installed.
"""

import json
import subprocess
from pathlib import Path

HERE = Path(__file__).parent

# . nothing, F foreground, D dim, A accent, a the accent faint (the sun's reflection)
PIXELS = """
.........FFF....FFFF................
.......FF...FF.F....F...............
......F....FFFFFFF...F..............
......F...F...F...FF................
.........F....F.....F.........AA....
.........F.....F....F........AAAA...
...............F.............AAAA...
................F.............AA....
................F...................
.................F..................
............AAAAAAAAAA..............
..........AAAA......AAAA............
.........AAA..........AAA...........
........AAA............AAA..........
........AA..............AA..........
.FF...FAAA..FFF...FFF...AAA...FFF...
...FFF...FFF...FFF...FFF...FFF...FF.
....................................
.........DDD...DDD...DDD............
........D...DDD...DDD...DD...aaaa...
....................................
..............................aa....
""".split()

WIDTH, HEIGHT = 1200, 627
BACKGROUND = "#0f0f0f"
ACCENT = "#f78f08"
INKS = {
    "F": "#ededed",
    "D": "#9c9c9c",
    "A": ACCENT,
    # A terminal's faint: halfway to the background.
    "a": "#834f0c",
}
MARGIN = 84
# One pixel of the splash, and where its grid starts: its last column is empty, so the sea
# ends at the right margin.
CELL = 14
ART = (WIDTH - MARGIN - CELL * (len(PIXELS[0]) - 1), 44)
TRACKING = -0.04
# What a card shows of luoto without a word beside it: the README's first sentence, short.
PITCH = ("A sandbox for dependencies and agents", "that feels like working locally.")


def art() -> str:
    """Each run of one ink in a row as a rect on whole pixels."""
    rects = []
    for y, row in enumerate(PIXELS):
        x = 0
        while x < len(row):
            end = x
            while end < len(row) and row[end] == row[x]:
                end += 1
            if row[x] != ".":
                rects.append(
                    f'<rect x="{ART[0] + x * CELL}" y="{ART[1] + y * CELL}" '
                    f'width="{(end - x) * CELL}" height="{CELL}" fill="{INKS[row[x]]}"/>'
                )
            x = end
    return "\n".join(rects)


def text(runs: list[tuple[str, str, str]], size: float, x: float, baseline: float) -> str:
    """`runs` of (text, weight, fill) as outlines, from `x` on `baseline`."""
    fonts = json.loads((HERE / "glyphs.json").read_text())
    paths = []
    for string, weight, fill in runs:
        font = fonts[weight]
        scale = size / font["em"]
        for char in string:
            advance, outline = font["glyphs"][char]
            if outline:
                paths.append(
                    f'<path transform="translate({x:.2f} {baseline}) scale({scale:.5f} '
                    f'{-scale:.5f})" fill="{fill}" d="{outline}"/>'
                )
            x += advance * scale + TRACKING * size
    return "\n".join(paths)


def svg() -> str:
    # The name's left side bearing is taken off, so its stem stands over the lines under it.
    name = text([("luoto", "600", INKS["F"]), (".", "600", ACCENT)], 168, MARGIN - 11, 226)
    tagline = text(
        [
            ("no tool is an island, except on ", "400", INKS["D"]),
            ("luoto", "600", INKS["F"]),
            (".", "600", ACCENT),
        ],
        30,
        MARGIN,
        292,
    )
    pitch = "\n".join(
        text([(line, "500", INKS["F"])], 54, MARGIN, 476 + 68 * i) for i, line in enumerate(PITCH)
    )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" \
width="{WIDTH}" height="{HEIGHT}" role="img" \
aria-label="luoto: no tool is an island, except on luoto.">
<!-- Written by make.py. The island mirrors the still frame of cli/src/splash.rs; the text is
Inter (Copyright 2016 The Inter Project Authors, SIL Open Font License 1.1) as outlines. -->
<rect width="{WIDTH}" height="{HEIGHT}" fill="{BACKGROUND}"/>
<g shape-rendering="crispEdges">
{art()}
</g>
{name}
{tagline}
{pitch}
</svg>
"""


if __name__ == "__main__":
    source = HERE / "og.svg"
    source.write_text(svg())
    subprocess.run(
        ["rsvg-convert", "-w", str(WIDTH), "-h", str(HEIGHT), "-o", HERE.parent / "og.png", source],
        check=True,
    )
