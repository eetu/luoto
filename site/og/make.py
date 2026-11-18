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
# A chat thumbnail is the square cut from the middle (x 286 to 913), so the island and the
# name stand inside it; a wide card shows the same picture with room either side.
# One pixel of the splash, and where its grid starts.
CELL = 15
ART = ((WIDTH - CELL * len(PIXELS[0])) // 2, 62)
NAME = [("luoto", "600", INKS["F"]), (".", "600", ACCENT)]
TRACKING = -0.04
FONTS = json.loads((HERE / "glyphs.json").read_text())


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


Runs = list[tuple[str, str, str]]


def advance(char: str, weight: str, size: float) -> float:
    font = FONTS[weight]
    return font["glyphs"][char][0] * size / font["em"] + TRACKING * size


def width(runs: Runs, size: float) -> float:
    return sum(advance(c, weight, size) for string, weight, _ in runs for c in string)


def text(runs: Runs, size: float, center: float, baseline: float) -> str:
    """`runs` of (text, weight, fill) as outlines on `baseline`, centered on `center`."""
    x = center - (width(runs, size) - TRACKING * size) / 2
    paths = []
    for string, weight, fill in runs:
        scale = size / FONTS[weight]["em"]
        for char in string:
            outline = FONTS[weight]["glyphs"][char][1]
            if outline:
                paths.append(
                    f'<path transform="translate({x:.2f} {baseline}) scale({scale:.5f} '
                    f'{-scale:.5f})" fill="{fill}" d="{outline}"/>'
                )
            x += advance(char, weight, size)
    return "\n".join(paths)


def svg() -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" \
width="{WIDTH}" height="{HEIGHT}" role="img" \
aria-label="luoto">
<!-- Written by make.py. The island mirrors the still frame of cli/src/splash.rs; the text is
Inter (Copyright 2016 The Inter Project Authors, SIL Open Font License 1.1) as outlines. -->
<rect width="{WIDTH}" height="{HEIGHT}" fill="{BACKGROUND}"/>
<g shape-rendering="crispEdges">
{art()}
</g>
{text(NAME, 150, WIDTH / 2, 556)}
</svg>
"""


if __name__ == "__main__":
    source = HERE / "og.svg"
    source.write_text(svg())
    subprocess.run(
        ["rsvg-convert", "-w", str(WIDTH), "-h", str(HEIGHT), "-o", HERE.parent / "og.png", source],
        check=True,
    )
