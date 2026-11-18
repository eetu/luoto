"""Writes glyphs.json: the outlines make.py sets the share image's text with, from the
page's Inter (../fonts/inter-latin.woff2) at the weights it uses. Run it only for a new
weight or font file:

    uvx --with fonttools --with brotli python site/og/glyphs.py
"""

import json
from pathlib import Path

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

HERE = Path(__file__).parent
WEIGHTS = (400, 500, 600)

fonts = {}
for weight in WEIGHTS:
    font = TTFont(HERE.parent / "fonts" / "inter-latin.woff2")
    axes = {axis.axisTag: axis.maxValue for axis in font["fvar"].axes}
    # The largest optical size, where the font has that axis: this is display text.
    font = instancer.instantiateVariableFont(font, axes | {"wght": weight})
    glyph_set, cmap, widths = font.getGlyphSet(), font.getBestCmap(), font["hmtx"]
    glyphs = {}
    for code in range(0x20, 0x7F):
        pen = SVGPathPen(glyph_set, lambda v: str(round(v)))
        glyph_set[cmap[code]].draw(pen)
        glyphs[chr(code)] = [widths[cmap[code]][0], pen.getCommands()]
    fonts[str(weight)] = {"em": font["head"].unitsPerEm, "glyphs": glyphs}

(HERE / "glyphs.json").write_text(json.dumps(fonts, indent=1, sort_keys=True) + "\n")
