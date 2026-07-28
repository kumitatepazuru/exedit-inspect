"""The four bright-part extraction workers, and the asymmetry between them.

All four read the image once and fill the scratch buffer (8 bytes/pixel,
alpha nailed to 4096). Which one runs is `no_color x flag&0x20`:

    0x10055540  object, 光色=指定なし      0x10055690  object, 光色=指定あり
    0x100557a0  frame,  光色=指定なし      0x100558e0  frame,  光色=指定あり

The 指定なし pair is *not* the 指定あり pair with the colour swapped in. They
apply different curves to the same input:

    指定なし   b = 0                if y <= T
               b = 2*(y - T)        if T < y < 2T     <- soft knee
               b = y                if y >= 2T
               out = (b, c_div(cb*b, y), c_div(cr*b, y), 4096)

    指定あり   b = 0                if y <= T
               b = y - T            otherwise          <- plain hinge, no knee
               out = ((colY*b)>>12, (colCb*b)>>12, (colCr*b)>>12, 4096)

Consequences worth stating because neither is visible in the formulas at a
glance:

  * 指定なし is continuous *and* asymptotically the identity. A pixel far above
    the threshold contributes its own brightness untouched, so raising
    しきい値 mostly changes which pixels light up, not how bright the bright
    ones are. 指定あり subtracts the threshold for good: every extracted value
    is `y - T`, so raising しきい値 dims the whole glow.
  * 指定なし preserves the chroma/luma *ratio* (`c * b / y`), so the glow keeps
    the source hue at reduced saturation-times-brightness. 指定あり throws the
    source colour away entirely and, because the light colour's own Y multiplies
    the result, a dark 光色 makes the whole glow proportionally dimmer - the
    same trap 発光 has ([`rgb_ycbcr.md` §4](../common/rgb_ycbcr.md)).
  * only the object versions premultiply, and the two of them premultiply
    different amounts: 指定なし weights all three channels by alpha
    (0x100555ea-0x10055604), 指定あり weights only the luma because it never
    reads the source chroma at all. Note this is *not* 発光's asymmetry, where
    the luma is alpha-weighted and the chroma deliberately is not
    ([`box_blur.md` §1](../common/box_blur.md)) - here the premultiply is
    consistent within each worker.

Run via main.py:
    uv run main.py inspect/glow/verify_extract.py
"""

from tools.cints import c_div
from tools.disasm import dump_all
from tools.pe_image import PEImage

OBJECT_NOCOLOR = (0x100555D4, 0x7A)
OBJECT_COLOR = (0x10055712, 0x64)
FRAME_NOCOLOR = (0x1005584D, 0x50)

ANNOTATIONS = {
    0x100555D4: "eax = src.a",
    0x100555D8: "ecx = src.y",
    0x100555DB: "edx = src.cb",
    0x100555DF: "ebp = src.cr",
    0x100555E3: "a >= 4096 -> skip the premultiply (it would be a no-op)",
    0x100555EF: "y  = (y*a)  >> 12",
    0x100555FC: "cb = (cb*a) >> 12",
    0x100555FF: "cr = (cr*a) >> 12   <- object version premultiplies ALL THREE here",
    0x10055606: "eax = threshold",
    0x1005560C: "y <= T -> write (0,0,0)",
    0x1005560E: "eax = 2*T",
    0x10055612: "y >= 2T ? ...",
    0x10055616: "... no: edi = y - T ...",
    0x1005561A: "... doubled -> the soft knee, continuous at both ends",
    0x1005561E: "out.y = brightness",
    0x10055625: "out.cb = c_div(cb * brightness, y)  <- keeps the chroma/luma ratio",
    0x10055631: "out.cr likewise",
    0x10055646: "out.a = 4096, unconditionally",
    0x10055712: "esi = src.a",
    0x10055716: "ecx = src.y",
    0x10055724: "y = (y*a) >> 12   <- only the luma; chroma is never read at all",
    0x10055729: "y <= T -> write (0,0,0)",
    0x10055734: "ecx = y - T. no knee, no clamp",
    0x1005572D: "esi = 光色 Y",
    0x10055739: "out.y  = (colourY * (y-T)) >> 12",
    0x1005573F: "esi = 光色 Cb",
    0x10055750: "esi = 光色 Cr",
    0x10055770: "out.a = 4096",
    0x1005584D: "edi = src.y - the frame version has no alpha to weight with",
    0x10055858: "ebp = src.cr",
    0x1005585E: "y <= T -> (0,0,0)",
    0x1005586B: "the same soft knee as the object version",
    0x10055876: "c_div(cb * brightness, y)",
    0x10055897: "out.a = 4096, even though the source had no alpha",
}


def extract_nocolor(y: int, cb: int, cr: int, a: int, t: int, premul: bool) -> tuple:
    """0x10055540 (premul=True) / 0x100557a0 (premul=False)."""
    if premul and a < 4096:
        y, cb, cr = (y * a) >> 12, (cb * a) >> 12, (cr * a) >> 12
    if y <= t:
        return 0, 0, 0, 4096
    b = y if y >= 2 * t else 2 * (y - t)
    return b, c_div(cb * b, y), c_div(cr * b, y), 4096


def extract_color(y: int, a: int, t: int, col: tuple, premul: bool) -> tuple:
    """0x10055690 (premul=True) / 0x100558e0 (premul=False)."""
    if premul and a < 4096:
        y = (y * a) >> 12
    if y <= t:
        return 0, 0, 0, 4096
    d = y - t
    return (col[0] * d) >> 12, (col[1] * d) >> 12, (col[2] * d) >> 12, 4096


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_all(PEImage(dll_path), {
        "extract, object, 光色=指定なし (0x10055540)": OBJECT_NOCOLOR,
        "extract, object, 光色=指定あり (0x10055690)": OBJECT_COLOR,
        "extract, frame, 光色=指定なし (0x100557a0)": FRAME_NOCOLOR,
    }, annotations=ANNOTATIONS)

    t = 1638      # the default しきい値 40.0
    print(f"\n--- 1. the two curves, しきい値 = 40.0 (T = {t}) ---")
    print(f"  {'src.y':>7}{'指定なし':>12}{'指定あり (白)':>16}{'指定あり (#f00)':>18}")
    white, red = (4095, 0, 0), (1224, -1801, 3612)   # see verify_ycbcr in inspect/luminous
    for y in (0, 800, 1638, 1700, 2000, 2500, 3276, 4096):
        a = extract_nocolor(y, 0, 0, 4096, t, True)[0]
        b = extract_color(y, 4096, t, white, True)[0]
        c = extract_color(y, 4096, t, red, True)[0]
        print(f"  {y:>7}{a:>12}{b:>16}{c:>18}")
    print("  指定なし converges on the identity; 指定あり keeps the whole -T offset")
    print("  and scales it by the light colour's own Y (red is 1224/4096 = 30%).")

    print("\n--- 2. continuity of the knee (指定なし) ---")
    for y in (2 * t - 1, 2 * t, 2 * t + 1):
        print(f"  y={y:>5} -> {extract_nocolor(y, 0, 0, 4096, t, True)[0]}")
    print(f"  y={t} -> {extract_nocolor(t, 0, 0, 4096, t, True)[0]}, "
          f"y={t + 1} -> {extract_nocolor(t + 1, 0, 0, 4096, t, True)[0]}")
    print("  no jump at either end: 2*(2T-T) == 2T, and 2*(T-T) == 0.")

    print("\n--- 3. chroma: the ratio is preserved, the value is not ---")
    print(f"  {'src.y':>7}{'src.cb':>8}{'out.y':>8}{'out.cb':>8}   cb/y in vs out")
    for y, cb in ((4096, -1000), (2000, -1000), (1800, -1000), (3000, 2000)):
        oy, ocb, _, _ = extract_nocolor(y, cb, 0, 4096, t, True)
        ratio = f"{cb / y:+.4f} -> {(ocb / oy) if oy else 0:+.4f}"
        print(f"  {y:>7}{cb:>8}{oy:>8}{ocb:>8}   {ratio}")

    print("\n--- 4. alpha weighting: object premultiplies, frame cannot ---")
    print(f"  {'a':>6}{'premul y':>10}{'object out':>28}{'frame out':>28}")
    for a in (4096, 2048, 512):
        o = extract_nocolor(3000, -1000, 500, a, t, True)
        f = extract_nocolor(3000, -1000, 500, a, t, False)
        print(f"  {a:>6}{(3000 * a) >> 12:>10}{str(o):>28}{str(f):>28}")
    print("  a semi-transparent object dims its own luma below T and stops glowing,")
    print("  while the frame filter - which has no alpha - always glows. Both write")
    print("  a=4096 into the scratch, which is why the blur workers never touch alpha.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
