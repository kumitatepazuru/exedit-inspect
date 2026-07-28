"""An integer-faithful reference implementation of グロー, and pictures of it.

Everything here is transcribed from the disassembly the other scripts in this
directory annotate; nothing is approximated with floats. Divisions use
`tools.cints.c_div` (truncation toward zero, like `idiv`) and shifts use `>>`
(floor, like `sar`), because the two disagree on the signed chroma channels.

The pipeline, in the order func_proc runs it:

    1. pre-grow the object if 2*拡散+1 exceeds either dimension   (verify_canvas_growth)
    2. extraction: image -> scratch, 8 bytes/pixel, alpha = 4096  (verify_extract)
    3. clear the accumulation buffer to OPAQUE black at (w+2rx, h+2ry)
    4. one of six shapes smears the scratch into it                (verify_shapes)
    5. if ぼかし > 0, two more V/H box-average rounds over the result
    6. composite, unless 光成分のみ                                 (verify_composite)
    7. swap the buffers; the object is now (w+2rx) x (h+2ry)

The one thing to keep in mind while reading the pictures: 通常 is a *cascade*.
Its vertical pass reads the accumulation buffer - which already holds
everything the previous passes deposited - so pass N+1 blurs the running total
rather than the extraction. The streak shapes are not cascaded: all three of
their scales read the untouched scratch.

Run via main.py:
    uv run main.py inspect/glow/simulate_glow_reference.py
    uv run main.py inspect/glow/simulate_glow_reference.py --shape ライン(縦)
    uv run main.py inspect/glow/simulate_glow_reference.py --spread 12 --blur 2
"""

import argparse

from tools.cints import c_div

SHAPES = ["通常", "クロス(4本)", "クロス(4本斜め)", "クロス(8本)", "ライン(横)", "ライン(縦)"]

# direction, and how each worker enumerates the streaks it owns.
#   (dx, dy, "rows"|"cols", skip_first)
STREAK_WORKERS = {
    "縦": [(0, 1, "cols", False)],
    "横": [(1, 0, "rows", False)],
    "斜め": [(1, 1, "rows", False), (1, 1, "cols", True),
             (-1, 1, "rows", True), (-1, 1, "cols", False)],
}


# --------------------------------------------------------------------------
# buffers: a plain list of [y, cb, cr, a] rows, addressed [row][col]

def new_buffer(w: int, h: int, fill=(0, 0, 0, 0)) -> list:
    return [[list(fill) for _ in range(w)] for _ in range(h)]


# --------------------------------------------------------------------------
# 2. extraction (0x10055540 / 0x10055690 / 0x100557a0 / 0x100558e0)

def extract(src: list, w: int, h: int, scratch: list, threshold: int,
            colour: tuple | None, premultiply: bool) -> None:
    for y in range(h):
        for x in range(w):
            sy, scb, scr, sa = src[y][x]
            if premultiply and sa < 4096:
                sy, scb, scr = (sy * sa) >> 12, (scb * sa) >> 12, (scr * sa) >> 12
            if sy <= threshold:
                out = [0, 0, 0, 4096]
            elif colour is None:
                b = sy if sy >= 2 * threshold else 2 * (sy - threshold)
                out = [b, c_div(scb * b, sy), c_div(scr * b, sy), 4096]
            else:
                d = sy - threshold
                out = [(colour[0] * d) >> 12, (colour[1] * d) >> 12,
                       (colour[2] * d) >> 12, 4096]
            scratch[y][x] = out


# --------------------------------------------------------------------------
# the shared accumulate step (sub_10056680, and its inlined twin in 0x10055ed0)

def accumulate(px: list, sums: list, strength: int) -> None:
    y, cb, cr = ((((s >> 4) * strength) >> 10) + px[i] for i, s in enumerate(sums))
    if y > 0x2000:
        cb = c_div(cb << 13, y)
        cr = c_div(cr << 13, y)
        y = 0x2000
    px[0], px[1], px[2] = y, cb, cr


# --------------------------------------------------------------------------
# 4a. 通常 - separable box, four cascaded passes

def vertical_average(acc: list, scratch: list, W: int, H: int, radius: int) -> None:
    """0x10055a10: acc -> scratch, divide by the kernel width, alpha untouched."""
    r = radius if 2 * radius + 1 <= H else c_div(H - 1, 2)
    k = 2 * r + 1
    for x in range(W):
        col = [acc[y][x] for y in range(H)]
        for y in range(H):
            sums = [0, 0, 0]
            for j in range(max(0, y - r), min(H, y + r + 1)):
                for c in range(3):
                    sums[c] += col[j][c]
            scratch[y][x][:3] = [c_div(s, k) for s in sums]


def horizontal_average(scratch: list, acc: list, W: int, H: int, radius: int) -> None:
    """0x10055c70: scratch -> acc, divide by the kernel width. The ぼかし tail."""
    r = radius if 2 * radius + 1 <= W else c_div(W - 1, 2)
    k = 2 * r + 1
    for y in range(H):
        row = scratch[y]
        for x in range(W):
            sums = [0, 0, 0]
            for j in range(max(0, x - r), min(W, x + r + 1)):
                for c in range(3):
                    sums[c] += row[j][c]
            acc[y][x][:3] = [c_div(s, k) for s in sums]


def horizontal_accumulate(scratch: list, acc: list, W: int, H: int,
                          radius: int, strength: int) -> None:
    """0x10055ed0: scratch -> acc, NO divide, weighted by strength, in place."""
    for y in range(H):
        row = scratch[y]
        for x in range(W):
            sums = [0, 0, 0]
            for j in range(max(0, x - radius), min(W, x + radius + 1)):
                for c in range(3):
                    sums[c] += row[j][c]
            accumulate(acc[y][x], sums, strength)


def shape_normal(acc, scratch, W, H, rx, strength_raw):
    """case 0 at 0x100551aa: the four (strength, radius) pairs, cascaded."""
    s = strength_raw * 3 * 2
    for i, divisor in enumerate((8, 6, 4, 2)):
        vertical_average(acc, scratch, W, H, c_div(rx, divisor))
        if i == 0:                                   # table[0x48] at 0x1005524e
            for row in acc:
                for px in row:
                    px[0] = px[1] = px[2] = 0
                    px[3] = 4096
        horizontal_accumulate(scratch, acc, W, H, c_div(rx, divisor), s)
        s = c_div(s, 2)


# --------------------------------------------------------------------------
# 4b. the streak shapes

def streak(scratch, acc, w, h, rx, ry, radius, strength, dx, dy, sx, sy, length):
    """One streak, at one scale. 0x10056220 / 0x100569e0 / the four diagonals.

    `radius` is clamped against the streak's own length, then the walk writes
    length + 2r samples starting r steps *behind* the source start.
    """
    r = radius if 2 * radius + 1 <= length else c_div(length - 1, 2)
    samples = [scratch[sy + i * dy][sx + i * dx] for i in range(length)]
    for j in range(length + 2 * r):
        sums = [0, 0, 0]
        for i in range(max(0, j - 2 * r), min(length, j + 1)):
            for c in range(3):
                sums[c] += samples[i][c]
        ax = rx + sx + (j - r) * dx
        ay = ry + sy + (j - r) * dy
        accumulate(acc[ay][ax], sums, strength)


def shape_streaks(acc, scratch, w, h, rx, ry, diag, strength_raw, kinds):
    """The five streak shapes: pick the worker set, run each at scales 1, 2, 4."""
    for kind in kinds:
        for dx, dy, over, skip_first in STREAK_WORKERS[kind]:
            radius0 = ry if (dx, dy) == (0, 1) else rx if (dx, dy) == (1, 0) else diag
            for divisor in (1, 2, 4):
                radius = c_div(radius0, divisor)
                strength = strength_raw * divisor
                for sx, sy, length in _streak_starts(w, h, dx, dy, over, skip_first):
                    streak(scratch, acc, w, h, rx, ry, radius, strength,
                           dx, dy, sx, sy, length)


def _streak_starts(w, h, dx, dy, over, skip_first):
    """Which streaks one worker owns, and how long each is."""
    if (dx, dy) == (0, 1):
        return [(x, 0, h) for x in range(w)]
    if (dx, dy) == (1, 0):
        return [(0, y, w) for y in range(h)]
    start = 1 if skip_first else 0
    if dx == 1:
        if over == "rows":
            return [(0, y, min(w, h - y)) for y in range(start, h)]
        return [(x, 0, min(h, w - x)) for x in range(start, w)]
    if over == "rows":
        return [(w - 1, y, min(w, h - y)) for y in range(start, h)]
    return [(x, 0, min(h, x + 1)) for x in range(start, w)]


# --------------------------------------------------------------------------
# 6. composite (0x10058aa0 / 0x10058de0)

def composite_object(acc, src, w, h, rx, ry) -> None:
    W, H = w + 2 * rx, h + 2 * ry
    for y in range(H):
        inside_row = ry <= y < ry + h
        for x in range(W):
            px = acc[y][x]
            if not (inside_row and rx <= x < rx + w):
                _glow_only(px)
                continue
            sy, scb, scr, sa = src[y - ry][x - rx]
            if sa >= 4096:
                px[0] += sy
                px[1] += scb
                px[2] += scr
                px[3] = sa
            elif sa <= 0:
                _glow_only(px)
            else:
                na = px[0] + sa
                if na <= 0:
                    px[:] = [0, 0, 0, 0]
                    continue
                na = min(na, 4096)
                px[:] = [c_div(s * sa + (g << 12), na)
                         for s, g in ((sy, px[0]), (scb, px[1]), (scr, px[2]))] + [na]


def _glow_only(px: list) -> None:
    if px[0] <= 0:
        px[:] = [0, 0, 0, 0]
        return
    a = min(px[0], 4096)
    px[:] = [c_div(px[0] << 12, a), c_div(px[1] << 12, a), c_div(px[2] << 12, a), a]


def composite_frame(acc, frame, w, h, rx, ry) -> None:
    for y in range(h):
        for x in range(w):
            for c in range(3):
                frame[y][x][c] += acc[ry + y][rx + x][c]


# --------------------------------------------------------------------------
# the whole thing

def glow(src, w, h, *, strength, spread, threshold_raw, blur,
         shape="通常", colour=None, light_only=False):
    """Returns (buffer, W, H) - the object as func_proc leaves it."""
    rx = ry = spread
    diag = min(rx, ry)                                    # verify_diag_radius.py
    threshold = (threshold_raw * 4096) // 1000

    W, H = w + 2 * rx, h + 2 * ry
    scratch = new_buffer(W, H)
    extract(src, w, h, scratch, threshold, colour, premultiply=True)

    acc = new_buffer(W, H, (0, 0, 0, 4096))               # table[0x48], opaque black
    if shape == "通常":
        for y in range(h):                                # table[0x44] at 0x100551df
            for x in range(w):
                acc[ry + y][rx + x][:3] = scratch[y][x][:3]
        shape_normal(acc, scratch, W, H, rx, strength)
    else:
        kinds = {"クロス(4本)": ["縦", "横"], "クロス(4本斜め)": ["斜め"],
                 "クロス(8本)": ["縦", "横", "斜め"],
                 "ライン(横)": ["横"], "ライン(縦)": ["縦"]}[shape]
        shape_streaks(acc, scratch, w, h, rx, ry, diag, strength, kinds)

    if blur > 0:
        for _ in range(2):
            vertical_average(acc, scratch, W, H, blur)
            horizontal_average(scratch, acc, W, H, blur)

    if not light_only:
        composite_object(acc, src, w, h, rx, ry)
    return acc, W, H


# --------------------------------------------------------------------------
# pictures

RAMP = " .:-=+*#%@"


def show(buf, W, H, channel=0, scale=None, title=""):
    """scale=None auto-scales to the picture's own peak, which is what makes a
    weak glow readable; a fixed scale is for comparing two pictures."""
    top = scale or max(1, max(buf[y][x][channel] for y in range(H) for x in range(W)))
    print(f"\n  {title}")
    for y in range(H):
        row = "".join(RAMP[min(len(RAMP) - 1, max(0, buf[y][x][channel] * len(RAMP) // top))]
                      for x in range(W))
        print(f"    {row}")


def test_sprite(w, h):
    """An opaque white cross on a transparent field, plus one red dot."""
    img = new_buffer(w, h)
    for y in range(h):
        for x in range(w):
            if abs(x - w // 2) <= 1 or abs(y - h // 2) <= 1:
                img[y][x] = [4096, 0, 0, 4096]
    img[2][2] = [1224, -692, 2047, 4096]         # #ff0000
    return img


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="simulate_glow_reference")
    ap.add_argument("--shape", choices=SHAPES, default=None)
    ap.add_argument("--spread", type=int, default=10)
    ap.add_argument("--strength", type=int, default=400, help="raw 強さ (UI x10)")
    ap.add_argument("--threshold", type=int, default=400, help="raw しきい値 (UI x10)")
    ap.add_argument("--blur", type=int, default=0)
    args = ap.parse_args(argv or [])

    w = h = 21
    src = test_sprite(w, h)
    print("AviUtl's registered defaults are 強さ=40.0 拡散=30 しきい値=40.0 ぼかし=1;")
    print("拡散=30 would swamp a 21x21 sprite, so the pictures use a smaller one.")
    print(f"\nsource: {w}x{h} opaque white cross with one #ff0000 pixel at (2,2)")
    show(src, w, h, 0, 4096, "source luma")

    shapes = [args.shape] if args.shape else SHAPES
    for shape in shapes:
        acc, W, H = glow(src, w, h, strength=args.strength, spread=args.spread,
                         threshold_raw=args.threshold, blur=args.blur, shape=shape)
        peak = max(px[0] for row in acc for px in row)
        opaque = sum(1 for row in acc for px in row if px[3] >= 4096)
        show(acc, W, H, 3, None,
             f"形状={shape}  拡散={args.spread} 強さ={args.strength / 10} "
             f"しきい値={args.threshold / 10} ぼかし={args.blur}  "
             f"-> {W}x{H}, peak luma {peak}, {opaque} opaque px   [ALPHA, auto-scaled]")
        mid = acc[H // 2]
        print("      middle-row alpha: " + " ".join(f"{px[3]:>4}" for px in mid[:W // 2 + 1]))

    print("\n--- 通常 pass by pass: the accumulation buffer as the cascade builds ---")
    for stop in range(1, 5):
        acc = _normal_partial(src, w, h, args, stop)
        W, H = w + 2 * args.spread, h + 2 * args.spread
        peak = max(px[0] for row in acc for px in row)
        show(acc, W, H, 0, None,
             f"after {stop} of 4 passes, before the composite (peak luma {peak})")

    print("\n--- 光成分のみ leaves the canvas opaque ---")
    for light_only in (False, True):
        acc, W, H = glow(src, w, h, strength=args.strength, spread=args.spread,
                         threshold_raw=args.threshold, blur=args.blur,
                         shape="通常", light_only=light_only)
        corner = acc[0][0]
        print(f"  光成分のみ={'on ' if light_only else 'off'}  corner pixel = {corner}"
              f"   ({'opaque black' if corner[3] else 'transparent'})")

    print("\n--- 光色の設定 changes the curve, not just the hue ---")
    for name, colour in (("指定なし", None), ("#ffffff", (4095, 0, 0)),
                         ("#ff0000", (1224, -692, 2047)), ("#0000ff", (466, 2047, -333))):
        acc, W, H = glow(src, w, h, strength=args.strength, spread=args.spread,
                         threshold_raw=args.threshold, blur=args.blur,
                         shape="通常", colour=colour)
        peak = max(px[0] for row in acc for px in row)
        halo = acc[H // 2][max(0, args.spread - 3)]
        print(f"  {name:<9} peak luma {peak:>5}   halo pixel 3px outside the object "
              f"{str(halo):>28}")
    print("  a dark 光色 dims the whole glow because its Y multiplies the extraction")
    print("  before any of the blurring happens.")


def _normal_partial(src, w, h, args, stop):
    """Re-run 通常 but stop after `stop` passes, to show the cascade building up."""
    rx = ry = args.spread
    W, H = w + 2 * rx, h + 2 * ry
    threshold = (args.threshold * 4096) // 1000
    scratch = new_buffer(W, H)
    extract(src, w, h, scratch, threshold, None, True)
    acc = new_buffer(W, H, (0, 0, 0, 4096))
    for y in range(h):
        for x in range(w):
            acc[ry + y][rx + x][:3] = scratch[y][x][:3]
    s = args.strength * 3 * 2
    for i, divisor in enumerate((8, 6, 4, 2)):
        if i == stop:
            break
        vertical_average(acc, scratch, W, H, c_div(rx, divisor))
        if i == 0:
            for row in acc:
                for px in row:
                    px[0] = px[1] = px[2] = 0
        horizontal_accumulate(scratch, acc, W, H, c_div(rx, divisor), s)
        s = c_div(s, 2)
    return acc


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
