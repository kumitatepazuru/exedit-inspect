"""An integer-faithful reimplementation of シャドー, and a render that shows
what each parameter actually does.

Assembled from disasm_params.py / verify_params.py / verify_blur_chain.py /
verify_geometry.py / verify_encode.py, keeping the original's arithmetic:
`idiv` truncates toward zero (`c_div`), the one `/1000` is the exact MSVC
sequence, the four box passes divide by their full kernel width, and the
output alpha goes through the same divide-then-multiply in floating point that
the x87 code does (verify_encode.py §3 - the reason a solid interior is
sometimes 4095 rather than 4096).

What is *not* modelled, and why it does not change the demo:

  * the multi-thread split. Each pass accumulates along one axis with no
    cross-thread state, so one thread produces identical output.
  * `table[0x44]` / `table[0x48]` internals - only their documented effects are
    used (composite_normal() and a flat fill, blend_modes.md §3/§4).
  * the pattern-image path, beyond `--pattern-alpha`: loading and tiling a real
    image is exedit-side work this analysis did not re-derive, but the encoder
    only ever sees the tiled result's alpha, so a constant stands in for it.
  * `影を別オブジェクトで描画`, which does not change any pixel - it changes
    who owns them (verify_geometry.py §5).

Run via main.py:
    uv run main.py inspect/shadow/simulate_shadow_reference.py
    uv run main.py inspect/shadow/simulate_shadow_reference.py --x 30 --y -20 --spread 12
    uv run main.py inspect/shadow/simulate_shadow_reference.py --density 1000 --colour ff0000
"""

import argparse

from tools.cints import c_div, msvc_div

MAGIC_1000 = 0x10624DD3
FULL = 4096


# ---------------------------------------------------------------- parameters

def setup(w, h, raw_x, raw_y, raw_density, raw_spread, stride=None, rows=None):
    """func_proc 0x10087fb0..0x100881a8. Returns None when 濃さ = 0 (no-op).

    `stride` / `rows` stand in for fpip+0xEC / +0xF0, the allocated buffer's
    extents - this analysis did not pin down how exedit sizes them, so they
    default to something roomy (verify_params.py §4).
    """
    if raw_density == 0:
        return None
    stride = stride if stride is not None else w + 512
    rows = rows if rows is not None else h + 512

    density = msvc_div(raw_density * FULL, MAGIC_1000, 6)

    x, y = raw_x, raw_y
    if w + abs(x) > stride:
        x += (stride - w - abs(x)) if x > 0 else (w + abs(x) - stride)
    if h + abs(y) > rows:
        y += (rows - h - abs(y)) if y > 0 else (h + abs(y) - rows)
    grown_w, grown_h = w + abs(x), h + abs(y)

    r = raw_spread
    if 2 * r > stride - grown_w:
        r = c_div(stride - grown_w, 2)
    if 2 * r > rows - grown_h:
        r = c_div(rows - grown_h, 2)

    r1 = c_div(r, 2)
    return {
        "w": w, "h": h, "x": x, "y": y, "r": r, "density": density,
        "kernel_a": 2 * r1 + 1, "kernel_b": 2 * (r - r1) + 1,
        "canvas_w": grown_w + 2 * r, "canvas_h": grown_h + 2 * r,
        "shadow_x": max(x, 0), "shadow_y": max(y, 0),
        "object_x": max(-x, 0) + r, "object_y": max(-y, 0) + r,
    }


def rgb_to_ycbcr(rgb: str):
    """0x1006fed0's shared conversion, Q14 BT.601 full-range (rgb_ycbcr.md)."""
    r, g, b = (int(rgb[i:i + 2], 16) for i in (0, 2, 4))
    y = int((0.299 * r + 0.587 * g + 0.114 * b) * FULL / 255)
    cb = int((-0.169 * r - 0.331 * g + 0.500 * b) * FULL / 255)
    cr = int((0.500 * r - 0.419 * g - 0.081 * b) * FULL / 255)
    return y, cb, cr


# ------------------------------------------------------------- the four passes

def grow_1d(values, kernel):
    """One sliding-window pass: output j is the sum of the existing source
    samples in [j-kernel+1, j], divided by the FULL kernel width. Length
    n + kernel - 1 (verify_blur_chain.py §4)."""
    n = len(values)
    total, out = 0, []
    for j in range(n + kernel - 1):
        if j < n:
            total += values[j]
        if 0 <= j - kernel < n:
            total -= values[j - kernel]
        out.append(c_div(total, kernel))
    return out


def window_sums(values, kernel):
    """The same window, but WITHOUT the divide - what pass 4 actually carries,
    since its division is folded into the x87 scale (verify_encode.py)."""
    n = len(values)
    total, out = 0, []
    for j in range(n + kernel - 1):
        if j < n:
            total += values[j]
        if 0 <= j - kernel < n:
            total -= values[j - kernel]
        out.append(total)
    return out


def blur_alpha(alpha, w, h, ka, kb):
    """Passes 1-3, plus pass 4's window as raw sums.

    Returns (out_w, out_h, sums) where `sums` is row-major over
    (h + 2r) x (w + 2r) and each entry is the horizontal window sum pass 4
    multiplies by the x87 scale.
    """
    # pass 1: vertical, kernel B  (fpip+0xAC alpha -> plane 1)
    h1 = h + kb - 1
    p1 = [[0] * w for _ in range(h1)]
    for x in range(w):
        col = grow_1d([alpha[y][x] for y in range(h)], kb)
        for y, v in enumerate(col):
            p1[y][x] = v
    # pass 2: horizontal, kernel B  (plane 1 -> plane 2)
    w2 = w + kb - 1
    p2 = [grow_1d(row, kb) for row in p1]
    # pass 3: vertical, kernel A  (plane 2 -> plane 1)
    h3 = h1 + ka - 1
    p3 = [[0] * w2 for _ in range(h3)]
    for x in range(w2):
        col = grow_1d([p2[y][x] for y in range(h1)], ka)
        for y, v in enumerate(col):
            p3[y][x] = v
    # pass 4's window, undivided
    return w2 + ka - 1, h3, [window_sums(row, ka) for row in p3]


# ----------------------------------------------------------------- the render

def render(w, h, obj, p, colour, pattern_alpha=None, draw_object=True):
    """The whole of func_proc's unchecked-check[0] path.

    `obj` is row-major [(y, cb, cr, a)]; the returned canvas is the same shape.
    `pattern_alpha`, when given, stands in for the alpha of a tiled pattern
    image and switches to sub_10088bc0's encoder. `draw_object=False` stops
    before the final table[0x44] so the shadow layer can be seen on its own.
    """
    cw, ch = p["canvas_w"], p["canvas_h"]
    ka = p["kernel_a"]
    canvas = [[0, 0, 0, 0] for _ in range(cw * ch)]      # table[0x48]: transparent

    bw, bh, sums = blur_alpha([[obj[y][x][3] for x in range(w)] for y in range(h)],
                              w, h, ka, p["kernel_b"])
    scale = p["density"] / (ka * FULL)
    pat_scale = scale / FULL

    for row in range(bh):
        for col in range(bw):
            s = sums[row][col]
            px = canvas[(p["shadow_y"] + row) * cw + (p["shadow_x"] + col)]
            if pattern_alpha is not None:
                px[0], px[1], px[2] = colour        # stands in for the tiled pattern
                px[3] = int(pattern_alpha * s * pat_scale)
            elif s == 0:
                px[3] = 0                            # colour deliberately left alone
            else:
                px[0], px[1], px[2] = colour
                px[3] = int(s * scale)

    # table[0x44](..., mode=3): the object, unmodified, on top
    if draw_object:
        for y in range(h):
            for x in range(w):
                i = (p["object_y"] + y) * cw + (p["object_x"] + x)
                canvas[i] = composite_normal(canvas[i], obj[y][x])
    return cw, ch, canvas


def composite_normal(dst, src):
    """blend_modes.md §3, src over dst: out_a = a_d + a_s - a_d*a_s,
    out_c = (c_s*a_s + c_d*a_d*(1-a_s)) / out_a."""
    a_s, a_d = src[3], dst[3]
    out_a = FULL - ((FULL - a_d) * (FULL - a_s) + 0x800 >> 12)
    if out_a <= 0:
        return [0, 0, 0, 0]
    out = []
    for i in range(3):
        num = src[i] * a_s + c_div(dst[i] * a_d * (FULL - a_s), FULL * FULL)
        out.append(c_div(num, out_a))
    return out + [out_a]


# ----------------------------------------------------------------- the object

def make_disc(w, h, radius, colour=(3000, -200, 400)):
    """A soft-edged disc, so the shadow has something with a real silhouette."""
    cx, cy = w / 2, h / 2
    px = []
    for y in range(h):
        row = []
        for x in range(w):
            d = ((x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2) ** 0.5
            t = radius - d
            a = 0 if t <= 0 else (FULL if t >= 1.5 else int(FULL * t / 1.5))
            row.append([colour[0], colour[1], colour[2], a])
        px.append(row)
    return px


def ascii_art(w, h, px, cols=56, rows=24, channel=3, scale=FULL):
    ramp = " .:-=+*#%@"
    lines = []
    for r in range(rows):
        line = []
        for c in range(cols):
            xs, xe = c * w // cols, max(c * w // cols + 1, (c + 1) * w // cols)
            ys, ye = r * h // rows, max(r * h // rows + 1, (r + 1) * h // rows)
            v = max(px[y * w + x][channel] for y in range(ys, ye) for x in range(xs, xe))
            v = max(0, min(scale, v))
            line.append(ramp[min(len(ramp) - 1, v * len(ramp) // (scale + 1))])
        lines.append("".join(line))
    return lines


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--x", type=int, default=-40, help="raw X, -1000..1000 (pixels)")
    parser.add_argument("--y", type=int, default=24, help="raw Y, -1000..1000 (pixels)")
    parser.add_argument("--density", type=int, default=400, help="raw 濃さ, 0..1000")
    parser.add_argument("--spread", type=int, default=10, help="raw 拡散, 0..500 (= radius)")
    parser.add_argument("--colour", default="000000", help="影色 as rrggbb")
    parser.add_argument("--pattern-alpha", type=int, default=None,
                        help="stand-in for a tiled pattern image's alpha, 0..4096")
    parser.add_argument("--size", type=int, default=64, help="the object is size x size")
    args = parser.parse_args(argv or [])

    n = args.size
    colour = rgb_to_ycbcr(args.colour)
    obj = make_disc(n, n, n // 3)

    p = setup(n, n, args.x, args.y, args.density, args.spread)
    if p is None:
        print("濃さ = 0: func_proc returns immediately, nothing is touched at all.")
        return

    print(f"object {n}x{n}, X={args.x} Y={args.y} 濃さ={args.density / 10:.1f}% "
          f"拡散={args.spread}, 影色=#{args.colour} -> YCbCr{colour}")
    print(f"  density={p['density']}  r={p['r']}  kernelA={p['kernel_a']}  "
          f"kernelB={p['kernel_b']}  (support {p['kernel_a'] + p['kernel_b'] - 1} "
          f"= 2*{p['r']}+1)")
    print(f"  canvas {p['canvas_w']}x{p['canvas_h']}  shadow box at "
          f"({p['shadow_x']}, {p['shadow_y']})  object at "
          f"({p['object_x']}, {p['object_y']})")

    cw, ch, out = render(n, n, obj, p, colour, args.pattern_alpha)
    mode = "pattern" if args.pattern_alpha is not None else "影色"
    print(f"\n  composited alpha ({mode} encoder) - the object is the solid core, the "
          f"shadow the halo offset by ({args.x}, {args.y}):")
    for line in ascii_art(cw, ch, out, channel=3):
        print("  " + line)

    print("\n  the shadow layer alone, before the object is drawn on top:")
    _, _, shadow_only = render(n, n, obj, p, colour, args.pattern_alpha, draw_object=False)
    for line in ascii_art(cw, ch, shadow_only, channel=3):
        print("  " + line)

    for label, cy in (("the object's centre", p["object_y"] + n // 2),
                      ("the shadow's centre", p["shadow_y"] + p["r"] + n // 2)):
        print(f"\n--- a scanline through {label} (canvas row {cy}) ---")
        print(f"  {'x':>5}{'shadow a':>10}{'object a':>10}{'composited a':>14}{'comp Y':>9}")
        for x in range(0, cw, max(1, cw // 18)):
            ox, oy = x - p["object_x"], cy - p["object_y"]
            o_a = obj[oy][ox][3] if 0 <= ox < n and 0 <= oy < n else 0
            c = out[cy * cw + x]
            print(f"  {x:>5}{shadow_only[cy * cw + x][3]:>10}{o_a:>10}{c[3]:>14}{c[0]:>9}")
    print("\n  The two rows are 'Y' apart and the two peaks 'X' apart - a diagonal offset")
    print("  means no single scanline crosses both centres, which is the point of the pair.")
    peak = max(px[3] for px in shadow_only)
    print(f"\n  peak shadow alpha = {peak} of a possible {p['density']} "
          f"(濃さ = {args.density / 10:.1f}%)"
          + ("  <- one short, see verify_encode.py §3"
             if peak == p["density"] - 1 else ""))
    print("  The shadow never gets more opaque than 濃さ, whatever 影色 is: the colour goes")
    print("  into y/cb/cr and only the coverage goes into a (verify_encode.py §2).")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
