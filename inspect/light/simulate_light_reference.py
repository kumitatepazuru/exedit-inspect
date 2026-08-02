"""An integer-faithful reimplementation of ライト, and a render that shows what
each parameter actually looks like.

Assembled from disasm_params.py / verify_params.py / verify_shading.py /
verify_halo.py, using the same integer semantics as the original: `idiv`
truncates toward zero (`c_div`), `sar` floors, the two magic-number divides
(`/1000`, `/11`) are the exact MSVC sequences, and the halo's alpha is the only
value ever hard-clamped.

What is *not* modelled, and why it does not affect the demo:

  * the multi-thread split. Every worker here only ever accumulates along one
    axis at a time with no cross-thread state, so a single-threaded pass
    produces identical output.
  * `table[0x44]`'s own internals (0x10081b40) - only its documented effect is
    used (composite_normal(), straight from blend_modes.md §3), since that
    routine is shared infrastructure this analysis did not re-derive.
  * the canvas-size clamps' actual DLL globals (0x10196748 etc.) - `setup()`
    takes them as parameters with generous defaults, exactly like
    inspect/glint/simulate_glint_reference.py's `grow()` does.

Run via main.py:
    uv run main.py inspect/light/simulate_light_reference.py
    uv run main.py inspect/light/simulate_light_reference.py --ratio -100
    uv run main.py inspect/light/simulate_light_reference.py --backlight --colour 3060ff
"""

import argparse

from tools.cints import c_div, msvc_div

MAGIC_1000 = 0x10624DD3
MAGIC_11 = 0x2E8BA2E9
FULL = 4096


# ---------------------------------------------------------------- parameters

def setup(w, h, raw_strength, raw_ratio, raw_spread,
          max_w=4096, max_h=4096, stride=None, rows=None):
    """func_proc 0x1005ba30..0x1005bc36. Returns None when 強さ=0 (no-op)."""
    if raw_strength == 0:
        return None
    s = msvc_div(raw_strength * 4096, MAGIC_1000, 6)
    a = s if raw_ratio >= 0 else msvc_div(s * (raw_ratio + 1000), MAGIC_1000, 6)
    b = s if raw_ratio <= 0 else msvc_div(s * (1000 - raw_ratio), MAGIC_1000, 6)

    r = raw_spread
    if 2 * r + 1 >= w:
        r = c_div(w, 2) - 2
    if 2 * r + 1 >= h:
        r = c_div(h, 2) - 2
    r = max(r, 0)
    if w + 2 * r > max_w:
        r = c_div(max_w - w, 2)
    if h + 2 * r > max_h:
        r = c_div(max_h - h, 2)

    # clamp #2 only matters once A > 0 (it feeds the halo pass); computed
    # unconditionally here since the demo always wants both numbers to hand.
    # The real (stride, rows) come from how exedit pre-allocates the object's
    # buffer, which this analysis did not independently pin down - stand-ins
    # with generous headroom, same spirit as glint's grow() taking max_w/max_h
    # as parameters instead of reading the DLL's globals.
    stride = stride if stride is not None else w + 256
    rows = rows if rows is not None else h + 256
    r2 = r
    if 2 * r2 > stride - w:
        r2 = c_div(stride - w, 2)
    if 2 * r2 > rows - h:
        r2 = c_div(rows - h, 2)

    return {"w": w, "h": h, "S": s, "A": a, "B": b, "r": r, "r2": r2}


def rgb_to_ycbcr(rgb: str):
    """0x1006fed0's shared conversion, Q14 BT.601 full-range (rgb_ycbcr.md),
    scaled the same way inspect/glint's demo does for a hex colour string."""
    r, g, b = (int(rgb[i:i + 2], 16) for i in (0, 2, 4))
    y = int((0.299 * r + 0.587 * g + 0.114 * b) * 4096 / 255)
    cb = int((-0.169 * r - 0.331 * g + 0.500 * b) * 4096 / 255)
    cr = int((0.500 * r - 0.419 * g - 0.081 * b) * 4096 / 255)
    return y, cb, cr


# --------------------------------------------------------- box-average passes

def _box_average_same(values, r):
    """No growth (the gradient pass, sub_1005c080/sub_1005c520): output index
    j in 0..n-1 covers window [j-r, j+r] clipped to the real range, always
    divided by the full kernel width k=2r+1 - the same windowed-sum shape
    verify_shading.py's box_average() checks against the raw phase structure
    (a silent r-sample pre-accumulation, then r+1 accumulate+emit, a steady
    middle run, then a r-iteration evict-only tail)."""
    n = len(values)
    k = 2 * r + 1
    out = []
    for j in range(n):
        lo, hi = max(0, j - r), min(n - 1, j + r)
        out.append(c_div(sum(values[lo:hi + 1]), k))
    return out


def _box_average_grow(values, r):
    """Grows the axis by 2r (the halo pass, sub_1005bcd0/sub_1005be50):
    output index j in 0..n+2r-1 covers window [j-2r, j] clipped to the real
    range - verify_halo.py's grow_1d(), checked there against the literal
    head/middle/tail loop bounds."""
    n = len(values)
    k = 2 * r + 1
    total = 0
    out = []
    for j in range(n + 2 * r):
        if 0 <= j < n:
            total += values[j]
        if 0 <= j - k < n:
            total -= values[j - k]
        out.append(c_div(total, k))
    return out


def box_average_2d(w, h, alpha, r, grow):
    """Vertical pass (per column) then horizontal pass (per row). Returns a
    (new_w, new_h, grid) - grow=False keeps (w, h); grow=True yields
    (w+2r, h+2r), matching sub_1005bcd0+sub_1005be50 vs sub_1005c080+
    sub_1005c250 / sub_1005c520+sub_1005c700."""
    pass_1d = _box_average_grow if grow else _box_average_same
    cols = [[alpha[y * w + x] for y in range(h)] for x in range(w)]
    v = [pass_1d(col, r) for col in cols]     # each is h(+2r) long
    new_h = len(v[0])
    rows_ = [[v[x][y] for x in range(w)] for y in range(new_h)]
    h_pass = [pass_1d(row, r) for row in rows_]
    new_w = len(h_pass[0])
    grid = [h_pass[y][x] for y in range(new_h) for x in range(new_w)]
    return new_w, new_h, grid


# ----------------------------------------------------------------- the passes

def gradient_pass(w, h, px, p, light, backlight):
    """Tints px (list of [y, cb, cr, a], mutated in place) using B."""
    if p["B"] <= 0:
        return
    alpha = [pix[3] for pix in px]
    if backlight:
        src = [FULL - a for a in alpha]
    else:
        src = alpha
    _, _, avg = box_average_2d(w, h, src, p["r"], grow=False)

    if backlight:
        coef = p["B"]
    else:
        coef = msvc_div(p["B"] * 2, MAGIC_11, 1)

    ly, lcb, lcr = light
    for i in range(w * h):
        a = avg[i]
        m = c_div(a * coef, FULL) if backlight else c_div((a + FULL) * coef, FULL)
        if m <= 0:
            continue
        if m >= FULL:
            px[i][0] += ly
            px[i][1] += lcb
            px[i][2] += lcr
        else:
            px[i][0] += (ly * m) >> 12
            px[i][1] += (lcb * m) >> 12
            px[i][2] += (lcr * m) >> 12


def halo_layer(w, h, px, p, light):
    """The separate, larger canvas of flat light colour, amplify-multiply
    encoded (Y pinned to FULL, alpha carries the payload)."""
    alpha = [pix[3] for pix in px]
    gw, gh, avg2d = box_average_2d(w, h, alpha, p["r2"], grow=True)
    ly, lcb, lcr = light
    out = []
    for a in avg2d:
        scale = c_div(a * p["A"], FULL)
        if scale > FULL:
            scale = FULL
        alpha_out = c_div(ly * scale, FULL)
        out.append([FULL, lcb, lcr, alpha_out])
    return gw, gh, out


def composite_normal(dst, src):
    """table[0x44] mode=3: src-over-dst (blend_modes.md §3), trunc division."""
    a_d, a_s = dst[3], src[3]
    out_a = FULL - (((FULL - a_d) * (FULL - a_s)) >> 12)
    if out_a <= 0:
        return [0, 0, 0, 0]
    out = [0, 0, 0, out_a]
    for c in range(3):
        num = src[c] * a_s + (dst[c] * a_d * (FULL - a_s) >> 12)
        out[c] = c_div(num, out_a)
    return out


def render(w, h, px, p, light, backlight):
    """One frame. px is [y, cb, cr, a] per pixel, mutated for the gradient
    tint. Returns (out_w, out_h, pixels) - grown iff A > 0."""
    gradient_pass(w, h, px, p, light, backlight)
    if p["A"] <= 0:
        return w, h, px  # halo, growth and the final composite are all skipped
    gw, gh, halo = halo_layer(w, h, px, p, light)
    r2 = p["r2"]
    out = [row[:] for row in halo]
    for y in range(h):
        for x in range(w):
            gi = (y + r2) * gw + (x + r2)
            out[gi] = composite_normal(halo[gi], px[y * w + x])
    return gw, gh, out


# ------------------------------------------------------------------- demo art

def make_circle(w, h, radius, y=3000, cb=0, cr=0):
    """A filled circle, opaque core with a soft 2px anti-aliased ring, on an
    otherwise fully transparent canvas - the shape used to show interior-
    bright (gradient OFF) vs edge-bright (逆光/ON) directly."""
    cx, cy = w // 2, h // 2
    px = []
    for y_ in range(h):
        for x_ in range(w):
            d = ((x_ - cx) ** 2 + (y_ - cy) ** 2) ** 0.5
            if d <= radius - 2:
                a = FULL
            elif d <= radius:
                a = int(FULL * (radius - d) / 2)
            else:
                a = 0
            px.append([y, cb, cr, a])
    return px


def ascii_art(w, h, px, cols=48, rows=22, channel=3, scale=FULL):
    """Max-pooled greyscale of one channel (default: alpha)."""
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
    parser.add_argument("--strength", type=int, default=1000, help="raw 強さ, 0..3000")
    parser.add_argument("--ratio", type=int, default=0, help="比率 shown value, -100..100")
    parser.add_argument("--spread", type=int, default=8, help="raw 拡散 (also the radius)")
    parser.add_argument("--colour", default="ff3020", help="light colour as rrggbb")
    parser.add_argument("--backlight", action="store_true", help="check 逆光")
    parser.add_argument("--size", type=int, default=60, help="canvas is size x size")
    args = parser.parse_args(argv or [])

    n = args.size
    light = rgb_to_ycbcr(args.colour)
    px = make_circle(n, n, n // 3)

    p = setup(n, n, args.strength, args.ratio * 10, args.spread)
    if p is None:
        print("強さ = 0: func_proc returns immediately, nothing is touched")
        return

    print(f"canvas {n}x{n}, 強さ raw={args.strength} ({args.strength/10:.1f}%), "
          f"比率={args.ratio:+d}%, 拡散(=r)={args.spread}, 逆光={'ON' if args.backlight else 'off'}")
    print(f"  S={p['S']}  A={p['A']}  B={p['B']}  r(clamp #1)={p['r']}  r(clamp #2)={p['r2']}")

    gw, gh, out = render(n, n, [row[:] for row in px], p, light, args.backlight)
    if gw != n:
        print(f"  output size {gw}x{gh} (grown by {gw-n}x{gh-n})")
    else:
        why = "A<=0, no halo at all" if p["A"] <= 0 else "r(clamp #2)=0, halo present but not grown"
        print(f"  output size {gw}x{gh} (unchanged - {why})")
    print("  composited alpha (the visible silhouette, halo included):")
    for line in ascii_art(gw, gh, out, channel=3, scale=FULL):
        print("  " + line)

    if p["A"] > 0:
        print("\nsame settings, the halo layer alone (its own alpha, before the object is drawn on top):")
        _, _, halo_only = halo_layer(n, n, px, p, light)
        for line in ascii_art(gw, gh, halo_only, channel=3, scale=FULL):
            print("  " + line)
    else:
        print("\n比率=-100% -> A=0, there is no halo layer at all this frame.")

    print("\n--- 逆光 off vs on, same 比率: a scanline through the centre (y = n/2) ---")
    print("  wherever the object is fully opaque (a_s=4096) the composite formula makes the")
    print("  halo's own contribution vanish entirely (out_a=4096, out_c=src_c) - so the Y values")
    print("  in that region are a direct, unobstructed reading of the gradient pass alone.")
    print(f"  {'x':>4}{'src a':>7}{'OFF: comp a':>13}{'OFF: Y':>8}{'ON: comp a':>12}{'ON: Y':>7}")
    off_w, off_h, off_out = render(n, n, [row[:] for row in make_circle(n, n, n // 3)], p, light, False)
    on_w, on_h, on_out = render(n, n, [row[:] for row in make_circle(n, n, n // 3)], p, light, True)
    # the offset into the (possibly grown) output is 0 when A<=0 (no growth at
    # all - render() returns the object buffer unchanged) and r2 otherwise.
    off_shift = (off_w - n) // 2
    on_shift = (on_w - n) // 2
    cy = n // 2
    for x in range(0, n, max(1, n // 20)):
        a_src = px[cy * n + x][3]
        off_gi = (cy + off_shift) * off_w + (x + off_shift)
        on_gi = (cy + on_shift) * on_w + (x + on_shift)
        print(f"  {x:>4}{a_src:>7}{off_out[off_gi][3]:>13}{off_out[off_gi][0]:>8}{on_out[on_gi][3]:>12}{on_out[on_gi][0]:>7}")
    print("  (OFF's Y peaks at the centre of the solid disc; ON's Y peaks near its rim and")
    print("  drops off toward the centre - verify_shading.py §4 shows the same shape in isolation.)")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
