"""An integer-faithful reimplementation of 拡散光, plus the checks that the
rest of this directory's findings actually fit together.

Everything here follows the disassembly, not the prose: the radius split from
verify_radius_split.py, the box average and its two different divisors from
verify_box_average.py, the window geometry from verify_canvas_growth.py, and
the merge rule from verify_composite.py. The three variants are all
implemented, because they differ in ways that matter:

    diffusion_light_object(..., size_fixed=False)  canvas grows by 拡散 a side
    diffusion_light_object(..., size_fixed=True)   canvas fixed
    diffusion_light_frame(...)                     PIXEL_YC, no alpha

The self-checks at the bottom are the point of the file. The strongest of them
is that a flat opaque image comes back bit-identical inside its original
bounds: that only holds if the box average, the alpha weighting and the
"only brighten" test are all right at once, since the blur of a constant has
to reproduce the constant exactly and then fail the d > 0 test everywhere.

Run via main.py:
    uv run main.py inspect/diffusion_light/simulate_diffusion_light.py
    uv run main.py inspect/diffusion_light/simulate_diffusion_light.py --size 32 --diffusion 6
"""

import argparse

from tools.cints import c_div

SPLIT_K = 0.44722719141323786   # the double at 0x1009a468; == 1/2.236
MAGIC_1000 = 0x10624DD3


def strength_q12(raw: int) -> int:
    """func_proc 0x1001c343-0x1001c358."""
    return raw * 4096 // 1000


def radii(diffusion_raw: int) -> tuple[int, int]:
    """func_proc 0x1001c431-0x1001c444. Round 1 uses the larger radius."""
    r2 = int(diffusion_raw * SPLIT_K)
    return diffusion_raw - r2, r2


# --------------------------------------------------------------------------
# object effect (PIXEL_YCA, 8 bytes/pixel)
# --------------------------------------------------------------------------

def _window(centre: int, r: int, n: int, grow: bool) -> range:
    """Source indices summed for output index `centre`.

    The growing workers slide a window of [d-2r, d] over a source that is
    conceptually shifted r forward - which is the same thing as [d'-r, d'+r]
    around source index d' = d - r. The fixed-size ones use [d-r, d+r]
    directly. Both are clipped to the image.
    """
    lo, hi = (centre - 2 * r, centre) if grow else (centre - r, centre + r)
    return range(max(lo, 0), min(hi, n - 1) + 1)


def _average(samples, kernel_width: int, grow: bool):
    """One output pixel of an object box pass (0x1001c7a1-0x1001c86b).
    Returns (y, cb, cr, alpha_sum); y/cb/cr are None when nothing was visible."""
    sy = scb = scr = sa = 0
    for y, cb, cr, a in samples:
        if a == 0:
            continue
        if a >= 0x1000:
            sy += y
            scb += cb
            scr += cr
        else:
            sy += (y * a) >> 12
            scb += (cb * a) >> 12
            scr += (cr * a) >> 12
        sa += a
    n = kernel_width if grow else len(samples)
    if sa == 0:
        return None, None, None, 0
    return c_div(sy * 4096, sa), c_div(scb * 4096, sa), c_div(scr * 4096, sa), c_div(sa, n)


def _composite(src, gy, gcb, gcr, ga):
    """0x1001cdd8-0x1001cf83."""
    s_y, s_cb, s_cr, s_a = src
    if gy is None or gy <= 0:
        return src
    d = gy - max(0, (s_y * s_a) >> 12)
    if d <= 0:
        return src
    base = gy - d
    pcb = (s_cb * s_a) >> 12
    pcr = (s_cr * s_a) >> 12
    cb = c_div(pcb * base + d * gcb, gy)
    cr = c_div(pcr * base + d * gcr, gy)
    if ga >= 0x1000:
        return gy, cb, cr, 0x1000
    if s_a >= 0x1000:
        ia = 0x1000 - ga
        return ((s_y * ia + gy * ga) >> 12, (s_cb * ia + cb * ga) >> 12,
                (s_cr * ia + cr * ga) >> 12, 0x1000)
    if s_a <= 0:
        return gy, cb, cr, ga
    ia = 0x1000 - ga
    na = (0x1000800 - (0x1000 - s_a) * ia) >> 12
    w_src = c_div(ia * s_a, na)
    w_glow = c_div(ga << 12, na)
    return ((s_y * w_src + gy * w_glow) >> 12, (s_cb * w_src + cb * w_glow) >> 12,
            (s_cr * w_src + cr * w_glow) >> 12, na)


def _object_round(img, w, h, r, strength, grow):
    """One (vertical, horizontal + composite) pair. Returns (img, w, h)."""
    if r <= 0:
        return img, w, h
    kw = 2 * r + 1
    out_h = h + 2 * r if grow else h
    out_w = w + 2 * r if grow else w

    # vertical: img -> mid, one column at a time
    mid = [[(0, 0, 0, 0)] * w for _ in range(out_h)]
    for x in range(w):
        for d in range(out_h):
            y, cb, cr, a = _average([img[sy][x] for sy in _window(d, r, h, grow)], kw, grow)
            prev = mid[d][x]
            mid[d][x] = (prev[0], prev[1], prev[2], a) if y is None else (y, cb, cr, a)

    # horizontal + composite: mid -> out, one row at a time
    out = [[(0, 0, 0, 0)] * out_w for _ in range(out_h)]
    for d in range(out_h):
        sy = d - r if grow else d
        for e in range(out_w):
            gy, gcb, gcr, sa = _average([mid[d][sx] for sx in _window(e, r, w, grow)], kw, grow)
            ga = (sa * strength) >> 12
            sx = e - r if grow else e
            src = img[sy][sx] if 0 <= sy < h and 0 <= sx < w else (0, 0, 0, 0)
            out[d][e] = _composite(src, gy, gcb, gcr, ga)
    return out, out_w, out_h


def diffusion_light_object(img, w, h, strength_raw, diffusion_raw, size_fixed=False):
    """The object-effect version. `img` is [h][w] of (y, cb, cr, a)."""
    if strength_raw == 0:                       # 0x1001c33d
        return img, w, h
    strength = strength_q12(strength_raw)
    r1, r2 = radii(diffusion_raw)
    grow = not size_fixed
    # 0x1001c45e: a radius too large relative to the image is handled by growing
    # the canvas up-front and then running the fixed-size workers instead.
    if grow and any(2 * r >= w or 2 * r >= h for r in (r1, r2)):
        rad = r1 + r2
        canvas = [[(0, 0, 0, 0)] * (w + 2 * rad) for _ in range(h + 2 * rad)]
        for y in range(h):
            canvas[y + rad][rad:rad + w] = img[y]
        img, w, h, grow = canvas, w + 2 * rad, h + 2 * rad, False
    for r in (r1, r2):
        img, w, h = _object_round(img, w, h, r, strength, grow)
    return img, w, h


# --------------------------------------------------------------------------
# frame filter (PIXEL_YC, 6 bytes/pixel, no alpha)
# --------------------------------------------------------------------------

def _frame_average(samples):
    """0x1001e5d4-0x1001e610: plain box average, one idiv per channel."""
    n = len(samples)
    return tuple(c_div(sum(s[c] for s in samples), n) for c in range(3))


def _frame_composite(src, glow, strength):
    """0x1001e898-0x1001e935."""
    gy, gcb, gcr = glow
    if gy <= 0:
        return src
    d = gy - max(0, src[0])
    if d <= 0:
        return src
    base = gy - d
    merged = (gy, c_div(src[1] * base + d * gcb, gy), c_div(src[2] * base + d * gcr, gy))
    if strength >= 0x1000:
        return merged
    return tuple(c + (((m - c) * strength) >> 12) for c, m in zip(src, merged))


def diffusion_light_frame(img, w, h, strength_raw, diffusion_raw):
    """The frame-filter version. `img` is [h][w] of (y, cb, cr)."""
    if strength_raw == 0:
        return img
    strength = strength_q12(strength_raw)
    for r in radii(diffusion_raw):
        if r <= 0:
            continue
        mid = [[_frame_average([img[sy][x] for sy in _window(d, r, h, False)])
                for x in range(w)] for d in range(h)]
        img = [[_frame_composite(img[d][e],
                                 _frame_average([mid[d][sx] for sx in _window(e, r, w, False)]),
                                 strength)
                for e in range(w)] for d in range(h)]
    return img


# --------------------------------------------------------------------------

def _square(size, box, luma=4096, cb=0, cr=0):
    """A bright opaque square centred in a transparent canvas."""
    lo, hi = (size - box) // 2, (size + box) // 2
    return [[(luma, cb, cr, 4096) if lo <= x < hi and lo <= y < hi else (0, 0, 0, 0)
             for x in range(size)] for y in range(size)]


def _show(img, channel=3, scale=4096):
    ramp = " .:-=+*#%@"
    for row in img:
        print("    " + "".join(ramp[min(len(ramp) - 1, max(0, px[channel]) * len(ramp) // (scale + 1))]
                               for px in row))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size", type=int, default=24, help="test canvas edge (default 24)")
    parser.add_argument("--diffusion", type=int, default=5, help="拡散 raw value (default 5)")
    parser.add_argument("--strength", type=int, default=1000, help="強さ raw value (default 1000)")
    args = parser.parse_args(argv or [])

    size, box = args.size, max(4, args.size // 3)
    r1, r2 = radii(args.diffusion)
    print(f"拡散={args.diffusion} -> radii {r1}, {r2};  強さ={args.strength / 10:.1f} "
          f"-> strength={strength_q12(args.strength)}")

    print(f"\n--- object effect, サイズ固定 OFF: {size}x{size} square, alpha channel ---")
    src = _square(size, box)
    out, ow, oh = diffusion_light_object(src, size, size, args.strength, args.diffusion)
    print(f"  input {size}x{size}, output {ow}x{oh} "
          f"(grew by {args.diffusion} a side, as r1+r2={r1 + r2})")
    _show(out)

    print("\n--- the same input with サイズ固定 ON (alpha) ---")
    out_fixed, fw, fh = diffusion_light_object(src, size, size, args.strength,
                                               args.diffusion, size_fixed=True)
    print(f"  output {fw}x{fh}")
    _show(out_fixed)

    print("\n--- checks ---")

    def check(name, ok):
        print(f"  [{'ok ' if ok else 'FAIL'}] {name}")
        return ok

    everything = True

    # 強さ=0 and 拡散=0 are both no-ops, for different reasons.
    o, w_, h_ = diffusion_light_object(src, size, size, 0, args.diffusion)
    everything &= check("強さ=0 returns the image untouched (func_proc's early return)",
                        o == src and (w_, h_) == (size, size))
    o, w_, h_ = diffusion_light_object(src, size, size, args.strength, 0)
    everything &= check("拡散=0 leaves both radii at 0, so nothing runs",
                        o == src and (w_, h_) == (size, size))

    # A flat opaque field must survive exactly: the box average of a constant is
    # the constant, so d == 0 everywhere and the composite copies the source.
    flat = [[(2000, 300, -200, 4096)] * size for _ in range(size)]
    o, _, _ = diffusion_light_object(flat, size, size, args.strength, args.diffusion,
                                     size_fixed=True)
    everything &= check("flat opaque image, サイズ固定 ON: bit-identical output", o == flat)
    o, ow2, oh2 = diffusion_light_object(flat, size, size, args.strength, args.diffusion)
    inner = [row[args.diffusion:args.diffusion + size]
             for row in o[args.diffusion:args.diffusion + size]]
    everything &= check("flat opaque image, サイズ固定 OFF: unchanged inside the old bounds",
                        inner == flat)
    everything &= check("... and the new border is not fully opaque (it fades out)",
                        o[0][0][3] < 0x1000)

    # The frame version on the same flat field, and its monotonicity.
    fflat = [[(2000, 300, -200)] * size for _ in range(size)]
    everything &= check("frame filter: flat image is bit-identical",
                        diffusion_light_frame(fflat, size, size, args.strength,
                                              args.diffusion) == fflat)
    grad = [[(x * 4096 // size, -400, 600) for x in range(size)] for _ in range(size)]
    fout = diffusion_light_frame(grad, size, size, args.strength, args.diffusion)
    everything &= check("frame filter never darkens a pixel",
                        all(o[0] >= i[0] for orow, irow in zip(fout, grad)
                            for o, i in zip(orow, irow)))

    # The composite is a source-over, so alpha can only go up.
    everything &= check("object effect never lowers alpha inside the old bounds",
                        all(o[y + args.diffusion][x + args.diffusion][3] >= src[y][x][3]
                            for y in range(size) for x in range(size)))

    # The two radii run in sequence on the *composited* result, so the result of
    # (r1, r2) is not the result of a single blur - a sanity check that the
    # second round really sees the first round's output.
    one_round, _, _ = diffusion_light_object(src, size, size, args.strength, r1)
    everything &= check("running only r1 differs from running r1 then r2",
                        one_round != out if r2 else True)

    print(f"\n  {'all checks passed' if everything else 'SOME CHECKS FAILED'}")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
