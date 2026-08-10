"""An integer-faithful reimplementation of シャープ, and a render that shows
what each parameter actually does.

Assembled from disasm_params.py / verify_param_scaling.py / verify_blur_chain.py
/ verify_unsharp.py / verify_luma_undershoot.py, keeping the original's
arithmetic: `sar` floors and `idiv` truncates toward zero (`c_div`), the one
`/1000` is the exact MSVC sequence, the box passes divide by the live sample
count, the combine divides *before* it scales by `強さ`, and the negative-luma
cleanup fades the chroma instead of clamping it.

What is *not* modelled, and why it does not change the demo:

  * the multi-thread split. The two box passes accumulate along one axis with
    no cross-thread state and the combine worker is per-pixel, so one thread
    produces identical output.
  * `table[0x44]`, whose only job here is a verbatim copy of the object image
    into the scratch buffer (mode `0x13000003`, blend_modes.md §3).
  * the 32-bit wraparound of `imul eax, 強さ` (verify_unsharp.py §4). Python
    ints do not overflow; the inputs that would trigger it need a blur alpha
    near 1 under an opaque original, which this demo does not construct.
  * the out-of-range reads when 範囲 exceeds the object (verify_blur_chain.py
    §4). Here the window is zero-filled past the edge, which is a guess at
    what the pair buffer holds - the real content is whatever was left there.

Run via main.py:
    uv run main.py inspect/sharp/simulate_sharp_reference.py
    uv run main.py inspect/sharp/simulate_sharp_reference.py --strength 2000 --range 3
"""

import argparse

from tools.cints import MAGIC_1000, c_div, msvc_div, sar

FULL = 4096


# ---------------------------------------------------------------- parameters

def setup(raw_strength, raw_range):
    """func_proc 0x10089030-0x10089092. None means "return 1, touch nothing"."""
    if raw_strength == 0 or raw_range == 0:
        return None
    r_lo = c_div(raw_range, 2)
    return {
        "strength": msvc_div(raw_strength * FULL, MAGIC_1000, 6),
        "r_hi": raw_range - r_lo,
        "r_lo": r_lo,
    }


# ------------------------------------------------------------- the box passes

class Acc:
    def __init__(self):
        self.y = self.cb = self.cr = self.a = 0

    def add(self, px, sign=1):
        y, cb, cr, a = px
        if a == 0:
            return
        if a < FULL:
            self.y += sign * ((y * a) >> 12)
            self.cb += sign * ((cb * a) >> 12)
            self.cr += sign * ((cr * a) >> 12)
        else:
            self.y += sign * y
            self.cb += sign * cb
            self.cr += sign * cr
        self.a += sign * a

    def emit(self, divisor, prev):
        if self.a != 0:
            y = int(self.y * 4096.0 / self.a)
            cb = int(self.cb * 4096.0 / self.a)
            cr = int(self.cr * 4096.0 / self.a)
        else:
            y, cb, cr = prev[:3]            # colour left untouched (box_blur.md §1)
        return (y, cb, cr, c_div(self.a, divisor))


def box_line(src, radius, dst):
    """0x100891c0 / 0x10089690 along one line. `dst` supplies the stale colour."""
    n, kernel = len(src), 2 * radius + 1
    acc, out, lead, trail = Acc(), [], 0, 0

    def read(i):
        return src[i] if 0 <= i < n else (0, 0, 0, 0)

    for _ in range(radius):
        acc.add(read(lead)); lead += 1
    for i in range(kernel - radius):
        acc.add(read(lead)); lead += 1
        out.append(acc.emit(radius + i + 1, dst[len(out)] if len(out) < n else dst[-1]))
    for _ in range(max(0, n - kernel)):
        acc.add(read(lead)); lead += 1
        acc.add(read(trail), sign=-1); trail += 1
        out.append(acc.emit(kernel, dst[len(out)]))
    for i in range(radius):
        acc.add(read(trail), sign=-1); trail += 1
        out.append(acc.emit(kernel - i - 1, dst[len(out)] if len(out) < n else dst[-1]))
    return out[:n]


def box_pass(img, w, h, radius, vertical, dst):
    out = list(dst)
    if vertical:
        for x in range(w):
            col = [img[y * w + x] for y in range(h)]
            res = box_line(col, radius, [dst[y * w + x] for y in range(h)])
            for y in range(h):
                out[y * w + x] = res[y]
    else:
        for y in range(h):
            row = img[y * w:(y + 1) * w]
            res = box_line(row, radius, dst[y * w:(y + 1) * w])
            out[y * w:(y + 1) * w] = res
    return out


# ------------------------------------------------------------- the combine

def combine_pixel(orig, blur, s):
    """0x10089b60's inner loop."""
    y0, cb0, cr0, a0 = orig
    yb, cbb, crb, ab = blur
    p = (ab * a0) >> 12
    if p == FULL:                                   # both fully opaque
        y = y0 + sar((y0 - yb) * s, 12)
        cb = cb0 + sar((cb0 - cbb) * s, 12)
        cr = cr0 + sar((cr0 - crb) * s, 12)
    elif p > 0:
        y = y0 + sar(c_div(a0 * y0 - ab * yb, p) * s, 12)
        cb = cb0 + sar(c_div(a0 * cb0 - ab * cbb, p) * s, 12)
        cr = cr0 + sar(c_div(a0 * cr0 - ab * crb, p) * s, 12)
    else:
        return (y0, cb0, cr0, a0)                   # blur discarded
    if y < 0:
        if y > -1024:
            cb = sar(cb * (y + 1024), 10)
            cr = sar(cr * (y + 1024), 10)
        else:
            cb = cr = 0
        y = 0
    return (y, cb, cr, a0)                          # alpha always the original's


def sharp(img, w, h, raw_strength=500, raw_range=5):
    cfg = setup(raw_strength, raw_range)
    if cfg is None:
        return list(img)
    orig = list(img)                                # table[0x44] -> the scratch
    cur, pair = list(img), [(0, 0, 0, 0)] * (w * h)
    for radius in (cfg["r_hi"], cfg["r_lo"]):
        if radius == 0:
            continue
        for vertical in (True, False):
            pair = box_pass(cur, w, h, radius, vertical, pair)
            cur, pair = pair, cur                   # func_proc swaps 0xAC/0xB0
    return [combine_pixel(orig[i], cur[i], cfg["strength"]) for i in range(w * h)]


# ------------------------------------------------------------------ demos

RAMP = " .:-=+*#%@"          # 0 .. 8192, so overshoot past 4096 stays visible


def luma_row(px, lo=0, hi=8192):
    out = []
    for p in px:
        v = max(lo, min(hi, p[0]))
        out.append(RAMP[min(len(RAMP) - 1, (v - lo) * len(RAMP) // (hi - lo + 1))])
    return "".join(out)


def tile(row, h):
    """Stack one row into an h-tall image, so the vertical passes see enough
    samples to be a no-op (verify_blur_chain.py §4)."""
    return [px for _ in range(h) for px in row]


def middle(img, w, h):
    return img[(h // 2) * w:(h // 2) * w + w]


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="simulate_sharp_reference")
    ap.add_argument("--strength", type=int, default=500, help="raw 強さ (UI x10)")
    ap.add_argument("--range", dest="rng", type=int, default=5, help="raw 範囲")
    args = ap.parse_args(argv or [])

    print("--- 1. parameter conversion ---")
    print("    強さ raw   範囲 raw   S (Q12)   passes")
    for s_raw, r_raw in ((500, 5), (1000, 5), (0, 5), (500, 0), (500, 1), (2000, 8)):
        cfg = setup(s_raw, r_raw)
        if cfg is None:
            print(f"    {s_raw:8d} {r_raw:10d}   -         early return, image untouched")
            continue
        passes = f"V({cfg['r_hi']}) H({cfg['r_hi']})"
        if cfg["r_lo"]:
            passes += f" V({cfg['r_lo']}) H({cfg['r_lo']})"
        print(f"    {s_raw:8d} {r_raw:10d}   {cfg['strength']:<9d} {passes}")

    w, h = 24, 25            # tall enough that the vertical passes are a no-op
    opaque = 4096
    edge_row = [((0 if x < 9 else 4096) if x < 9 or x > 14 else (x - 9) * 4096 // 6,
                 0, 0, opaque) for x in range(w)]

    print("\n--- 2. one soft edge, sharpened (ramp spans luma 0..8192) ---")
    print(f"    input                {luma_row(edge_row)}")
    for ui in (25.0, 50.0, 100.0, 200.0, 400.0):
        out = middle(sharp(tile(edge_row, h), w, h, int(ui * 10), 3), w, h)
        print(f"    強さ={ui:6.1f} 範囲=3   {luma_row(out)}"
              f"   peak {max(p[0] for p in out):5d}"
              f"  min Δ vs input {min(p[0] - o[0] for p, o in zip(out, edge_row)):5d}")
    out = middle(sharp(tile(edge_row, h), w, h, 1000, 3), w, h)
    print(f"    raw luma at 強さ=100.0 範囲=3: {[p[0] for p in out[6:19]]}")
    print("    The over/undershoot on either side of the edge is the whole effect.")
    print("    Undershoot is pinned to 0 by the cleanup; overshoot runs past 4096")
    print("    unbounded and is only clipped by aviutl.exe at the very end.")

    print("\n--- 3. 範囲 picks the feature size, not the amount ---")
    fine_row = [(4096 if (x // 3) % 2 else 0, 0, 0, opaque) for x in range(w)]
    print(f"    3px stripes, input   {luma_row(fine_row)}")
    for rng in (1, 2, 3, 6, 10):
        out = middle(sharp(tile(fine_row, h), w, h, 1000, rng), w, h)
        lo = min(p[0] for p in out)
        hi = max(p[0] for p in out)
        print(f"    範囲={rng:<2d} 強さ=100.0  {luma_row(out)}   luma {lo}..{hi}")
    print("    Detail finer than 範囲 is swallowed by the blur and stops counting as")
    print("    detail, so the response peaks when 範囲 matches the feature and falls")
    print("    away again above it. Small 範囲 sharpens texture, large 範囲 shapes.")

    print("\n--- 4. alpha is never touched, but it changes the result ---")
    for alpha in (4096, 2048, 1024):
        row = [(p[0], 0, 0, alpha) for p in edge_row]
        out = middle(sharp(tile(row, h), w, h, 1000, 3), w, h)
        print(f"    alpha={alpha:<5d} out.a={out[0][3]:<5d} peak luma "
              f"{max(p[0] for p in out):6d}  {luma_row(out)}")
    print("    Same 強さ, same picture, four times the ringing at quarter opacity:")
    print("    the general path divides by (orig.a*blur.a)>>12 (verify_unsharp.py §3).")
    print("    out.a is the original's every time - シャープ writes the alpha back")
    print("    unchanged, so the four blur passes never reach the silhouette.")

    print("\n--- 5. a flat area is a fixed point ---")
    flat = [(2000, 300, -200, opaque)] * (w * h)
    out = sharp(flat, w, h, 8000, 5)
    print(f"    強さ=800.0 範囲=5 on a flat field: "
          f"{'unchanged' if out == flat else out[:3]}")
    print("    (a box average of a constant is that constant, so the difference is 0;")
    print("     この意味で 強さ は「輪郭にしか効かない」)")

    print("\n--- 6. an object shorter than the kernel breaks (verify_blur_chain.py §4) ---")
    print("    範囲=5 -> r_hi = 3, kernel 7. Every row of the image is identical, so a")
    print("    correct vertical pass is the identity and every h must give the same")
    print("    answer. It does not:")
    ref = middle(sharp(tile(edge_row, 25), w, 25, 1000, 5), w, 25)
    for small_h in (25, 9, 7, 5, 3, 1):
        out = middle(sharp(tile(edge_row, small_h), w, small_h, 1000, 5), w, small_h)
        dev = max(abs(a[0] - b[0]) for a, b in zip(out, ref))
        rows_written = 2 * 3 + 1
        note = "" if small_h >= rows_written else f"  <- pass writes {rows_written} rows into {small_h}"
        print(f"    h={small_h:<3d} middle row max |Δluma| vs h=25: {dev:6d}{note}")
    print("    The alpha survives (the combine writes the original's back), but the")
    print("    blur it was compared against averaged samples that were never there.")

    print(f"\n--- 7. your parameters: 強さ={args.strength / 10:.1f} 範囲={args.rng} ---")
    out = middle(sharp(tile(edge_row, h), w, h, args.strength, args.rng), w, h)
    print(f"    {luma_row(edge_row)}   input")
    print(f"    {luma_row(out)}   output")
    print(f"    luma {[p[0] for p in out]}")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
