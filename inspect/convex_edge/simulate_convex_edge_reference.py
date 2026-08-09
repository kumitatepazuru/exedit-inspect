"""An integer-faithful reimplementation of 凸エッジ, and a render that shows
what each parameter actually does.

Assembled from disasm_params.py / verify_registration.py / verify_direction.py
/ verify_shading.py, keeping the original's arithmetic: `_ftol` truncates
toward zero (`math.trunc`), the offset accumulators are int32 shifted with
`sar` (floor), the chroma rescale divides with `idiv` (`c_div`) and then
shifts with `sar`, and the backward sample is the negated *floored* offset
rather than a second floor.

What is *not* modelled, and why it does not change the demo:

  * the multi-thread split. The worker splits by row and never writes outside
    its own band or reads anything but the (read-only) source buffer, so one
    thread produces identical output.
  * `exec_multi_thread_func` itself - only its documented calling shape.
  * x87's `fsin`/`fcos`, which are used here via the host libm. The two can
    differ by 1 ulp, and verify_direction.py §7 shows that matters at exactly
    34 (角度, component) pairs, all multiples of 30 degrees.

The draft-quality path (`fpip->flag & 0x200`, sample count capped at 16) IS
modelled, behind --draft, because it is the only thing in the effect that
changes the *sampling* rather than the parameters.

Run via main.py:
    uv run main.py inspect/convex_edge/simulate_convex_edge_reference.py
    uv run main.py inspect/convex_edge/simulate_convex_edge_reference.py --angle 90
    uv run main.py inspect/convex_edge/simulate_convex_edge_reference.py \
        --width 8 --height 200 --shape disc --obj 32
"""

import argparse
import math

from tools.cints import c_div, sar, to_i32

FULL = 4096


# ---------------------------------------------------------------- parameters

def setup(w, h, width_raw, height_raw, angle_raw, draft=False, flag=0):
    """func_proc 0x10007a80..0x10007b62. Returns None when the effect returns
    early without even swapping the buffers (幅 = 0, or an object under 2 px)."""
    if width_raw == 0:                                        # 0x10007a8f
        return None
    width = min(width_raw, c_div(w, 2), c_div(h, 2))           # 0x10007a99-0x10007ab9

    t = angle_raw * -0.0017453292519943296                     # 0x10007abe, -pi/1800
    dx = math.trunc(math.sin(t) * 65536.0)                     # 0x10007ac6-0x10007ace
    dy = math.trunc(math.cos(t) * 65536.0)                     # 0x10007ad3-0x10007ae3

    if (draft or flag & 0x200) and width > 16:                 # 0x10007af2 / 0x10007af7
        dx = c_div(dx * width, 16)                             # 0x10007afc-0x10007b0a
        dy = c_div(dy * width, 16)
        width = 16                                             # 0x10007b18
    elif width <= 0:                                           # 0x10007b2b
        return None

    return {
        "steps": width,                                        # g_100d7590
        "dx": dx, "dy": dy,                                    # g_100d7598 / g_100d7594
        # g_100d7588: fild 高さ ; fmul 0.5 ; fild 100*steps ; fdivp
        "scale": (height_raw * 0.5) / (100 * width),
    }


# -------------------------------------------------------------------- worker

def convex_edge(img, w, h, p):
    """The worker at 0x10007b90, for the whole image instead of one row band.

    `img` is a flat list of [y, cb, cr, a] and the result is a fresh list -
    the original writes into the pair buffer and func_proc swaps, so the
    source is never modified mid-pass.
    """
    steps, dx, dy, scale = p["steps"], p["dx"], p["dy"], p["scale"]
    out = [None] * (w * h)

    for y in range(h):
        for x in range(w):
            ax = ay = total = 0
            for _ in range(steps):                             # 0x10007c59-0x10007ced
                ax = to_i32(ax + dx)
                ay = to_i32(ay + dy)
                ox, oy = sar(ax, 16), sar(ay, 16)              # sar, i.e. floor
                sx, sy = x + ox, y + oy                        # 0x10007c72 / 0x10007c7a
                if 0 <= sx < w and 0 <= sy < h:
                    total += img[sy * w + sx][3]
                sx, sy = x - ox, y - oy                        # 0x10007cb0-0x10007cba
                if 0 <= sx < w and 0 <= sy < h:
                    total -= img[sy * w + sx][3]

            d = math.trunc(total * scale)                      # 0x10007cf3-0x10007cfd
            y0, cb, cr, a = img[y * w + x]
            if d < 0 and y0 > 0:                               # 0x10007d0d / 0x10007d11
                ny = d + y0
                if ny < 0:                                     # 0x10007d15
                    ny, k = 0, 0
                else:
                    k = c_div(ny << 12, y0)                    # 0x10007d23
                out[y * w + x] = [ny, sar(cb * k, 12), sar(cr * k, 12), a]
            else:
                out[y * w + x] = [y0 + d, cb, cr, a]           # 0x10007d55, no clamp
    return out


def apply(img, w, h, width_raw, height_raw, angle_raw, draft=False):
    """func_proc end to end, including the early-out that leaves img alone."""
    p = setup(w, h, width_raw, height_raw, angle_raw, draft)
    if p is None:
        return [list(px) for px in img], None
    return convex_edge(img, w, h, p), p


# ------------------------------------------------------------- test material

def make(shape, w, h, colour=(2048, 0, 0)):
    """A solid object on a transparent field. 凸エッジ only reads alpha from
    the neighbours, so the shape of the alpha channel is the whole input."""
    y0, cb, cr = colour
    img = []
    cx, cy, r = (w - 1) / 2, (h - 1) / 2, min(w, h) / 2 - 2
    for j in range(h):
        for i in range(w):
            if shape == "rect":
                inside = 3 <= i < w - 3 and 3 <= j < h - 3
                a = FULL if inside else 0
            elif shape == "disc":
                a = FULL if math.hypot(i - cx, j - cy) <= r else 0
            elif shape == "ring":
                dist = math.hypot(i - cx, j - cy)
                a = FULL if r * 0.55 <= dist <= r else 0
            elif shape == "ramp":                 # a semi-transparent wedge
                a = max(0, min(FULL, (i - 3) * FULL // max(1, w - 6)))
            else:
                raise SystemExit(f"unknown shape {shape!r}")
            img.append([y0, cb, cr, a])
    return img


RAMP = " .:-=+*#%@"


def render(img, w, h, label):
    print(f"\n  {label}")
    for j in range(h):
        row = ""
        for i in range(w):
            y0, _, _, a = img[j * w + i]
            if a < FULL // 2:
                row += " "
            else:
                row += RAMP[max(0, min(len(RAMP) - 1, y0 * (len(RAMP) - 1) // FULL))]
        print("   |" + row + "|")


# ---------------------------------------------------------------- self-tests

def selftest(check):
    w = h = 24
    src = make("rect", w, h)

    out, p = apply(src, w, h, 4, 100, -450)
    check("defaults: 幅=4 clamps to 4 (object is 24 px), direction is (46340, 46340)",
          (p["steps"], p["dx"], p["dy"]) == (4, 46340, 46340))
    check("alpha is identical everywhere", [q[3] for q in out] == [q[3] for q in src])
    check("cb / cr are untouched wherever the pixel got brighter",
          all(o[1:3] == s[1:3] for o, s in zip(out, src) if o[0] >= s[0]))

    mid = out[(h // 2) * w + w // 2]
    check("a pixel in the middle of a 24x24 block is 8 px from every edge, so its "
          "window is entirely inside and it is unchanged",
          mid == src[(h // 2) * w + w // 2], f"{mid}")

    tl = out[4 * w + 4]
    br = out[(h - 5) * w + (w - 5)]
    check("with the default 角度 = -45.0 the top-left corner is lit and the "
          "bottom-right one is shaded", tl[0] > 2048 > br[0], f"top-left {tl[0]}, "
          f"bottom-right {br[0]}")

    flat, _ = apply(src, w, h, 4, 0, -450)
    check("高さ = 0.00 produces a bit-exact copy (but still does all the work)",
          flat == [list(q) for q in src])

    none, p0 = apply(src, w, h, 0, 100, -450)
    check("幅 = 0 returns before the swap, so the object is untouched",
          p0 is None and none == [list(q) for q in src])
    check("an object 1 px tall clamps 幅 to 0 and returns the same way",
          setup(w, 1, 4, 100, -450) is None)

    # 角度 = 0 and 角度 = 180.0 have exactly antisymmetric offsets (0, +-k), so
    # on the axes the two are mirror images. Off the axes flooring breaks it.
    down, _ = apply(src, w, h, 4, 100, 0)
    up, _ = apply(src, w, h, 4, 100, 1800)
    check("角度 = 0.0 and 角度 = 180.0 are exact mirrors of each other "
          "(vertical offsets are integers, so nothing is lost to flooring)",
          all(d[0] - 2048 == -(u[0] - 2048)
              for d, u in zip(down, up) if d[0] >= 0 and u[0] >= 0))

    a45, _ = apply(src, w, h, 4, 100, -450)
    a225, _ = apply(src, w, h, 4, 100, 1350)
    diff = [abs((x[0] - 2048) + (y[0] - 2048)) for x, y in zip(a45, a225)]
    check("角度 +180 is NOT an exact mirror off the axes - flooring is not "
          f"antisymmetric (max residual {max(diff)} of 2048)", 0 < max(diff) <= 2048,
          f"max {max(diff)}")

    dark, _ = apply(make("rect", w, h, colour=(2048, -900, 1500)), w, h, 4, 200, -450)
    shaded = [q for q in dark if q[0] < 2048 and q[3]]
    check("on the shaded side the chroma shrinks with the luminance (hue preserved)",
          all(abs(q[1]) < 900 and abs(q[2]) < 1500 for q in shaded) and shaded)

    big, pb = apply(src, w, h, 100, 100, -450, draft=False)
    check("幅 = 100 on a 24 px object clamps to 12 before anything else",
          pb["steps"] == 12)
    _, pd = apply(make("rect", 200, 200), 200, 200, 40, 100, -450, draft=True)
    check("draft quality caps the count at 16 and stretches the step by 40/16",
          (pd["steps"], pd["dx"]) == (16, c_div(46340 * 40, 16)))


# ---------------------------------------------------------------------- main

def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="simulate_convex_edge_reference")
    ap.add_argument("--width", type=int, default=4, help="幅 raw (0..100), default 4")
    ap.add_argument("--height", type=int, default=100,
                    help="高さ raw (0..300, shown /100), default 100 = 1.00")
    ap.add_argument("--angle", type=int, default=-450,
                    help="角度 raw (-3600..3600, shown /10), default -450 = -45.0")
    ap.add_argument("--obj", type=int, default=28, help="test object size in px")
    ap.add_argument("--shape", default="rect", choices=("rect", "disc", "ring", "ramp"))
    ap.add_argument("--draft", action="store_true", help="pretend fpip->flag & 0x200")
    args = ap.parse_args(argv or [])

    print(__doc__.split("Run via main.py:")[0].rstrip())

    print("\n=== self-verification ===")
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    selftest(check)
    print(f"\n  {sum(checks)}/{len(checks)} checks passed.")

    w = h = args.obj
    src = make(args.shape, w, h)
    out, p = apply(src, w, h, args.width, args.height, args.angle, args.draft)

    print(f"\n=== 幅 = {args.width}, 高さ = {args.height / 100:.2f}, "
          f"角度 = {args.angle / 10:+.1f}, shape = {args.shape}, "
          f"{'draft' if args.draft else 'full'} quality ===")
    if p is None:
        print("  幅 clamps to 0 - func_proc returns without touching the object.")
        return
    print(f"  steps = {p['steps']}, (dx, dy) = ({p['dx']}, {p['dy']}) "
          f"= ({p['dx'] / 65536:+.4f}, {p['dy'] / 65536:+.4f}) px/step, "
          f"scale = {p['scale']:.6f}")
    print(f"  peak |d| = {math.trunc(p['steps'] * FULL * p['scale'])} "
          f"of {FULL} (verify_shading.py §1)")

    render(src, w, h, f"before  (flat Y = 2048, ramp '{RAMP}' = 0..4096)")
    render(out, w, h, "after")

    row = h // 2
    print(f"\n  scanline y = {row}:")
    print("   " + "".join(f"{i % 10}" for i in range(w)) + "   x")
    print("   " + "".join("#" if src[row * w + i][3] else "." for i in range(w))
          + "   alpha (# = opaque)")
    print("\n   " + "  ".join(f"{out[row * w + i][0] - src[row * w + i][0]:+5d}"
                              for i in range(min(w, 12))))
    print("   (Y change for the first 12 pixels of that row)")

    lo = min(q[0] for q in out)
    hi = max(q[0] for q in out)
    print(f"\n  output Y range {lo}..{hi}"
          + ("  <- above 4096, aviutl.exe clips it" if hi > FULL else "")
          + ("  <- below 0" if lo < 0 else ""))
    check2 = [q[3] for q in out] == [q[3] for q in src]
    print(f"  alpha unchanged: {check2}")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
