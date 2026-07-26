"""An integer-faithful reference implementation of ぼかし, assembled from
everything the other scripts in this directory established, and run on small
synthetic images so the behaviour can be inspected as numbers.

This is the place where the separate findings have to agree with each other:
the radius arithmetic (verify_radius_split.py), the four-pass chain
(verify_pass_chain.py), the alpha-weighted box average and its three edge
policies (verify_box_average.py), the canvas growth (verify_canvas_growth.py)
and the 光の強さ curve (verify_light_curve.py). Every rounding step is the one
the binary uses - truncation toward zero for the plain divides, round-half-away
for the two chroma divides that add half the divisor first, float32 storage for
the curved luma.

It is a model of the arithmetic, not a bit-exact emulator: the x87 keeps its
accumulators at 80-bit precision, and the multithread split (each thread takes
a slice of columns for a vertical pass, of rows for a horizontal one) is not
reproduced because it does not change the result.

Run via main.py:
    uv run main.py inspect/blur/simulate_blur_reference.py
    uv run main.py inspect/blur/simulate_blur_reference.py --range 8 --light 30
    uv run main.py inspect/blur/simulate_blur_reference.py --frame
"""

import argparse
import math
import struct

MAX_W = MAX_H = 4096


def f32(x):
    return struct.unpack("<f", struct.pack("<f", x))[0]


def trunc_div(a, b):
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def round_half_away(num, den):
    """`if (x < 0) x -= den/2; else x += den/2; x /= den` - the chroma divides."""
    half = trunc_div(den, 2)
    return trunc_div(num - half if num < 0 else num + half, den)


# --------------------------------------------------------------------------
# One sliding-window pass along a single line
# --------------------------------------------------------------------------

class ObjectAcc:
    """8-byte pixels (y, cb, cr, a); colour is alpha weighted."""

    def __init__(self, curved):
        self.curved = curved
        self.y = 0.0 if curved else 0
        self.cb = self.cr = self.a = 0

    def add(self, px, sign=1):
        y, cb, cr, a = px
        if not a:               # a == 0 (skipped by the worker) or never written
            return
        if a < 0x1000:
            self.y += sign * (y * a / 4096.0 if self.curved else (y * a) >> 12)
            self.cb += sign * ((cb * a) >> 12)
            self.cr += sign * ((cr * a) >> 12)
        else:
            self.y += sign * y
            self.cb += sign * cb
            self.cr += sign * cr
        self.a += sign * a

    def emit(self, divisor):
        alpha = trunc_div(self.a, divisor)
        if self.a == 0:
            # 0x1000ebec: the colour stores are skipped entirely, so the
            # destination keeps whatever the ping-pong buffer already held.
            # None marks that: alpha is 0 here, so the colour is unobservable.
            return (None, None, None, alpha)
        if self.curved:
            # float32 luma; chroma rounded, then truncated into a signed byte
            y = f32(self.y * 4096.0 / self.a)
            cb = round_half_away(self.cb * 4096, self.a)
            cr = round_half_away(self.cr * 4096, self.a)
            cb, cr = max(-128, min(127, cb)), max(-128, min(127, cr))
        else:
            y = int(self.y * 4096.0 / self.a)
            cb = int(self.cb * 4096.0 / self.a)
            cr = int(self.cr * 4096.0 / self.a)
        return (y, cb, cr, alpha)


class FrameAcc:
    """6-byte pixels; no alpha, so a plain unweighted sum."""

    def __init__(self, curved):
        self.curved = curved
        self.y = 0.0 if curved else 0
        self.cb = self.cr = 0

    def add(self, px, sign=1):
        y, cb, cr, _a = px
        if y is None:           # cannot happen on the frame path; see line_pass
            return
        self.y += sign * y
        self.cb += sign * cb
        self.cr += sign * cr

    def emit(self, divisor):
        if self.curved:
            return (f32(self.y / divisor),
                    max(-128, min(127, round_half_away(self.cb, divisor))),
                    max(-128, min(127, round_half_away(self.cr, divisor))),
                    None)
        return (trunc_div(self.y, divisor), trunc_div(self.cb, divisor),
                trunc_div(self.cr, divisor), None)


def line_pass(src, radius, grow, object_mode, curved):
    """One worker, applied to one line. Returns the output line.

    grow=True  -> 0x1000eae0 family: fixed divisor, output is 2*radius longer
    grow=False -> 0x1000f310 / 0x1000fcb0 families: divisor = valid samples,
                  output keeps its length
    """
    n, kernel = len(src), 2 * radius + 1
    acc = (ObjectAcc if object_mode else FrameAcc)(curved)
    # A destination cell never written keeps the ping-pong buffer's old
    # content; None marks "not written by this pass".
    unwritten = (None, None, None, None)

    if grow:
        out, lead, trail = [], 0, 0
        for _ in range(kernel):                              # ramp in
            acc.add(src[lead]); lead += 1
            out.append(acc.emit(kernel))
        for _ in range(n - kernel):                          # steady state
            acc.add(src[lead]); lead += 1
            acc.add(src[trail], sign=-1); trail += 1
            out.append(acc.emit(kernel))
        for _ in range(kernel - 1):                          # ramp out
            acc.add(src[trail], sign=-1); trail += 1
            out.append(acc.emit(kernel))
        return out

    # The three output phases have fixed trip counts taken from the radius and
    # the kernel, not from the line length, so when the radius is not smaller
    # than half the line they write past its end - and, with the middle phase's
    # `n - kernel` trip count going negative, leave a gap in the middle that
    # keeps the destination buffer's stale content. func_proc avoids this on
    # both normal routes (the frame path clamps the radius, the object path
    # pre-expands the canvas); it is only reachable with サイズ固定 on. The
    # binary also reads past the end of the image there; since that memory is
    # the max-size buffer's unspecified tail, this model skips those samples
    # instead of inventing values for them.
    out, lead, trail, row = [unwritten] * n, 0, 0, 0

    def put(value):
        nonlocal row
        if 0 <= row < n:
            out[row] = value
        row += 1

    for _ in range(radius):                                  # prefill, no output
        if lead < n:
            acc.add(src[lead])
        lead += 1
    for i in range(kernel - radius):                         # window growing
        if lead < n:
            acc.add(src[lead])
        lead += 1
        put(acc.emit(radius + i + 1))
    for _ in range(max(0, n - kernel)):                      # steady state
        acc.add(src[lead]); lead += 1
        acc.add(src[trail], sign=-1); trail += 1
        put(acc.emit(kernel))
    for i in range(radius):                                  # window shrinking
        if trail < n:
            acc.add(src[trail], sign=-1)
        trail += 1
        put(acc.emit(kernel - i - 1))
    return out


# --------------------------------------------------------------------------
# The whole filter
# --------------------------------------------------------------------------

class Img:
    def __init__(self, w, h, px):
        self.w, self.h, self.px = w, h, px

    def col(self, x):
        return [self.px[y * self.w + x] for y in range(self.h)]

    def row(self, y):
        return self.px[y * self.w:(y + 1) * self.w]


def vertical(img, radius, grow, object_mode, curved):
    cols = [line_pass(img.col(x), radius, grow, object_mode, curved) for x in range(img.w)]
    nh = len(cols[0])
    return Img(img.w, nh, [cols[x][y] for y in range(nh) for x in range(img.w)])


def horizontal(img, radius, grow, object_mode, curved):
    rows = [line_pass(img.row(y), radius, grow, object_mode, curved) for y in range(img.h)]
    nw = len(rows[0])
    return Img(nw, img.h, [px for r in rows for px in r])


def forward_curve(img, strength, object_mode):
    base = 1.0 + min(max(strength, 1), 100) * 0.001
    out = []
    for y, cb, cr, a in img.px:
        if object_mode and a <= 0:
            out.append((0.0, 0, 0, a))
            continue
        cb_b = max(-128, min(127, (cb + 8) >> 4))
        cr_b = max(-128, min(127, (cr + 8) >> 4))
        out.append((f32(math.pow(base, min(max(y, 0), 4096) * 0.0625) - 1.0),
                    cb_b, cr_b, a))
    return Img(img.w, img.h, out), base


def inverse_curve(img, base, object_mode):
    k = 16.0 / math.log(base)
    out = []
    for y, cb, cr, a in img.px:
        if object_mode and a <= 0:
            out.append((0, 0, 0, a))
            continue
        out.append((int(math.log(y + 1.0) * k + 0.5), cb << 4, cr << 4, a))
    return Img(img.w, img.h, out)


def blur(img, rng, aspect, light, size_fixed, object_mode):
    if rng == 0:                                   # 0x1000e300
        return img
    rx = ry = rng
    if aspect > 0:
        ry = trunc_div((1000 - aspect) * rng, 1000)
    elif aspect < 0:
        rx = trunc_div((1000 + aspect) * rng, 1000)

    if object_mode:
        if img.w + 2 * rx > MAX_W:
            rx = trunc_div(MAX_W - img.w, 2)
        if img.h + 2 * ry > MAX_H:
            ry = trunc_div(MAX_H - img.h, 2)

    rx_hi, rx_lo = rx - trunc_div(rx, 2), trunc_div(rx, 2)
    ry_hi, ry_lo = ry - trunc_div(ry, 2), trunc_div(ry, 2)

    if object_mode:
        if not size_fixed and (2 * rx_hi >= img.w or 2 * ry_hi >= img.h
                               or 2 * rx_lo >= img.w or 2 * ry_lo >= img.h):
            nw, nh = img.w + 2 * rx, img.h + 2 * ry
            px = [(0, 0, 0, 0)] * (nw * nh)
            for y in range(img.h):                 # clear + blit into the middle
                for x in range(img.w):
                    px[(y + ry) * nw + (x + rx)] = img.px[y * img.w + x]
            img = Img(nw, nh, px)
            size_fixed = 1                         # 0x1000e45c
    else:
        if 2 * rx_hi > img.w:
            rx_hi = trunc_div(img.w, 2)
        if 2 * ry_hi > img.h:
            ry_hi = trunc_div(img.h, 2)
        if 2 * rx_lo > img.w:
            rx_lo = trunc_div(img.w, 2)
        if 2 * ry_lo > img.h:
            ry_lo = trunc_div(img.h, 2)
        size_fixed = 1                             # a frame never grows

    curved = light > 0
    base = None
    if curved:
        img, base = forward_curve(img, light, object_mode)

    grow = object_mode and not size_fixed
    for radius, fn in ((ry_hi, vertical), (rx_hi, horizontal),
                       (ry_lo, vertical), (rx_lo, horizontal)):
        if radius:                                 # radius 0 -> pass skipped
            img = fn(img, radius, grow, object_mode, curved)

    if curved:
        img = inverse_curve(img, base, object_mode)
    return img


# --------------------------------------------------------------------------

def cutout(w=11, h=7):
    """An opaque, strongly red bar on a fully transparent canvas.

    Shows what the alpha channel does: since every visible sample has the same
    colour, the alpha-weighted average leaves the colour flat and the blur is
    visible only in the alpha.
    """
    px = []
    for y in range(h):
        for x in range(w):
            inside = 3 <= x <= 7 and 2 <= y <= 4
            px.append((4096, -1000, 2000, 4096) if inside else (0, 0, 0, 0))
    return Img(w, h, px)


def opaque_bar(w=11, h=7):
    """A bright bar on a dark but fully opaque canvas - shows the luma blur."""
    px = []
    for y in range(h):
        for x in range(w):
            inside = 4 <= x <= 6 and 2 <= y <= 4
            px.append((4096, 0, 0, 4096) if inside else (256, 0, 0, 4096))
    return Img(w, h, px)


def _show(img, title, field):
    idx = {"y": 0, "cb": 1, "cr": 2, "a": 3}[field]
    print(f"\n  {title}  ({img.w}x{img.h}, channel {field})")
    for y in range(img.h):
        cells = []
        for x in range(img.w):
            v = img.px[y * img.w + x][idx]
            cells.append("    -" if v is None else "    ." if v == 0 else f"{int(v):5d}")
        print("    " + " ".join(cells))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--range", dest="rng", type=int, default=2, help="範囲 (0..1000)")
    p.add_argument("--aspect", type=int, default=0, help="縦横比 (-1000..1000)")
    p.add_argument("--light", type=int, default=0, help="光の強さ (0..60)")
    p.add_argument("--size-fixed", action="store_true", help="サイズ固定")
    p.add_argument("--frame", action="store_true", help="frame filter instead of object effect")
    args = p.parse_args(argv or [])

    object_mode = not args.frame
    print(f"ぼかし: 範囲={args.rng} 縦横比={args.aspect} 光の強さ={args.light} "
          f"サイズ固定={int(args.size_fixed)} "
          f"mode={'object effect' if object_mode else 'frame filter'}\n"
          f"  '.' = 0, '-' = never written by the last pass (stale buffer content)")

    # ---- 1: what happens to alpha ---------------------------------------
    src = cutout()
    print("\n=== 1. opaque red bar on a transparent canvas ===")
    _show(src, "source", "a")
    out = blur(src, args.rng, args.aspect, args.light, args.size_fixed, object_mode)
    if object_mode:
        _show(out, "result", "a")
        _show(out, "result", "cr")
        stale = sum(1 for px in out.px if px[0] is None and px[3])
        print(f"\n  pixels with alpha > 0 but no colour written: {stale}"
              "   (must be 0: the colour store is skipped only when the whole\n"
              "    window was transparent, and then the alpha written is 0 too)")

        # Every pixel of this sprite has the same colour, so any spread in the
        # result is pure rounding loss from repeated premultiply/un-premultiply
        # with truncating shifts and divides.
        lit = [px for px in out.px if px[3]]
        if lit:
            cbs, crs = [px[1] for px in lit], [px[2] for px in lit]
            print(f"  source colour cb=-1000 cr=2000; after four passes "
                  f"cb in [{min(cbs)}, {max(cbs)}], cr in [{min(crs)}, {max(crs)}]\n"
                  "    - the (c*a)>>12 premultiply truncates, so the colour of a\n"
                  "      partially transparent pixel drifts by a fraction of a percent")
    else:
        _show(out, "result", "y")
    print(f"\n  canvas: {src.w}x{src.h} -> {out.w}x{out.h}")

    if object_mode:
        other = blur(cutout(), args.rng, args.aspect, args.light,
                     not args.size_fixed, True)
        _show(other, f"same input with サイズ固定={int(not args.size_fixed)}", "a")
        print(f"\n  canvas: {src.w}x{src.h} -> {other.w}x{other.h}")

    # ---- 2: what happens to luma, and what 光の強さ does -------------------
    print("\n=== 2. bright bar on a dark but opaque canvas ===")
    base_img = opaque_bar()
    _show(base_img, "source", "y")
    res = blur(opaque_bar(), args.rng, args.aspect, args.light,
               args.size_fixed, object_mode)
    _show(res, "result", "y")

    print("\n  luma along the middle row for a few 光の強さ values:")
    for light in (0, 10, 30, 60):
        r = blur(opaque_bar(), args.rng, args.aspect, light,
                 args.size_fixed, object_mode)
        row = [int(px[0]) for px in r.row(r.h // 2)]
        print(f"    光の強さ={light:3d}: {row}")
    print("    (higher 光の強さ pulls each window's average toward its brightest\n"
          "     sample, so the bar spreads while staying bright)")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
