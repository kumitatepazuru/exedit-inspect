"""An integer-faithful reimplementation of 閃光, and a few renders that show
what each parameter does to the output.

Everything the other scripts in this directory establish, assembled in one
place and written with the same integer semantics as the original: `sar` where
the code shifts, truncation toward zero where it divides, 16-bit stores with
no clamp, and the centre pixel's borrowed alpha carried explicitly.

What is *not* modelled, and why it does not affect the pixels:

  * the multi-thread split. Each thread owns a horizontal band and the bands
    do not interact, so a single-threaded scan produces identical output -
    except for the centre pixel, whose borrowed alpha depends on scan order.
    --threads reproduces a given split for that one pixel.
  * the final blit of the original object back over the light (mode 0/1). That
    goes through an exedit-internal draw routine reached via fp+0x64, outside
    this analysis; render() returns the light layer, which is exactly what
    mode 2 (光成分のみ) outputs.
  * the fit-to-canvas clamp, which needs the running exedit's max canvas size.
    grow() applies it if a limit is passed.

Run via main.py:
    uv run main.py inspect/glint/simulate_glint_reference.py
    uv run main.py inspect/glint/simulate_glint_reference.py --strength 500
    uv run main.py inspect/glint/simulate_glint_reference.py --colour 0000ff
"""

import argparse
import math

from tools.cints import MAGIC_1000, c_div, msvc_div


# ---------------------------------------------------------------- parameters

def setup(w, h, raw_strength, track_x, track_y, draft=False):
    """func_proc 0x1004e560..0x1004e7c6. Returns None when the effect is skipped."""
    if raw_strength == 0:  # `test eax, eax; je` - no canvas growth either
        return None
    strength = msvc_div(raw_strength << 12, MAGIC_1000, 6)
    T = max(0, 0x1000 - strength)

    cx = c_div(w, 2) + track_x
    cy = c_div(h, 2) + track_y

    maxd = max(abs(cx), abs(cy), abs(cx - w), abs(cy - h))
    maxd = min(maxd, int(math.sqrt(w * w + h * h)))  # fild/fsqrt/_ftol
    if draft and maxd > 50:  # fpip->flag & 0x200
        maxd = 50
    R = msvc_div(maxd * 250, MAGIC_1000, 6) + c_div(maxd, 2)

    x0 = min(cx - msvc_div(cx * 1000, MAGIC_1000, 4), 0)
    y0 = min(cy - msvc_div(cy * 1000, MAGIC_1000, 4), 0)
    tx, ty = cx - w, cy - h
    x1 = max(tx + msvc_div(-tx * 1000, MAGIC_1000, 4), 0)
    y1 = max(ty + msvc_div(-ty * 1000, MAGIC_1000, 4), 0)

    x0, y0 = (x0 * strength) >> 12, (y0 * strength) >> 12
    x1, y1 = ((x1 * strength) >> 12) + w, ((y1 * strength) >> 12) + h
    return {"cx": cx, "cy": cy, "R": R, "T": T, "strength": strength,
            "x0": x0, "y0": y0, "x1": x1, "y1": y1, "w": w, "h": h}


def grow(p, max_w=None, max_h=None, fpip_w=None, fpip_h=None):
    """0x1004e7e0: shave the longer side until the canvas fits both limits."""
    w, h = p["w"], p["h"]
    if max_w is not None:
        lim = min(max_w, (fpip_w if fpip_w is not None else max_w) + 2 * w)
        while p["x1"] - p["x0"] > lim:
            if p["x0"] < w - p["x1"]:
                p["x0"] += 1
            else:
                p["x1"] -= 1
    if max_h is not None:
        lim = min(max_h, (fpip_h if fpip_h is not None else max_h) + 2 * h)
        while p["y1"] - p["y0"] > lim:
            if p["y0"] < h - p["y1"]:
                p["y0"] += 1
            else:
                p["y1"] -= 1
    return p


def fix_size(p):
    """サイズ固定 checked (0x1004e860): keep the original rectangle."""
    p["x0"] = p["y0"] = 0
    p["x1"], p["y1"] = p["w"], p["h"]
    return p


# ------------------------------------------------------------------- the ray

def ray_shape(dx, dy, R):
    """0x1004ea86..0x1004eb2a -> (samples_per_full_distance, ray_length)."""
    dist8 = int(math.sqrt(dx * dx + dy * dy) * 8.0)  # _ftol truncates
    length = msvc_div(dist8 * 750, MAGIC_1000, 6)
    if dist8 > R:
        return R, c_div(R * length, dist8)
    m = 8 if dist8 > 8 else 4 if dist8 > 4 else 2 if dist8 > 2 else 1
    return dist8 * m, length * m


def to_i16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def emit(sum_y, sum_cb, sum_cr, length, T):
    """The shared tail: threshold, then luminance-as-alpha (verify_output_encoding.py)."""
    avg_y = c_div(sum_y, length)
    out = avg_y - T
    if out <= 0:
        return (0, 0, 0, 0)
    cb = c_div(sum_cb, length)
    cr = c_div(sum_cr, length)
    cb -= c_div(T * cb, avg_y)
    cr -= c_div(T * cr, avg_y)
    if out < 0x1000:
        return (0x1000, to_i16(c_div(cb << 12, out)), to_i16(c_div(cr << 12, out)), out)
    return (to_i16(out), to_i16(cb), to_i16(cr), 0x1000)


def render(src, p, colour=None, threads=1):
    """One frame of light.

    src: (w, h, pixels) with pixels[y*w + x] = (y, cb, cr, a), PIXEL_YCA.
    colour: None reproduces worker 0x1004e9c0 (sample the source's own colour);
            a (y, cb, cr) triple reproduces 0x1004ee20 (sample coverage only).
    Returns (out_w, out_h, pixels) in the grown canvas.
    """
    w, h, px = src
    cx, cy, R, T = p["cx"], p["cy"], p["R"], p["T"]
    x0, y0, x1, y1 = p["x0"], p["y0"], p["x1"], p["y1"]
    ow, oh = x1 - x0, y1 - y0
    out = [(0, 0, 0, 0)] * (ow * oh)

    for tid in range(threads):
        ys = (y1 - y0) * tid // threads + y0
        ye = (y1 - y0) * (tid + 1) // threads + y0
        borrowed = 0  # [esp+0x48], see verify_center_pixel.py
        for y in range(ys, ye):
            for x in range(x0, x1):
                dx, dy = cx - x, cy - y
                N, length = ray_shape(dx, dy, R)

                if N >= 2 and length >= 2:
                    stepx, stepy = c_div(dx << 16, N), c_div(dy << 16, N)
                    fx, fy = (x << 16) + 0x8000, (y << 16) + 0x8000
                    sy = scb = scr = 0
                    for _ in range(length):
                        sx_i, sy_i = fx >> 16, fy >> 16
                        fx, fy = fx + stepx, fy + stepy
                        if not (0 <= sx_i < w and 0 <= sy_i < h):
                            continue
                        s = px[sy_i * w + sx_i]
                        a = s[3]
                        borrowed = a
                        if not a:
                            continue
                        c = colour if colour is not None else s[:3]
                        if a < 0x1000:
                            sy += (c[0] * a) >> 12
                            scb += (c[1] * a) >> 12
                            scr += (c[2] * a) >> 12
                        else:
                            sy, scb, scr = sy + c[0], scb + c[1], scr + c[2]
                    out[(y - y0) * ow + (x - x0)] = emit(sy, scb, scr, length, T)
                    continue

                # centre path: no sampling, borrowed alpha
                if not (0 <= x < w and 0 <= y < h):
                    continue
                a = borrowed
                c = colour if colour is not None else px[y * w + x][:3]
                yy, cb, cr = (c[0] * a) >> 12, (c[1] * a) >> 12, (c[2] * a) >> 12
                o = yy - T
                if o <= 0:
                    continue
                cb -= c_div(T * cb, yy)
                cr -= c_div(T * cr, yy)
                if o < 0x1000:
                    out[(y - y0) * ow + (x - x0)] = (
                        0x1000, to_i16(c_div(cb << 12, o)), to_i16(c_div(cr << 12, o)), o)
                else:
                    out[(y - y0) * ow + (x - x0)] = (to_i16(o), to_i16(cb), to_i16(cr), 0x1000)
    return ow, oh, out


# ------------------------------------------------------------------- demo art

def make_source(w, h, spots):
    """Transparent canvas with a few opaque bright dots."""
    px = [(0, 0, 0, 0)] * (w * h)
    for sx, sy, y, cb, cr in spots:
        for dy in range(-1, 2):
            for dx in range(-1, 2):
                if 0 <= sx + dx < w and 0 <= sy + dy < h:
                    px[(sy + dy) * w + sx + dx] = (y, cb, cr, 0x1000)
    return (w, h, px)


def ascii_art(ow, oh, out, cols=61, rows=25):
    """Alpha as coarse greyscale - alpha *is* the light (verify_output_encoding.py).

    Max-pooled rather than point-sampled: the streaks are one pixel wide far
    from the centre (verify_ray_geometry.py's undersampling), and point
    sampling a 244px canvas down to 61 columns drops most of them.
    """
    ramp = " .:-=+*#%@"
    lines = []
    for r in range(rows):
        line = []
        for c in range(cols):
            xs, xe = c * ow // cols, max(c * ow // cols + 1, (c + 1) * ow // cols)
            ys, ye = r * oh // rows, max(r * oh // rows + 1, (r + 1) * oh // rows)
            a = max(out[y * ow + x][3] for y in range(ys, ye) for x in range(xs, xe))
            line.append(ramp[min(len(ramp) - 1, a * len(ramp) // 4097)])
        lines.append("".join(line))
    return lines


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strength", type=int, default=1000, help="raw 強さ, 0..1000")
    parser.add_argument("--x", type=int, default=0, help="raw X")
    parser.add_argument("--y", type=int, default=0, help="raw Y")
    parser.add_argument("--colour", help="light colour as rrggbb; omit for 指定無し")
    parser.add_argument("--size", type=int, default=81, help="source object is size x size")
    parser.add_argument("--threads", type=int, default=1)
    args = parser.parse_args(argv or [])

    n = args.size
    src = make_source(n, n, [
        (n // 2, n // 2, 0x1000, 0, 0),
        (n // 4, n // 3, 0x1000, -600, 900),
        (3 * n // 4, 2 * n // 3, 0x0C00, 800, -400),
    ])

    colour = None
    if args.colour:
        r, g, b = (int(args.colour[i:i + 2], 16) for i in (0, 2, 4))
        # exedit's Q14 BT.601 rows, scaled to AviUtl's 0..4096 luminance
        colour = (int((0.299 * r + 0.587 * g + 0.114 * b) * 4096 / 255),
                  int((-0.169 * r - 0.331 * g + 0.500 * b) * 4096 / 255),
                  int((0.500 * r - 0.419 * g - 0.081 * b) * 4096 / 255))

    p = setup(n, n, args.strength, args.x, args.y)
    if p is None:
        print("強さ = 0: func_proc returns immediately, the object is untouched")
        return

    print(f"source {n}x{n}, 強さ raw={args.strength} ({args.strength / 10:.1f}), "
          f"X={args.x} Y={args.y}, colour={args.colour or '指定無し'}")
    print(f"  centre ({p['cx']}, {p['cy']})  sample cap R={p['R']}  threshold T={p['T']}")
    print(f"  canvas [{p['x0']}, {p['x1']}) x [{p['y0']}, {p['y1']}) "
          f"= {p['x1'] - p['x0']} x {p['y1'] - p['y0']}")

    ow, oh, out = render(src, p, colour, args.threads)
    print("\nlight layer (alpha as brightness - this is what 光成分のみ outputs):")
    for line in ascii_art(ow, oh, out):
        print("  " + line)

    lit = [q for q in out if q[3]]
    print(f"\n  {len(lit)} of {len(out)} pixels lit "
          f"({100 * len(lit) / len(out):.1f}%)")
    if lit:
        print(f"  alpha range {min(q[3] for q in lit)}..{max(q[3] for q in lit)}, "
              f"luminance range {min(q[0] for q in lit)}..{max(q[0] for q in lit)}")

    print("\nsame parameters with サイズ固定 checked (canvas kept at the object size):")
    p2 = fix_size(setup(n, n, args.strength, args.x, args.y))
    ow2, oh2, out2 = render(src, p2, colour, args.threads)
    for line in ascii_art(ow2, oh2, out2, rows=15):
        print("  " + line)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
