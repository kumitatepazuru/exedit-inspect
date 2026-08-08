"""An integer-faithful reimplementation of 縁取り, and a render that shows what
each parameter actually does.

Assembled from disasm_params.py / verify_params.py / verify_canvas.py /
verify_border_chain.py / verify_encode.py, keeping the original's arithmetic:
`idiv` truncates toward zero (`c_div`), the gain is the same round-half-up of
an x87 quotient, the window sum is scaled and saturated rather than divided,
and the `imul` is a signed 32-bit multiply that really can wrap
(verify_border_chain.py §5 - reachable with サイズ >= 256 and ぼかし = 0).

What is *not* modelled, and why it does not change the demo:

  * the multi-thread split. Pass 1 splits by column and pass 2 by row, with no
    cross-thread state, so one thread produces identical output.
  * `table[0x44]` / `table[0x48]` internals - only their documented effects are
    used (composite_normal() and a flat fill, blend_modes.md §3/§4).
  * the pattern-image path beyond `--pattern-alpha`: loading and tiling a real
    image is exedit-side work this analysis did not re-derive, and the encoder
    only ever sees the tiled result's own alpha.
  * the four rect-clears, which verify_canvas.py §3 shows are unreachable.

The pre-pad IS modelled, because it is the reason 縁取り never reads outside
its object the way シャドー does - and because with a small object it changes
the intermediate canvas size (though never the published one).

Run via main.py:
    uv run main.py inspect/border/simulate_border_reference.py
    uv run main.py inspect/border/simulate_border_reference.py --border-size 12 --blur 60
    uv run main.py inspect/border/simulate_border_reference.py --colour ff0000 --obj 24
"""

import argparse

from tools.cints import c_div, to_i32

FULL = 4096


# ---------------------------------------------------------------- parameters

def setup(w, h, raw_size, raw_blur, stride=None, rows=None):
    """func_proc 0x100515d0..0x100519a5. Returns None when サイズ = 0 (no-op).

    `stride` / `rows` stand in for fpip+0xEC / +0xF0, the allocated buffer's
    extents - this analysis did not pin down how exedit sizes them, so they
    default to something roomy (verify_params.py §5).
    """
    if raw_size == 0:
        return None
    stride = stride if stride is not None else w + 1024
    rows = rows if rows is not None else h + 1024

    pad_x = pad_y = 0
    pw, ph = w, h
    if 2 * raw_size >= w or 2 * raw_size >= h:              # 0x10051644
        pad_x = c_div(max(2 * raw_size - w, 0) + 2, 2)      # 0x1005166c
        pad_y = c_div(max(2 * raw_size - h, 0) + 2, 2)
        if 2 * pad_x > stride - w:
            pad_x = c_div(stride - w, 2)
        if 2 * pad_y > rows - h:
            pad_y = c_div(rows - h, 2)
        pw, ph = w + 2 * pad_x, h + 2 * pad_y

    size = raw_size                                          # 0x1005176f
    if 2 * size > stride - pw:
        size = c_div(stride - pw, 2)
    if 2 * size > rows - ph:
        size = c_div(rows - ph, 2)

    return {
        "w": w, "h": h, "pad_x": pad_x, "pad_y": pad_y,
        "padded_w": pw, "padded_h": ph,
        "size": size, "kernel": 2 * size + 1,
        "gain": int(1024.0 / ((2 * size) * raw_blur * 0.01 + 1.0) + 0.5),
        "canvas_w": pw + 2 * size, "canvas_h": ph + 2 * size,
        "final_w": w + 2 * size, "final_h": h + 2 * size,
        # the dead one, kept so the README's claim can be printed from the model
        "dead_blur": FULL - raw_blur * FULL // 1000,
    }


def rgb_to_ycbcr(rgb: str):
    """0x1006fed0's shared conversion, Q14 BT.601 full-range (rgb_ycbcr.md)."""
    r, g, b = (int(rgb[i:i + 2], 16) for i in (0, 2, 4))
    y = int((0.299 * r + 0.587 * g + 0.114 * b) * FULL / 255)
    cb = int((-0.169 * r - 0.331 * g + 0.500 * b) * FULL / 255)
    cr = int((0.500 * r - 0.419 * g - 0.081 * b) * FULL / 255)
    return y, cb, cr


# -------------------------------------------------------------- the two passes

def saturate(total, gain):
    """0x10051b6d-0x10051b86: `imul gain ; sar 10 ; >= 4096 ? 4096 : store cx`.

    The signed 32-bit wrap and the 16-bit store are both deliberate - together
    they are the only way this filter can produce a value outside 0..4096.
    """
    v = to_i32(to_i32(total) * gain) >> 10
    if v >= FULL:
        return FULL
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def sliding(samples, kernel, gain):
    """One pass over one axis (0x10051b65 / 0x10051bc0 / 0x10051c27).

    Emits len(samples) + kernel - 1 values. The pre-pad guarantees
    len(samples) >= kernel, so the middle phase never goes negative.
    """
    n = len(samples)
    out, total, lead, trail = [], 0, 0, 0
    for _ in range(kernel):
        total += samples[lead]; lead += 1
        out.append(saturate(total, gain))
    for _ in range(n - kernel):
        total += samples[lead] - samples[trail]; lead += 1; trail += 1
        out.append(saturate(total, gain))
    for _ in range(kernel - 1):
        total -= samples[trail]; trail += 1
        out.append(saturate(total, gain))
    return out


def coverage(alpha, kernel, gain):
    """Passes 1 and 2's alpha maths: vertical then horizontal, both saturating.

    `alpha` is a list of rows over the PRE-PADDED object. Returns the
    (h + kernel - 1) x (w + kernel - 1) coverage map.
    """
    h, w = len(alpha), len(alpha[0])
    cols = [sliding([alpha[y][x] for y in range(h)], kernel, gain) for x in range(w)]
    scratch = [[cols[x][y] for x in range(w)] for y in range(h + kernel - 1)]
    return [sliding(row, kernel, gain) for row in scratch]


# ----------------------------------------------------------------- the render

def render(obj, p, colour, pattern_alpha=None, draw_object=True):
    """The whole of func_proc, ending at the crop that publishes the canvas.

    `obj` is row-major-by-row [(y, cb, cr, a)]; the returned canvas is
    final_w x final_h, row-major flat.
    """
    w, h, size, kernel = p["w"], p["h"], p["size"], p["kernel"]
    px, py = p["pad_x"], p["pad_y"]
    pw, ph = p["padded_w"], p["padded_h"]
    cw, ch = p["canvas_w"], p["canvas_h"]

    # the pre-pad: table[0x48] clears, table[0x44] drops the object in the middle
    padded = [[[0, 0, 0, 0] for _ in range(pw)] for _ in range(ph)]
    for y in range(h):
        for x in range(w):
            padded[py + y][px + x] = list(obj[y][x])

    cov = coverage([[padded[y][x][3] for x in range(pw)] for y in range(ph)],
                   kernel, p["gain"])

    canvas = [[0, 0, 0, 0] for _ in range(cw * ch)]
    for y in range(ch):
        for x in range(cw):
            c = cov[y][x]
            dst = canvas[y * cw + x]
            if pattern_alpha is not None:               # sub_10051ea0
                dst[0], dst[1], dst[2] = colour         # stands in for the tiled pattern
                dst[3] = pattern_alpha
                if c < FULL:
                    dst[3] = to_i32(dst[3] * c) >> 12
            elif c == 0:                                # sub_10051c80, 0x10051d35
                dst[3] = 0                              # colour deliberately left alone
            else:
                dst[0], dst[1], dst[2] = colour
                dst[3] = c

    # table[0x44](..., mode=3): the object, unmodified, at (size, size)
    if draw_object:
        for y in range(ph):
            for x in range(pw):
                i = (size + y) * cw + (size + x)
                canvas[i] = composite_normal(canvas[i], padded[y][x])

    # 0x10051a6a: crop the pre-pad back off
    out = []
    for y in range(p["final_h"]):
        for x in range(p["final_w"]):
            out.append(canvas[(py + y) * cw + (px + x)])
    return p["final_w"], p["final_h"], out


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

def make_ring(w, h, outer, inner, colour=(3400, -300, 500)):
    """A soft-edged annulus. The hole is what makes 縁取り interesting: the
    border appears on the inside edge too, which a solid disc would hide."""
    cx, cy = w / 2, h / 2
    px = []
    for y in range(h):
        row = []
        for x in range(w):
            d = ((x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2) ** 0.5
            t = min(outer - d, d - inner)
            a = 0 if t <= 0 else (FULL if t >= 1.5 else int(FULL * t / 1.5))
            row.append([colour[0], colour[1], colour[2], a])
        px.append(row)
    return px


def ascii_art(w, h, px, cols=60, rows=26, channel=3, scale=FULL):
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
    parser.add_argument("--border-size", type=int, default=3,
                        help="raw サイズ, 0..500 (= border width in pixels)")
    parser.add_argument("--blur", type=int, default=10, help="raw ぼかし, 0..100")
    parser.add_argument("--colour", default="000000", help="縁色 as rrggbb")
    parser.add_argument("--pattern-alpha", type=int, default=None,
                        help="stand-in for a tiled pattern image's alpha, 0..4096")
    parser.add_argument("--obj", type=int, default=48, help="the object is obj x obj")
    args = parser.parse_args(argv or [])

    n = args.obj
    colour = rgb_to_ycbcr(args.colour)
    obj = make_ring(n, n, n * 0.42, n * 0.20)

    p = setup(n, n, args.border_size, args.blur)
    if p is None:
        print("サイズ = 0: func_proc returns immediately, nothing is touched at all.")
        return

    print(f"object {n}x{n} (a ring), サイズ={args.border_size} ぼかし={args.blur}, "
          f"縁色=#{args.colour} -> YCbCr{colour}")
    print(f"  size={p['size']}  kernel={p['kernel']}  gain={p['gain']}  "
          f"(1024/{1024 / p['gain']:.2f})")
    print(f"  pre-pad ({p['pad_x']}, {p['pad_y']}) -> working canvas "
          f"{p['canvas_w']}x{p['canvas_h']}, published {p['final_w']}x{p['final_h']}")
    print(f"  the object ends up at ({p['size']}, {p['size']}), so the border is "
          f"{p['size']} px on all four sides")
    print(f"  g_101b1e38 = {p['dead_blur']} is also computed, and read by nothing "
          "(verify_params.py §1)")

    cw, ch, out = render(obj, p, colour, args.pattern_alpha)
    _, _, border_only = render(obj, p, colour, args.pattern_alpha, draw_object=False)
    mode = "pattern" if args.pattern_alpha is not None else "縁色"

    print(f"\n  the border layer's alpha ({mode} encoder) - the silhouette dilated by "
          f"{p['size']} px,\n  which fills the ring's hole from the inside as well:")
    for line in ascii_art(cw, ch, border_only, channel=3):
        print("  " + line)

    print("\n  the composited luminance - the object on top, the border showing around")
    print("  it. Blank is either background or a dark border; the scanline below tells")
    print("  them apart:")
    for line in ascii_art(cw, ch, out, channel=0):
        print("  " + line)

    same = sum(1 for i in range(cw * ch) if out[i][3] == border_only[i][3])
    print(f"\n  {same} of {cw * ch} pixels have the same alpha before and after the")
    print("  object is composited. src-over never reduces alpha, so the two differ")
    print("  exactly where the border was NOT already opaque under the object - which")
    print("  is nowhere at all while the coverage still saturates.")

    mid = ch // 2
    print(f"\n--- a scanline through the middle (canvas row {mid}) ---")
    print(f"  {'x':>5}{'border a':>10}{'object a':>10}{'composited a':>14}{'comp Y':>9}")
    for x in range(0, cw, max(1, cw // 20)):
        ox, oy = x - p["size"], mid - p["size"]
        o_a = obj[oy][ox][3] if 0 <= ox < n and 0 <= oy < n else 0
        c = out[mid * cw + x]
        print(f"  {x:>5}{border_only[mid * cw + x][3]:>10}{o_a:>10}{c[3]:>14}{c[0]:>9}")

    peak = max(q[3] for q in border_only)
    why = ""
    if peak < FULL:
        why = ("  <- capped by the pattern's own alpha (verify_encode.py §4)"
               if args.pattern_alpha is not None else
               "  <- ぼかし scaled the whole border down, not just its edge "
               "(verify_border_chain.py §4)")
    print(f"\n  peak border alpha = {peak} of 4096{why}")
    print("  The border is the silhouette dilated by サイズ, so it also fills the ring's")
    print("  hole from the inside - and the object, composited on top, hides the middle")
    print("  of the dilation. That is the whole effect.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
