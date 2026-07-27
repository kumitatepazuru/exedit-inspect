"""An integer-faithful reference implementation of 境界ぼかし, assembled from
verify_radius_clamp.py (範囲/縦横比 -> rx,ry), verify_ease_table.py (the
raised-cosine lookup table) and verify_off_path.py / verify_on_path.py (the
two worker pairs selected by 透明度の境界をぼかす), run end to end on small
synthetic alpha canvases.

境界ぼかし only ever touches the ALPHA channel of the object's own image; y/cb/cr
are never read or written by func_proc (see decompile_boundary_blur.py - the
only buffer offsets it touches are +0xAC/+0xB0's field_6, the alpha word).
This model therefore represents a frame purely as a width*height list of
0..4096 alpha values.

Run via main.py:
    uv run main.py inspect/boundary_blur/simulate_boundary_blur_reference.py
    uv run main.py inspect/boundary_blur/simulate_boundary_blur_reference.py --range 4 --aspect 500
    uv run main.py inspect/boundary_blur/simulate_boundary_blur_reference.py --range 4 --on
"""

import argparse
import math

from tools.cints import MAGIC_1000, c_div, msvc_div

MAGIC = MAGIC_1000
C1 = math.pi / 4096
C2 = 2048.0
EASE_TABLE = [math.trunc(C2 * (1 - math.cos(i * C1))) for i in range(4097)]


def magic_div_1000(x):
    return msvc_div(x, MAGIC, 6)


def radii(rng, aspect, width, height):
    """func_proc 0x10011b08-0x10011b9c: トラックバー -> clamped (rx, ry)."""
    rx = ry = rng
    if aspect > 0:
        ry = magic_div_1000((1000 - aspect) * rng)
    elif aspect < 0:
        rx = magic_div_1000((1000 + aspect) * rng)
    rx = min(rx, c_div(width, 2))
    ry = min(ry, c_div(height, 2))
    return rx, ry


def edge_ramp(length, r):
    """sub_10011c30's per-axis ramp, modelled as the pointer-continuation it
    actually is (see verify_off_path.py for the full derivation and the
    even-length/r==length//2 overrun edge case this reproduces)."""
    if r == 0:
        return [0] * length
    k = 2 * r + 1
    buf = [0] * (length + r)
    cursor = 0
    iter1 = r * 4096
    for _ in range(r + 1):
        iter1 += 4096
        buf[cursor] = 4096 - iter1 // k
        cursor += 1
    middle = length - k
    if middle > 0:
        cursor += middle
    iter1 = k * 4096
    for _ in range(r):
        iter1 -= 4096
        buf[cursor] = 4096 - iter1 // k
        cursor += 1
    return buf[:length]


def erode_off(alpha, width, height, rx, ry):
    """sub_10011c30 + sub_10011db0: geometric rounded-corner erosion."""
    v_ramp = edge_ramp(height, ry)
    h_ramp = edge_ramp(width, rx)
    out = list(alpha)
    for row in range(height):
        v = EASE_TABLE[v_ramp[row]]
        for col in range(width):
            h = EASE_TABLE[h_ramp[col]]
            dist = math.trunc(math.sqrt(h * h + v * v))  # sub_10091ad8 truncates toward zero, does not round
            idx = row * width + col
            out[idx] = max(alpha[idx] - 2 * dist, 0)
    return out


def _box_average_1d(values, radius):
    n = len(values)
    k = 2 * radius + 1
    out = [0] * n
    for i in range(n):
        s = sum(values[j] for j in range(i - radius, i + radius + 1) if 0 <= j < n)
        out[i] = s // k
    return out


def _box_blur_2d(alpha, width, height, rx, ry):
    tmp = [0] * (width * height)
    for col in range(width):
        blurred = _box_average_1d([alpha[row * width + col] for row in range(height)], ry)
        for row in range(height):
            tmp[row * width + col] = blurred[row]
    out = [0] * (width * height)
    for row in range(height):
        blurred = _box_average_1d(tmp[row * width:row * width + width], rx)
        for col in range(width):
            out[row * width + col] = blurred[col]
    return out


def erode_on(alpha, width, height, rx, ry):
    """sub_10012060 + sub_10012200: real box blur of alpha + nonlinear recombine."""
    blurred = _box_blur_2d(alpha, width, height, rx, ry)
    out = []
    for a, b in zip(alpha, blurred):
        t = ((a * b) >> 11) - 4096
        out.append((a * t) >> 12 if t > 0 else 0)
    return out


def boundary_blur(alpha, width, height, rng, aspect, on):
    rx, ry = radii(rng, aspect, width, height)
    fn = erode_on if on else erode_off
    return fn(alpha, width, height, rx, ry), rx, ry


# --------------------------------------------------------------------------

def opaque_rect(w=14, h=10, hole=False):
    """A fully-opaque rectangle, optionally with a single transparent pixel
    punched in the middle to show OFF vs ON's different treatment of
    pre-existing alpha structure (see verify_off_path.py / verify_on_path.py)."""
    px = [4096] * (w * h)
    if hole:
        px[(h // 2) * w + w // 2] = 0
    return px, w, h


def _show(title, alpha, width, height):
    print(f"\n  {title}  ({width}x{height})")
    for row in range(height):
        print("    " + " ".join(f"{alpha[row * width + col]:5d}" for col in range(width)))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--range", dest="rng", type=int, default=3, help="範囲 (0..2000)")
    p.add_argument("--aspect", type=int, default=0, help="縦横比 (-1000..1000)")
    p.add_argument("--on", action="store_true", help="透明度の境界をぼかす (checked = real alpha box blur)")
    p.add_argument("--width", type=int, default=14)
    p.add_argument("--height", type=int, default=10)
    args = p.parse_args(argv or [])

    print(f"境界ぼかし: 範囲={args.rng} 縦横比={args.aspect} "
          f"透明度の境界をぼかす={'ON (real alpha blur)' if args.on else 'OFF (geometric erosion, default)'}")

    alpha, w, h = opaque_rect(args.width, args.height, hole=False)
    rx, ry = radii(args.rng, args.aspect, w, h)
    print(f"  rx={rx} ry={ry}  (clamped to <= width//2={w // 2}, height//2={h // 2})")
    out, _, _ = boundary_blur(alpha, w, h, args.rng, args.aspect, args.on)
    _show("source alpha (fully opaque rectangle)", alpha, w, h)
    _show("result alpha", out, w, h)

    print("\n=== OFF vs ON on the same rectangle WITH an interior hole ===")
    for on, label in ((False, "OFF (default)"), (True, "ON")):
        alpha, w, h = opaque_rect(args.width, args.height, hole=True)
        out, _, _ = boundary_blur(alpha, w, h, args.rng, args.aspect, on)
        _show(f"{label}: result alpha", out, w, h)
    print("\n  OFF leaves the interior hole exactly as sharp as the source (it never reads\n"
          "  neighbouring alpha values, only (row,col) position); ON smears it into its\n"
          "  neighbours because it is a real box blur of the alpha channel.")

    print("\n=== rx/ry clamp: 範囲 larger than half the object's own size ===")
    small_w, small_h = 6, 6
    alpha = [4096] * (small_w * small_h)
    rx, ry = radii(200, 0, small_w, small_h)
    print(f"  a {small_w}x{small_h} object with 範囲=200 clamps to rx=ry={rx} "
          f"(== min(200, {small_w}//2, {small_h}//2))")
    out = erode_off(alpha, small_w, small_h, rx, ry)
    _show("result alpha (whole object erodes toward its own center)", out, small_w, small_h)

    print("\n=== even-size overrun quirk: rx==width//2 on an even width (see verify_off_path.py) ===")
    w, h = 8, 8
    alpha = [4096] * (w * h)
    out = erode_off(alpha, w, h, 4, 4)
    _show(f"{w}x{h}, rx=ry=4 (=w//2=h//2): left/top edge vs right/bottom edge differ slightly", out, w, h)

    print(f"\n=== ON-path recap: same 14x{args.height} rectangle, checkbox checked ===")
    alpha, w, h = opaque_rect(args.width, args.height, hole=False)
    out, rx, ry = boundary_blur(alpha, w, h, args.rng, args.aspect, True)
    _show("result alpha", out, w, h)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
