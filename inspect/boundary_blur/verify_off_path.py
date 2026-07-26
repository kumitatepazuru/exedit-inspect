"""Transcribe the OFF-path workers (透明度の境界をぼかす UNCHECKED, the
default) instruction-for-instruction from capstone disassembly, then run the
transcription on synthetic alpha canvases to check the properties claimed in
the README.

sub_10011c30 (vertical mask writer) writes a per-column ramp into the alpha
channel of the secondary buffer *(fpip+0xB0), one axis at a time. Crucially,
the x86 write pointer (`ecx`) is threaded continuously through all three
phases by plain `add ecx, <row stride>` - it is NEVER recomputed from an
absolute row index, so this is a pointer-continuation model, not a "top r+1
rows, bottom r rows" mirror:

    0x10011c9b: ecx = buffer_B + column*8             ; row 0 of this column
    0x10011cb7-cec: for i in 0..ry (ry+1 rows):        ; TOP edge
        iter1 = (ry + i + 1) * 4096
        val = 4096 - iter1 // kernelWidth_y            ; kernelWidth_y = 2*ry+1
        write val to *ecx; ecx += row_stride
    0x10011cfc-d18: for (height - kernelWidth_y) rows:  ; interior (skipped if <= 0)
        write 0 to *ecx; ecx += row_stride
    0x10011d25-d56: for k in 0..ry-1 (ry rows):          ; BOTTOM edge
        iter1 -= 4096
        val = 4096 - iter1 // kernelWidth_y
        write val to *ecx; ecx += row_stride

When kernelWidth_y <= height (the common case), the interior loop runs and
leaves `ecx` exactly `height - ry` rows in, so the bottom loop lands on the
last ry rows - a clean mirror of the top, verified below. But when 範囲
(clamped) reaches exactly height//2 on an EVEN height, kernelWidth_y =
height+1 > height: the interior loop's trip count goes negative and is
skipped, `ecx` is left only ry+1 rows in, and the bottom loop's ry writes
land at rows [ry+1 .. height] - the last of which is one row PAST this
column's own data. This is a genuine, silent one-row overrun that this
script reproduces (and flags) rather than assumes away.

sub_10011db0 (horizontal combine) recomputes the same per-axis formula
inline for the horizontal direction (no interior-loop hazard there because
it revisits every column every row, not via a threaded pointer across the
whole axis), reads the vertical mask plus the ORIGINAL alpha, and erodes:

    0x10011e6b: v = ease_table[mask_value]              ; mask_value from sub_10011c30 (forward index)
    0x10011e68: h = ease_table[4096 - h_ratio]           ; h_ratio, same formula shape as the vertical one
    0x10011e73-e87: dist = trunc(sqrt(h*h + v*v))          ; fild/fsqrt/trunc via sub_10091ad8 (truncating, not rounding)
    0x10011e92-ea5: alpha' = max(orig_alpha - 2*dist, 0)

None of this reads the object's own alpha except as the thing being eroded -
the erosion amount depends only on (row, col) position relative to the
object's own bounding box and (rx, ry). A hole punched in the middle of an
otherwise-opaque sprite is NOT rounded off by this path (verify_on_path.py's
ON-path counterpart does react to it).

Run via main.py:
    uv run main.py inspect/boundary_blur/verify_off_path.py
"""

import math

# table[i] = trunc(2048*(1-cos(i*pi/4096))), i=0..4096 - derived and checked
# against the .rdata constants in verify_ease_table.py; inlined here so this
# script stays self-contained like the rest of inspect/.
C1 = math.pi / 4096
C2 = 2048.0
EASE_TABLE = [math.trunc(C2 * (1 - math.cos(i * C1))) for i in range(4097)]


def edge_ramp(length, r):
    """sub_10011c30's per-axis formula, modelled as the pointer-continuation
    it actually is. Returns (ramp, overrun): ramp is the LINEAR (pre-easing)
    values that land inside [0,length), and overrun is how many of the
    bottom/right-edge writes fell past position length-1 (0 in the normal
    case; only nonzero when 2r+1 > length, i.e. r clamped to exactly
    length//2 on an even length - see the module docstring)."""
    if r == 0:
        return [0] * length, 0
    k = 2 * r + 1
    buf = [0] * (length + r)  # generous tail so out-of-range writes don't raise
    cursor = 0
    iter1 = r * 4096
    for _ in range(r + 1):  # top/left edge: r+1 taps
        iter1 += 4096
        buf[cursor] = 4096 - iter1 // k
        cursor += 1
    middle = length - k
    if middle > 0:  # interior: only runs when the two edges don't already overlap
        cursor += middle  # every write here is 0, buf is already 0-initialized
    iter1 = k * 4096
    for _ in range(r):  # bottom/right edge: r taps, continuing from `cursor`
        iter1 -= 4096
        buf[cursor] = 4096 - iter1 // k
        cursor += 1
    overrun = max(0, cursor - length)
    return buf[:length], overrun


def erode_alpha_off(alpha, width, height, rx, ry):
    """Full OFF-path: alpha is a width*height list of 0..4096 ints (row-major).
    Returns the eroded alpha, matching sub_10011c30 + sub_10011db0 exactly."""
    v_ramp, _ = edge_ramp(height, ry)  # same for every column
    h_ramp, _ = edge_ramp(width, rx)  # same for every row
    out = list(alpha)
    for row in range(height):
        v = EASE_TABLE[v_ramp[row]]
        for col in range(width):
            h = EASE_TABLE[h_ramp[col]]
            dist = math.trunc(math.sqrt(h * h + v * v))  # sub_10091ad8 truncates toward zero, does not round
            idx = row * width + col
            out[idx] = max(alpha[idx] - 2 * dist, 0)
    return out


def _print_grid(title, grid, width, height):
    print(f"  {title}")
    for row in range(height):
        print("    " + " ".join(f"{grid[row * width + col]:5d}" for col in range(width)))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("--- edge ramp for a single axis, various (length, r) ---")
    for length, r in [(12, 0), (12, 1), (12, 2), (12, 3), (12, 5), (10, 3), (7, 3)]:
        ramp, overrun = edge_ramp(length, r)
        print(f"  length={length:2d} r={r}: {ramp}   overrun={overrun}")
    print("  -> all clean mirrors (overrun=0): 2r+1 <= length in every case above")

    print("\n--- the overrun case: EVEN length, r clamped to exactly length//2 ---")
    for length in (6, 8, 10):
        r = length // 2
        ramp, overrun = edge_ramp(length, r)
        print(f"  length={length} r={r} (=length//2, 2r+1={2 * r + 1} > length): "
              f"ramp={ramp}  overrun={overrun}")
        print(f"    ramp[0]={ramp[0]} vs ramp[-1]={ramp[-1]}: "
              f"{'symmetric' if ramp[0] == ramp[-1] else 'ASYMMETRIC - one bottom/right write escaped the buffer'}")
    print("  This is reachable from the UI: an object whose width or height (in pixels) is\n"
          "  even, with 範囲 set at or above half that dimension, silently loses a little\n"
          "  symmetry at the bottom/right edge (and, in the real DLL, writes one PIXEL_YCA's\n"
          "  worth of alpha into whatever memory follows that column in the buffer - harmless\n"
          "  in practice since exedit allocates buffers at the max canvas size, same class of\n"
          "  quirk as ぼかし's サイズ固定-off edge case, inspect/blur's README section 9).")

    print("\n--- full erosion of a fully-opaque 12x8 rectangle, rx=ry=3 ---")
    w, h = 12, 8
    alpha = [4096] * (w * h)
    out = erode_alpha_off(alpha, w, h, 3, 3)
    _print_grid("resulting alpha (0=fully transparent, 4096=fully opaque):", out, w, h)
    corner = out[0]
    edge_mid_top = out[w // 2]
    center = out[(h // 2) * w + w // 2]
    print(f"  corner (0,0)={corner}  top-edge-middle={edge_mid_top}  center={center}")
    print(f"  corner is more eroded than the top-edge midpoint: {corner <= edge_mid_top} "
          "(both axes contribute at the corner -> larger sqrt(h^2+v^2) -> more erosion,"
          " i.e. the fade rounds the corner instead of mitring it)")
    print(f"  interior (more than r pixels from every edge) is untouched: {center == 4096}")

    print("\n--- OFF-path ignores a hole already punched in the source alpha ---")
    w, h = 12, 8
    alpha = [4096] * (w * h)
    hole_row, hole_col = h // 2, w // 2
    alpha[hole_row * w + hole_col] = 0  # a single fully-transparent pixel deep in the interior
    out = erode_alpha_off(alpha, w, h, 2, 2)
    neighbours = [out[hole_row * w + hole_col + d] for d in (-1, 0, 1)]
    print(f"  interior hole at (row={hole_row},col={hole_col}): alpha at col-1,col,col+1 = {neighbours}")
    print("  (the hole stays a lone 0 with 4096 on both sides - no averaging/spreading happens\n"
          "   around it, because OFF only erodes from the OBJECT's own rectangular bounding-box\n"
          "   edge. verify_on_path.py shows the ON path reacts to this hole instead.)")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
