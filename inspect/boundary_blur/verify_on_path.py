"""Transcribe the ON-path workers (透明度の境界をぼかす CHECKED) from capstone
disassembly, then run the transcription on synthetic alpha canvases to check
the properties claimed in the README - in particular that, unlike the
OFF-path (verify_off_path.py), this path really does blur the object's own
alpha channel, so a hole already punched in the middle of a sprite gets
feathered too.

sub_10012060 (vertical pass) is a plain sliding-window box average of the
ORIGINAL alpha channel *(fpip+0xAC), written into the secondary buffer
*(fpip+0xB0):

    0x100120e4-f6:  growing phase   (0..ry samples summed so far)
    0x10012108-13d: full window     (exactly kernelWidth_y=2*ry+1 samples)
    0x10012151-19a: shrinking phase (window trails off past the bottom edge)
    -> in EVERY phase the running sum is divided by the FULL kernel width
       (`idiv ebx` where ebx=g_1011ec50 never changes), so samples outside
       the image implicitly contribute 0 - zero-padding, not edge-replicate
       or renormalize-by-count like ぼかし's `サイズ固定` ON variant
       (inspect/blur's verify_box_average.py) uses.

sub_10012200 (horizontal pass) does the same box sum again, this time over
the vertically-box-averaged buffer, then recombines with the ORIGINAL alpha
through a nonlinear curve instead of just overwriting it:

    0x100122b4-bd:  esi = running horizontal sum of buffer B (already vertically averaged)
    0x100122bd:     blurred = esi // kernelWidth_x            ; box2d average, 0..4096ish
    0x100122bf-c9:  t = ((orig_alpha * blurred) >> 11) - 4096
    0x100122ce-d8:  alpha' = (orig_alpha * t) >> 12  if t > 0  else 0

Run via main.py:
    uv run main.py inspect/boundary_blur/verify_on_path.py
"""


def box_average_1d(values, radius):
    """sub_10012060 / the first half of sub_10012200: a sliding-window sum
    ALWAYS divided by the full kernel width (2*radius+1), even where fewer
    than that many samples exist (out-of-bounds samples count as 0)."""
    n = len(values)
    k = 2 * radius + 1
    out = [0] * n
    for i in range(n):
        s = 0
        for d in range(-radius, radius + 1):
            j = i + d
            if 0 <= j < n:
                s += values[j]
        out[i] = s // k
    return out


def box_blur_alpha(alpha, width, height, rx, ry):
    """2D separable box average of the alpha channel, zero-padded at the
    image edges - sub_10012060 then sub_10012200's running sum."""
    # vertical pass (per column)
    tmp = [0] * (width * height)
    for col in range(width):
        column = [alpha[row * width + col] for row in range(height)]
        blurred = box_average_1d(column, ry)
        for row in range(height):
            tmp[row * width + col] = blurred[row]
    # horizontal pass (per row)
    out = [0] * (width * height)
    for row in range(height):
        blurred = box_average_1d(tmp[row * width:row * width + width], rx)
        for col in range(width):
            out[row * width + col] = blurred[col]
    return out


def recombine(orig_alpha, blurred_alpha):
    """sub_10012200's final nonlinear step, applied after the box blur."""
    t = ((orig_alpha * blurred_alpha) >> 11) - 4096
    if t <= 0:
        return 0
    return (orig_alpha * t) >> 12


def erode_alpha_on(alpha, width, height, rx, ry):
    blurred = box_blur_alpha(alpha, width, height, rx, ry)
    return [recombine(alpha[i], blurred[i]) for i in range(width * height)]


def _print_grid(title, grid, width, height):
    print(f"  {title}")
    for row in range(height):
        print("    " + " ".join(f"{grid[row * width + col]:5d}" for col in range(width)))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("--- recombine() sanity checks at the corners of its (orig_alpha, blurred_alpha) domain ---")
    for a, b, note in [
        (4096, 4096, "fully opaque and untouched by the blur -> should stay 4096"),
        (4096, 0, "opaque pixel whose neighbourhood is fully transparent -> should go to 0"),
        (0, 4096, "already-transparent pixel -> stays 0 regardless of neighbours"),
        (4096, 2048, "opaque pixel exactly half-covered by its own window -> boundary case"),
    ]:
        print(f"  orig={a:4d} blurred={b:4d} -> {recombine(a, b):4d}   ({note})")

    print("\n--- a fully-opaque 12x8 rectangle, rx=ry=3 (compare with verify_off_path.py's same case) ---")
    w, h = 12, 8
    alpha = [4096] * (w * h)
    out = erode_alpha_on(alpha, w, h, 3, 3)
    _print_grid("resulting alpha:", out, w, h)
    print(f"  corner={out[0]}  top-edge-middle={out[w // 2]}  center={out[(h // 2) * w + w // 2]}")
    print(f"  interior (more than r pixels from every edge) is untouched: {out[(h // 2) * w + w // 2] == 4096}")

    print("\n--- ON-path DOES react to a hole punched in the source alpha (unlike OFF) ---")
    w, h = 12, 8
    alpha = [4096] * (w * h)
    hole_row, hole_col = h // 2, w // 2
    alpha[hole_row * w + hole_col] = 0
    out = erode_alpha_on(alpha, w, h, 2, 2)
    neighbours = [out[hole_row * w + hole_col + d] for d in (-3, -2, -1, 0, 1, 2, 3)]
    print(f"  interior hole at (row={hole_row},col={hole_col}): alpha across col-3..col+3 = {neighbours}")
    print("  (the hole visibly dims its neighbours - the box blur genuinely mixes the alpha\n"
          "   channel, unlike the OFF path which only erodes from the bounding-box edge)")

    print("\n--- edge zero-padding: a fully-opaque strip near the left edge (rx=4, width=10) ---")
    w, h = 10, 1
    alpha = [4096] * (w * h)
    out = erode_alpha_on(alpha, w, h, 4, 0)
    print(f"  row: {out}")
    print("  (alpha drops near column 0 even though every real pixel is opaque - the missing\n"
          "   samples past the left edge count as 0 in the box sum, i.e. zero-padding, exactly\n"
          "   like the OFF path's geometric erosion also only ever fades TOWARD the edge)")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
