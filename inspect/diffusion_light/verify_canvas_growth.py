"""How the object-effect version makes room for light that spills outside the
object, and why the intermediate buffer is written 2r+1 pixels to the right.

With サイズ固定 unchecked, 拡散光 grows the canvas by `拡散` pixels on every
side - r1 per side in round 1 and r2 in round 2, and r1 + r2 == 拡散
(verify_radius_split.py). There is no call to exedit's 「オフスクリーン描画」
helper the way 発光 does it; instead the blur workers themselves write outside
the old bounds and func_proc bumps w/h afterwards:

    vertical pass writes h + 2r rows   ->  *(fpip+0xB8) += 2r
    horizontal pass writes w + 2r cols ->  *(fpip+0xB4) += 2r, buffers swapped

The three things that are easy to get wrong, and what this script checks:

  1. **where the image ends up**. Output row d is the box sum of source rows
     [d-2r, d] clipped to the image, i.e. output row d corresponds to source
     row d-r. Since the buffer origin never moves and the canvas gains r rows
     at each end, the object stays centred. This is checked by *replaying the
     three loops* (their trip counts are read straight off the disassembly)
     and comparing the set of rows each one actually accumulates against
     `clip([d-2r, d])` - not by re-deriving the same formula twice.

  2. **the 2r+1 column shift**. The vertical worker writes to
     `dst + (kernel_width + column)*8` (0x1001c784) while the fixed-size one
     writes to the same column (0x1001d77f). The reason is that the growing
     horizontal worker runs *in place*: it reads *(fpip+0xB0) at column
     kw + i and writes *(fpip+0xB0) at column i (0x1001cb8f / 0x1001cb92).
     The shift is exactly kw and not one more, because the pixel leaving the
     window is read from the very column about to be overwritten, one
     instruction earlier.

  3. **the single blanked row**. func_proc zeroes one row *above* each object
     buffer (0x1001c3f5, 0x1001c428). The horizontal worker points its
     "original image" pointer at that row for every output row outside the
     original image (0x1001cbb9), so those rows composite against a fully
     transparent pixel and come out as pure diffusion.

Also here: the clamp that keeps the grown canvas inside the buffer, and the
escape hatch for radii that are large relative to the image, where the canvas
is grown up-front through exedit's own draw table and the *fixed-size* workers
run instead.

Run via main.py:
    uv run main.py inspect/diffusion_light/verify_canvas_growth.py
"""

from tools.cints import c_div
from tools.disasm import dump_all
from tools.pe_image import PEImage

PREAMBLE = (0x1001C38B, 0xA6)
ESCAPE = (0x1001C45E, 0x2A)
VERTICAL_PTRS = (0x1001C76C, 0x20)
VERTICAL_LOOPS = {
    "vertical loop 1 (ramp-up) trip count": (0x1001C797, 0x0A),
    "vertical loop 2 (sliding) trip count": (0x1001C888, 0x12),
    "vertical loop 3 (tail) trip count": (0x1001C9F7, 0x11),
}
HORIZONTAL_PTRS = (0x1001CB7A, 0x50)
HORIZONTAL_INPLACE = (0x1001D042, 0x08)

ANNOTATIONS = {
    0x1001C38B: "w",
    0x1001C391: "stride == the widest row the buffer can hold",
    0x1001C397: "w + 拡散*4",
    0x1001C39A: "fits?",
    0x1001C3A8: "no: 拡散 = c_div(stride - w, 4)",
    0x1001C3B1: "h",
    0x1001C3B7: "*(fpip+0xF0) = height limit",
    0x1001C3D2: "same clamp on the vertical axis",
    0x1001C3EE: "one row above *(fpip+0xAC)",
    0x1001C3F5: "zero w + 拡散*4 pixels there",
    0x1001C428: "and the same above *(fpip+0xB0)",
    0x1001C464: "2*r1 vs w",
    0x1001C474: "2*r1 vs h",
    0x1001C479: "2*r2 vs w",
    0x1001C47D: "2*r2 vs h",
    0x1001C47F: "all four fit -> let the workers grow the canvas as they blur",
    0x1001C76C: "src = *(fpip+0xAC) ...",
    0x1001C77A: "... + column*8, row 0",
    0x1001C772: "dst = *(fpip+0xB0) ...",
    0x1001C77D: "... + (kernel_width + column)",
    0x1001C784: "... *8 - the whole intermediate is shifted 2r+1 pixels right",
    0x1001C797: "loop 1 runs kernel_width times",
    0x1001C888: "loop 2 runs h - kernel_width times",
    0x1001C894: "(h is the *pre-growth* height here; the += 2r happens after this worker)",
    0x1001C9F7: "loop 3 runs kernel_width - 1 = 2r times: h + 2r rows written in total",
    0x1001CB7A: "row index",
    0x1001CB85: "the buffer the vertical pass just wrote",
    0x1001CB8F: "leading read pointer: column kernel_width == logical column 0",
    0x1001CB92: "write pointer: column 0 - same buffer, in place",
    0x1001CB8D: "output row < r ?",
    0x1001CBA5: "or >= h - r ?",
    0x1001CBB4: "no: the original image, row (output row - r)",
    0x1001CBB9: "yes: the blanked row above the buffer - fully transparent",
    0x1001D042: "trailing read: the pixel leaving the window ...",
    0x1001D046: "... read here, one instruction before the same column is written",
}


def vertical_rows(h: int, r: int) -> dict[int, list[int]]:
    """Replay the three loops of 0x1001c710 and record which source rows each
    output row ends up holding. Trip counts and pointer motion are taken from
    the disassembly, nothing else."""
    kw = 2 * r + 1
    window: list[int] = []
    out: dict[int, list[int]] = {}
    lead = 0        # esi, source row
    trail = 0       # edi, source row
    dst = 0         # ebx, destination row
    for _ in range(kw):                 # loop 1: add only
        window.append(lead); lead += 1
        out[dst] = list(window); dst += 1
    for _ in range(h - kw):             # loop 2: add + subtract
        window.append(lead); lead += 1
        window.remove(trail); trail += 1
        out[dst] = list(window); dst += 1
    for _ in range(kw - 1):             # loop 3: subtract only
        window.remove(trail); trail += 1
        out[dst] = list(window); dst += 1
    return out


def horizontal_cols(w: int, r: int) -> dict[int, tuple[list[int], int | None]]:
    """Same for 0x1001cb10: which source columns each output column sums, and
    which column of the *original* image it composites against (None = the
    blank pixel). Five loops, in the order they appear at 0x1001cbe2,
    0x1001ccf5, 0x1001cfc7, 0x1001d31f and 0x1001d601."""
    kw = 2 * r + 1
    window: list[int] = []
    out: dict[int, tuple[list[int], int | None]] = {}
    lead = trail = dst = 0

    def emit(with_source: bool):
        nonlocal dst
        src = dst - r if with_source else None
        out[dst] = (list(window), src)
        dst += 1

    for _ in range(r):                  # loop 1: outside the image on the left
        window.append(lead); lead += 1
        emit(False)
    for _ in range(kw - r):             # loop 2: ramp-up, composited
        window.append(lead); lead += 1
        emit(True)
    for _ in range(w - kw):             # loop 3: sliding, composited
        window.append(lead); lead += 1
        window.remove(trail); trail += 1
        emit(True)
    for _ in range(r):                  # loop 4: tail, still composited
        window.remove(trail); trail += 1
        emit(True)
    for _ in range(r):                  # loop 5: outside the image on the right
        window.remove(trail); trail += 1
        emit(False)
    return out


def clip(lo: int, hi: int, n: int) -> list[int]:
    return [i for i in range(lo, hi + 1) if 0 <= i < n]


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_all(PEImage(dll_path), {
        "func_proc: clamp 拡散 to the buffer, blank one row above each buffer": PREAMBLE,
        "func_proc: can the workers grow the canvas themselves?": ESCAPE,
        "0x1001c710: source/destination pointers": VERTICAL_PTRS,
        **VERTICAL_LOOPS,
        "0x1001cb10: in-place read/write pointers and the source row": HORIZONTAL_PTRS,
        "0x1001cb10: the trailing read that makes in-place safe": HORIZONTAL_INPLACE,
    }, annotations=ANNOTATIONS)

    print("\n--- clamp: 拡散 is reduced until w + 4*拡散 <= stride and h + 4*拡散 <= max_h ---")
    print("    (4x, although each round only adds 2r and the two rounds add 2*拡散 in total)")
    for w, h, stride, max_h, raw in ((320, 240, 512, 384, 30), (320, 240, 512, 384, 60),
                                     (100, 100, 4096, 4096, 500)):
        rad = raw
        if w + rad * 4 > stride:
            rad = c_div(stride - w, 4)
        if h + rad * 4 > max_h:
            rad = c_div(max_h - h, 4)
        print(f"  w={w} h={h} stride={stride} max_h={max_h}  拡散={raw:3d} -> {rad}"
              f"   final canvas {w + 2 * rad}x{h + 2 * rad}")

    print("\n--- vertical pass: the three loops really do produce clip([d-2r, d]) ---")
    for h, r in ((16, 3), (32, 7), (240, 56)):
        rows = vertical_rows(h, r)
        want_n = h + 2 * r
        ok_count = len(rows) == want_n
        ok_window = all(rows[d] == clip(d - 2 * r, d, h) for d in rows)
        centre = (want_n - 1) / 2 - r
        print(f"  h={h:4d} r={r:3d}: rows written={len(rows):4d} (expected {want_n})"
              f"  windows match clip([d-2r,d]): {ok_window}"
              f"  centre maps to source row {centre:.1f} (= (h-1)/2 = {(h - 1) / 2:.1f})")
        assert ok_count and ok_window

    print("\n--- horizontal pass: five loops, and which columns see the original image ---")
    for w, r in ((16, 3), (32, 7)):
        cols = horizontal_cols(w, r)
        ok_window = all(cols[d][0] == clip(d - 2 * r, d, w) for d in cols)
        blank = [d for d in cols if cols[d][1] is None]
        composited = [d for d in cols if cols[d][1] is not None]
        srcs = [cols[d][1] for d in composited]
        print(f"  w={w:3d} r={r:2d}: cols written={len(cols):3d} (expected {w + 2 * r})"
              f"  windows match: {ok_window}")
        print(f"          luminous-only columns: {blank}")
        print(f"          composited columns {composited[0]}..{composited[-1]} -> "
              f"source columns {srcs[0]}..{srcs[-1]} (image is 0..{w - 1})")
        assert ok_window and len(cols) == w + 2 * r
        assert srcs == list(range(0, w)), "composited columns must cover the image exactly"

    print("\n--- in-place safety margin ---")
    for r in (1, 3, 7):
        kw = 2 * r + 1
        # loop 3 iteration for output column d: leading read at kw+d, trailing at d,
        # write at d.  A shift of kw-1 would have the trailing read land on an
        # already-overwritten pixel.
        d = kw
        print(f"  r={r}: writing output column {d} reads columns {d + kw} (leading) and "
              f"{d} (trailing); the trailing read is the same address as the write")
    print("  -> the shift cannot be smaller than 2r+1, and being larger would waste")
    print("     the margin the clamp above has to reserve.")

    print("\n--- when the workers cannot do it: the up-front grow ---")
    print("  condition (0x1001c45e): 2*r1 >= w or 2*r1 >= h or 2*r2 >= w or 2*r2 >= h")
    print("  then func_proc clears a (w+2R)x(h+2R) canvas and blits the image at (R,R),")
    print("  R = r1 + r2 = 拡散, swaps the buffers, and forces サイズ固定 = 1 locally")
    print("  (0x1001c4af), so both rounds run the *fixed-size* workers on the new canvas.")
    print("  Either way the object grows by exactly 拡散 pixels on each side.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
