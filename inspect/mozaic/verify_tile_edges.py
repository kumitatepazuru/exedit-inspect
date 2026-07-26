"""Verify what the タイル風 checkbox actually draws.

It does not change the averaging at all - the accumulate half of
0x1006b6b0 / 0x1006ba40 is byte-identical in structure to the plain workers.
The only difference is the write-back loop, which classifies each pixel by
its position inside the block (object version at 0x1006b962, frame version
at 0x1006bc58 - the same four compares in the same order):

    0x1006b962  cmp edx, [esp+0x34]   ; x == x_last  ?
    0x1006b966  je  DARK
    0x1006b968  cmp eax, [esp+0x20]   ; y == y_last  ?
    0x1006b96c  je  DARK
    0x1006b96e  cmp edx, [esp+0x44]   ; x == x_first ?
    0x1006b972  je  BRIGHT
    0x1006b974  cmp eax, [esp+0x48]   ; y == y_first ?
    0x1006b978  je  BRIGHT

    BRIGHT 0x1006b987:  y = avg_y + (avg_y >> 2)          ; cb, cr untouched
    DARK   0x1006b99b:  y  = avg_y  - (avg_y  >> 2)
                        cb = avg_cb - (avg_cb >> 2)
                        cr = avg_cr - (avg_cr >> 2)
    NORMAL 0x1006b97a:  y, cb, cr = avg                   ; alpha is written
                                                          ; unmodified in all 3

Four details that a "just draw a bevel" summary would get wrong, and that
this script demonstrates:

  * DARK is tested first, so a cell only 1px wide or tall is drawn dark, not
    bright.
  * x_first/x_last come from the UNCLIPPED block extent (offset + x and
    offset + x + size - 1), so at the image border the bevel line falls
    outside the image and simply is not drawn.
  * BRIGHT scales only luma; DARK scales luma AND both chroma channels. The
    highlight keeps the cell's colour, the shadow desaturates toward grey.
  * there is no clamp on the write (`mov word ptr [ecx], di`), so a bright
    edge on an already-white cell writes y > 4096.

Run via main.py:
    uv run main.py inspect/mozaic/verify_tile_edges.py
"""

BRIGHT, DARK, NORMAL = "B", "D", "."


def offset_asm(dim: int, size: int) -> int:
    """func_proc's (dim % (size*2)) / 2 - see verify_grid.py."""
    rem = dim - int(dim / (size * 2)) * (size * 2)
    return int(rem / 2)


def blocks(dim: int, size: int) -> list[tuple[int, int]]:
    """Clipped 1-D block extents - see verify_grid.py."""
    off, out, x = offset_asm(dim, size), [], -size
    while x < dim:
        start, length = off + x, min(dim - (off + x), size)
        if start < 0:
            length, start = length + start, 0
        if length > 0:
            out.append((start, start + length))
        x += size
    return out


def classify(x: int, y: int, x_first: int, y_first: int, size: int) -> str:
    """The four compares, in the order the asm makes them."""
    x_last = x_first + size - 1
    y_last = y_first + size - 1
    if x == x_last:
        return DARK
    if y == y_last:
        return DARK
    if x == x_first:
        return BRIGHT
    if y == y_first:
        return BRIGHT
    return NORMAL


def shade(v: int, kind: str) -> int:
    """0x1006b987 / 0x1006b99b. `>> 2` is sar, i.e. a floor."""
    if kind == BRIGHT:
        return v + (v >> 2)
    if kind == DARK:
        return v - (v >> 2)
    return v


def cell_map(w: int, h: int, size: int) -> list[str]:
    """Render the whole image the way the タイル風 write loop classifies it."""
    ox, oy = offset_asm(w, size), offset_asm(h, size)
    grid = [[" "] * w for _ in range(h)]
    y = -size
    while y < h:
        x = -size
        while x < w:
            x_first, y_first = ox + x, oy + y
            for py in range(max(0, y_first), min(h, y_first + size)):
                for px in range(max(0, x_first), min(w, x_first + size)):
                    grid[py][px] = classify(px, py, x_first, y_first, size)
            x += size
        y += size
    return ["".join(r) for r in grid]


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("1) the shading factors, exactly as the shifts compute them")
    print("   BRIGHT y = v + (v>>2)      DARK  v = v - (v>>2)")
    for v in (4096, 2048, 1000, 3, 1, 0, -1, -3, -2048):
        print(f"   v={v:6d}  bright={shade(v, BRIGHT):6d} ({shade(v, BRIGHT) / v if v else 0:+.4f}x)"
              f"   dark={shade(v, DARK):6d} ({shade(v, DARK) / v if v else 0:+.4f}x)")
    print("   -> +25% / -25% for positive values; on negative chroma the floor in")
    print("      `sar` makes DARK slightly stronger than a true 0.75x")

    print("\n2) no clamp on write-back: a white cell's highlight exceeds full luma")
    print(f"   avg_y=4096 -> bright y={shade(4096, BRIGHT)}  (PIXEL_YC full scale is 4096)")

    print("\n3) DARK wins over BRIGHT, so a 1px-wide cell is a shadow line")
    for size in (2, 3, 8):
        row = "".join(classify(x, 5, 0, 0, size) for x in range(size))
        print(f"   size={size}: a middle row of a cell = {row!r}")
    print(f"   a 1px cell (x_first == x_last): {classify(0, 0, 0, 0, 1)!r} - DARK, not BRIGHT")
    print("   the same collision happens for real on the 1px-tall partial cells that")
    print("   the centred grid leaves at the image border (see 4 below)")

    print("\n4) 24x14 image, size=6 - note the partial cells at the border have no")
    print("   bevel on the clipped side, because x_first/x_last are unclipped")
    w, h, size = 24, 14, 6
    print(f"   offset_x={offset_asm(w, size)} offset_y={offset_asm(h, size)}  "
          f"columns={[e - s for s, e in blocks(w, size)]}  "
          f"rows={[e - s for s, e in blocks(h, size)]}")
    for line in cell_map(w, h, size):
        print("   " + line)
    print("   B = luma x1.25 (top/left)   D = luma+chroma x0.75 (bottom/right)")

    print("\n5) full-cell case for comparison (24x12, size=6, offsets both 0)")
    for line in cell_map(24, 12, 6):
        print("   " + line)

    print("\n6) alpha is never shaded - 0x1006b9c5 writes avg_a on every path")
    print("   so タイル風 changes only the visible colour of an object, never its")
    print("   silhouette or its edge softness")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
