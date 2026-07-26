"""Integer-faithful reference implementation of モザイク, covering all four
code paths (object effect / frame filter x タイル風 off / on).

Everything here is a direct transcription of the disassembly, so the integer
truncation matches exedit rather than being "close enough":

  * `>> 12` on premultiplied colour is `sar`, i.e. a floor, and it runs on
    signed chroma (verify_alpha_average.py)
  * `sum / count` and the x87 colour divide both truncate TOWARD ZERO, which
    differs from Python's `//` for negative chroma
  * the block grid is anchored to the image centre (verify_grid.py)
  * the thread split is reproduced too, so the `h < thread_num` overlap
    (verify_thread_split.py) is visible here rather than hidden

Run via main.py:
    uv run main.py inspect/mozaic/simulate_mozaic_reference.py
    uv run main.py inspect/mozaic/simulate_mozaic_reference.py --size 8 --tile
    uv run main.py inspect/mozaic/simulate_mozaic_reference.py --threads 4 --self-check
"""

import argparse


# --------------------------------------------------------------------------
# integer primitives, matching the exact instruction used at each site
# --------------------------------------------------------------------------

def cdiv(a: int, b: int) -> int:
    """x86 idiv: truncate toward zero (Python's // floors, which differs)."""
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def sar(v: int, n: int) -> int:
    """Arithmetic shift right: floors, including for negative values."""
    return v >> n


def premul(v: int, a: int) -> int:
    """0x1006b2f0: a >= 4096 passes v through unscaled."""
    return v if a >= 0x1000 else sar(v * a, 12)


# --------------------------------------------------------------------------
# grid geometry (func_proc, 0x1006b0b0..0x1006b13c)
# --------------------------------------------------------------------------

def grid_offset(dim: int, size: int) -> int:
    """(dim % (size*2)) / 2 == (dim / 2) % size: puts a cell edge on the centre."""
    return cdiv(dim - cdiv(dim, size * 2) * (size * 2), 2)


def thread_band(h: int, size: int, tid: int, tnum: int) -> tuple[int, int]:
    """The [start, end) block-row band worker `tid` walks (0x1006b186..0x1006b1e0)."""
    def ceil_to_size(a):
        return cdiv(a + size - 1, size) * size

    y_start = ceil_to_size(cdiv(h * tid, tnum))
    y_end = ceil_to_size(cdiv(h * (tid + 1), tnum))
    if y_start == 0:
        y_start = -size                      # the centred grid starts above y=0
    return y_start, y_end


def clip_span(offset: int, coord: int, size: int, dim: int) -> tuple[int, int]:
    """Clip one block's [offset+coord, +size) extent to [0, dim). Returns (start, len)."""
    start = offset + coord
    length = min(dim - start, size)
    if start < 0:
        length += start
        start = 0
    return start, length


# --------------------------------------------------------------------------
# the tile bevel (0x1006b962 / 0x1006bc58)
# --------------------------------------------------------------------------

BRIGHT, DARK, NORMAL = 1, -1, 0


def bevel_of(px: int, py: int, x_first: int, y_first: int, size: int) -> int:
    """The four compares, in asm order - DARK is tested before BRIGHT."""
    if px == x_first + size - 1 or py == y_first + size - 1:
        return DARK
    if px == x_first or py == y_first:
        return BRIGHT
    return NORMAL


# --------------------------------------------------------------------------
# the four workers
# --------------------------------------------------------------------------

def mozaic_object(pix, w, h, size, tile=False, tnum=1):
    """0x1006b180 (tile=False) / 0x1006b6b0 (tile=True).

    `pix` is a mutable list of h lists of w [y, cb, cr, a] lists, edited in
    place exactly as exedit edits *(fpip+0xAC).
    """
    if size < 2:                             # 0x1006b099: func_proc bails out
        return pix
    ox, oy = grid_offset(w, size), grid_offset(h, size)

    for tid in range(tnum):
        y_start, y_end = thread_band(h, size, tid, tnum)
        for by in range(y_start, y_end, size):
            y0, bh = clip_span(oy, by, size, h)
            if bh <= 0:
                continue
            for bx in range(-size, w, size):
                x0, bw = clip_span(ox, bx, size, w)
                if bw <= 0:
                    continue

                sum_y = sum_cb = sum_cr = sum_a = 0
                count = bw * bh              # alpha-blind: += bw once per row
                for py in range(y0, y0 + bh):
                    for px in range(x0, x0 + bw):
                        y, cb, cr, a = pix[py][px]
                        if a == 0:           # 0x1006b2ea
                            continue
                        sum_y += premul(y, a)
                        sum_cb += premul(cb, a)
                        sum_cr += premul(cr, a)
                        sum_a += a
                if count == 0:
                    continue

                if sum_a == 0:               # 0x1006b387
                    avg_y = avg_cb = avg_cr = 0
                else:                        # x87: * 4096.0, / sum_a, trunc
                    avg_y = int(sum_y * 4096.0 / sum_a)
                    avg_cb = int(sum_cb * 4096.0 / sum_a)
                    avg_cr = int(sum_cr * 4096.0 / sum_a)
                avg_a = cdiv(sum_a, count)   # 0x1006b3d3: divided by COUNT, not sum_a

                for py in range(y0, y0 + bh):
                    for px in range(x0, x0 + bw):
                        y, cb, cr = avg_y, avg_cb, avg_cr
                        if tile:
                            k = bevel_of(px, py, ox + bx, oy + by, size)
                            if k == BRIGHT:
                                y = avg_y + sar(avg_y, 2)          # luma only
                            elif k == DARK:
                                y = avg_y - sar(avg_y, 2)
                                cb = avg_cb - sar(avg_cb, 2)
                                cr = avg_cr - sar(avg_cr, 2)
                        pix[py][px] = [y, cb, cr, avg_a]           # alpha never shaded
    return pix


def mozaic_frame(pix, w, h, size, tile=False, tnum=1):
    """0x1006b470 (tile=False) / 0x1006ba40 (tile=True).

    `pix` is h lists of w [y, cb, cr] lists (fpip->ycp_edit), edited in place.
    """
    if size < 2:
        return pix
    ox, oy = grid_offset(w, size), grid_offset(h, size)

    for tid in range(tnum):
        y_start, y_end = thread_band(h, size, tid, tnum)
        for by in range(y_start, y_end, size):
            y0, bh = clip_span(oy, by, size, h)
            if bh <= 0:
                continue
            for bx in range(-size, w, size):
                x0, bw = clip_span(ox, bx, size, w)
                if bw <= 0:
                    continue

                sum_y = sum_cb = sum_cr = 0
                count = bw * bh
                for py in range(y0, y0 + bh):
                    for px in range(x0, x0 + bw):
                        y, cb, cr = pix[py][px]
                        sum_y += y
                        sum_cb += cb
                        sum_cr += cr
                if count == 0:
                    continue
                avg_y = cdiv(sum_y, count)
                avg_cb = cdiv(sum_cb, count)
                avg_cr = cdiv(sum_cr, count)

                for py in range(y0, y0 + bh):
                    for px in range(x0, x0 + bw):
                        y, cb, cr = avg_y, avg_cb, avg_cr
                        if tile:
                            k = bevel_of(px, py, ox + bx, oy + by, size)
                            if k == BRIGHT:
                                y = avg_y + sar(avg_y, 2)
                            elif k == DARK:
                                y = avg_y - sar(avg_y, 2)
                                cb = avg_cb - sar(avg_cb, 2)
                                cr = avg_cr - sar(avg_cr, 2)
                        pix[py][px] = [y, cb, cr]
    return pix


# --------------------------------------------------------------------------
# demo
# --------------------------------------------------------------------------

RAMP = " .:-=+*#%@"


def _luma_art(pix, w, h):
    out = []
    for row in pix[:h]:
        out.append("".join(RAMP[min(len(RAMP) - 1, max(0, p[0] * len(RAMP) // 4097))]
                           for p in row[:w]))
    return out


def _test_frame(w, h):
    """A diagonal ramp with a bright square, enough to show block boundaries."""
    pix = []
    for y in range(h):
        row = []
        for x in range(w):
            v = (x + y) * 4096 // (w + h)
            if 6 <= x < 14 and 4 <= y < 10:
                v = 4096
            row.append([v, 0, 0])
        pix.append(row)
    return pix


def _test_object(w, h):
    """The same, but as a circle on a fully transparent background."""
    pix = []
    cx, cy, r = w / 2, h / 2, min(w, h) * 0.42
    for y in range(h):
        row = []
        for x in range(w):
            inside = (x - cx) ** 2 + (y - cy) ** 2 <= r * r
            row.append([(x + y) * 4096 // (w + h) if inside else 0,
                        0, 0, 4096 if inside else 0])
        pix.append(row)
    return pix


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size", type=int, default=6, help="サイズ (track[0])")
    parser.add_argument("--tile", action="store_true", help="タイル風 on")
    parser.add_argument("--width", type=int, default=40)
    parser.add_argument("--height", type=int, default=20)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--self-check", action="store_true",
                        help="assert the thread split does not change the result")
    args = parser.parse_args(argv or [])

    w, h, size = args.width, args.height, args.size
    print(f"w={w} h={h} サイズ={size} タイル風={'on' if args.tile else 'off'} "
          f"threads={args.threads}")
    print(f"offset_x={grid_offset(w, size)} offset_y={grid_offset(h, size)}  "
          f"(a cell edge sits on x={w // 2}, y={h // 2})")

    src = _test_frame(w, h)
    before = _luma_art(src, w, h)
    dst = mozaic_frame([[list(p) for p in r] for r in src], w, h, size,
                       args.tile, args.threads)
    after = _luma_art(dst, w, h)
    print("\nframe filter (no alpha, plain integer mean):")
    print(f"  {'source':<{w}}   result")
    for a, b in zip(before, after):
        print(f"  {a}   {b}")

    osrc = _test_object(w, h)
    dst_o = mozaic_object([[list(p) for p in r] for r in osrc], w, h, size,
                          args.tile, args.threads)
    print("\nobject effect (alpha-weighted; second pane is alpha):")
    print(f"  {'result luma':<{w}}   result alpha")
    alpha_art = ["".join(RAMP[min(len(RAMP) - 1, max(0, p[3] * len(RAMP) // 4097))]
                         for p in row) for row in dst_o]
    for a, b in zip(_luma_art(dst_o, w, h), alpha_art):
        print(f"  {a}   {b}")

    if args.self_check:
        print("\nself-check: thread count must not change the output for h >= tnum")
        base = mozaic_frame([[list(p) for p in r] for r in src], w, h, size, args.tile, 1)
        for tnum in (2, 3, 4, 8, 16):
            if h < tnum:
                print(f"  tnum={tnum:2d}: skipped (h={h} < tnum, the overlapping-band case)")
                continue
            got = mozaic_frame([[list(p) for p in r] for r in src], w, h, size, args.tile, tnum)
            print(f"  tnum={tnum:2d}: {'identical' if got == base else 'DIFFERS'}")

        print("\nself-check: an opaque object must give the same luma as the frame filter")
        opaque = [[[(x + y) * 4096 // (w + h), 0, 0] for x in range(w)] for y in range(h)]
        opaque_a = [[p + [4096] for p in row] for row in opaque]
        f = mozaic_frame([[list(p) for p in r] for r in opaque], w, h, size, args.tile)
        o = mozaic_object([[list(p) for p in r] for r in opaque_a], w, h, size, args.tile)
        same = all(f[y][x][:3] == o[y][x][:3] for y in range(h) for x in range(w))
        print(f"  {'identical' if same else 'DIFFERS'}  "
              f"(premultiply by a=4096 then divide by sum_a=4096*n is the plain mean,")
        print("   but the two divides truncate differently, so this is worth checking)")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
