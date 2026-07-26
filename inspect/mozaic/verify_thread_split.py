"""Verify how モザイク splits work across threads, and find the one input
range where the split is not a clean partition.

All four workers open with the same prologue (0x1006b186..0x1006b1e0 for the
object/タイル風-OFF variant; the other three are register-renamed copies):

    y_start = ((h *  tid      / tnum) + size - 1) / size * size
    y_end   = ((h * (tid + 1) / tnum) + size - 1) / size * size
    if (y_start == 0) y_start = -size          ; 0x1006b1d6  cmp ecx, ebx
                                               ; 0x1006b1dc  jne
                                               ; 0x1006b1de  mov ecx, esi / neg ecx
    for (y = y_start; y < y_end; y += size) ...

Two things are worth pinning down rather than assuming:

  * the `ceil to a multiple of size` on BOTH ends is what keeps a block row
    from being cut in half between two threads - without it two threads would
    each average a partial block and write conflicting values, and

  * the `if (y_start == 0) y_start = -size` special case exists because the
    grid is centred (see verify_grid.py), so the topmost block starts above
    y=0 and would otherwise never be visited. It keys off the *value* 0, not
    off tid==0 - which is exactly right for every h >= tnum, and is a race
    for h < tnum.

Run via main.py:
    uv run main.py inspect/mozaic/verify_thread_split.py
"""


def band(h: int, size: int, tid: int, tnum: int) -> tuple[int, int]:
    """The [y_start, y_end) block-row band worker `tid` walks, as the asm computes it."""
    def ceil_to_size(a):
        return int((a + size - 1) / size) * size

    y_start = ceil_to_size(int(h * tid / tnum))
    y_end = ceil_to_size(int(h * (tid + 1) / tnum))
    if y_start == 0:
        y_start = -size
    return y_start, y_end


def rows(h: int, size: int, tid: int, tnum: int) -> list[int]:
    y_start, y_end = band(h, size, tid, tnum)
    return list(range(y_start, y_end, size))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("1) for h >= tnum the bands are a clean partition of the block rows")
    bad = []
    for h in range(1, 1081):
        for size in (2, 3, 12, 64, 200):
            for tnum in (1, 2, 4, 8, 16, 32):
                if h < tnum:
                    continue
                seen = []
                for tid in range(tnum):
                    seen += rows(h, size, tid, tnum)
                expect = list(range(-size, h, size))
                if seen != expect:
                    bad.append((h, size, tnum, seen, expect))
    print(f"   h=1..1080 x size in (2,3,12,64,200) x tnum in (1,2,4,8,16,32)")
    print(f"   -> {'OK, every block row visited exactly once, in order' if not bad else f'{len(bad)} failures'}")
    for b in bad[:3]:
        print(f"      h={b[0]} size={b[1]} tnum={b[2]}: {b[3]} != {b[4]}")

    print("\n2) but for h < tnum, several threads compute y_start == 0 and are all")
    print("   rewritten to -size, so they redo the same top block row")
    print("   (the write is the block average, so the values agree; the reads and")
    print("    writes of the overlapping threads are still unsynchronised)")
    for h, size, tnum in [(2, 8, 4), (3, 4, 8), (1, 2, 4), (7, 2, 8)]:
        per = {tid: rows(h, size, tid, tnum) for tid in range(tnum)}
        dupes = {}
        for tid, rs in per.items():
            for r in rs:
                dupes.setdefault(r, []).append(tid)
        overlapped = {r: t for r, t in dupes.items() if len(t) > 1}
        print(f"   h={h} size={size} tnum={tnum}: bands={ {t: band(h, size, t, tnum) for t in range(tnum)} }")
        print(f"      rows done by >1 thread: {overlapped or 'none'}")

    print("\n3) smallest h that is safe for a given thread count is h >= tnum")
    for tnum in (2, 4, 8, 16, 32):
        first_ok = next(h for h in range(1, 200)
                        if all(len(t) == 1 for t in _dupe_map(h, 12, tnum).values()))
        print(f"   tnum={tnum:3d} -> first h with no duplicated row: {first_ok}")


def _dupe_map(h, size, tnum):
    d = {}
    for tid in range(tnum):
        for r in rows(h, size, tid, tnum):
            d.setdefault(r, []).append(tid)
    return d


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
