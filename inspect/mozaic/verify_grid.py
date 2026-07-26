"""Verify how モザイク places its block grid over the image.

func_proc (0x1006b090) computes, once per frame, two globals that every
worker then reads:

    0x1006b0b0  lea  esi, [eax + eax]      ; esi = size*2
    0x1006b0b9  mov  eax, [edi + 0xb4]     ; w   (object mode)
    0x1006b0bf  cdq
    0x1006b0c0  idiv esi                   ; edx = w % (size*2)
    0x1006b0c2  mov  eax, edx
    0x1006b0c4  cdq
    0x1006b0c5  sub  eax, edx
    0x1006b0c7  sar  eax, 1                ; eax = (w % (size*2)) / 2
    0x1006b0c9  mov  [0x101bad28], eax     ; offset_x
    ... same for h -> [0x101bad2c] = offset_y

and every worker walks

    for (y = -size; y < h; y += size)          # (thread-split, see verify_thread_split.py)
        for (x = -size; x < w; x += size)
            block = [offset_x + x, offset_x + x + size) x [offset_y + y, ...)
            clipped to [0,w) x [0,h); skipped when the clipped extent is empty

Read literally, `(w % (2*size)) / 2` looks like an arbitrary fudge factor.
This script shows it is not: it is exactly `(w / 2) % size`, which is the
offset that puts a cell boundary on the image centre. That single fact
explains every visible artefact of the grid - why the two edge columns are
partial and equally wide, and why a サイズ larger than half the image gives
2x2 quadrants instead of one flat block.

Run via main.py:
    uv run main.py inspect/mozaic/verify_grid.py
"""


def offset_asm(dim: int, size: int) -> int:
    """(dim % (size*2)) / 2, with C signed semantics (truncating division)."""
    rem = int(dim / (size * 2)) * (size * 2)
    rem = dim - rem
    return int(rem / 2)


def offset_simple(dim: int, size: int) -> int:
    """The claim: the same value as `(dim / 2) % size`."""
    return (dim // 2) % size


def blocks(dim: int, size: int) -> list[tuple[int, int]]:
    """Clipped 1-D block extents [start, end) in the order the workers emit them."""
    off = offset_asm(dim, size)
    out = []
    x = -size
    while x < dim:
        start = off + x
        length = min(dim - start, size)
        if start < 0:
            length += start
            start = 0
        if length > 0:
            out.append((start, start + length))
        x += size
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("1) offset identity:  (dim % (2*size)) / 2  ==  (dim / 2) % size")
    bad = 0
    for dim in range(0, 4097):
        for size in range(2, 65):
            if offset_asm(dim, size) != offset_simple(dim, size):
                bad += 1
                if bad < 5:
                    print(f"   MISMATCH dim={dim} size={size}: "
                          f"{offset_asm(dim, size)} != {offset_simple(dim, size)}")
    print(f"   dim=0..4096 x size=2..64  ->  {'OK, identical' if bad == 0 else f'{bad} mismatches'}")

    print("\n2) the grid tiles the image exactly (no gap, no overlap),")
    print("   and a cell boundary always lands on dim/2")
    bad = 0
    for dim in range(1, 2049):
        for size in range(2, 130):
            bs = blocks(dim, size)
            covered = 0
            prev_end = 0
            for start, end in bs:
                if start != prev_end:
                    bad += 1
                    break
                covered += end - start
                prev_end = end
            else:
                if covered != dim:
                    bad += 1
                    continue
                # dim//2 must be a block boundary (i.e. a start, or the very end)
                bounds = {b[0] for b in bs} | {bs[-1][1]}
                if dim // 2 not in bounds:
                    bad += 1
                    print(f"   centre {dim // 2} not a boundary for dim={dim} size={size}: {bs}")
    print(f"   dim=1..2048 x size=2..129  ->  {'OK' if bad == 0 else f'{bad} failures'}")

    print("\n3) the edge cells are the leftover, split evenly on both sides")
    for dim, size in [(100, 12), (100, 10), (101, 6), (36, 12), (1920, 16), (1920, 100)]:
        bs = blocks(dim, size)
        widths = [e - s for s, e in bs]
        print(f"   dim={dim:5d} size={size:4d} offset={offset_asm(dim, size):3d} "
              f"cells={len(bs):3d} widths={widths if len(widths) <= 10 else widths[:3] + ['...'] + widths[-3:]}")

    print("\n4) consequence: size > dim/2 never yields one flat block - the centre")
    print("   boundary always splits the image in two")
    for dim, size in [(100, 51), (100, 60), (100, 100), (100, 2000), (1920, 2000)]:
        bs = blocks(dim, size)
        print(f"   dim={dim:5d} size={size:4d} -> {len(bs)} cells {bs}")

    print("\n5) サイズ=1 is a no-op: func_proc returns before touching the image")
    print("   0x1006b099  cmp eax, 2 / 0x1006b0a1  jl -> 'mov eax,1; ret'")
    print("   (track range is [1,2000], so 1 is reachable from the UI)")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
