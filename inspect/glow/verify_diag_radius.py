"""0x101b2028, the radius the diagonal streaks use, is `min(rx, ry)` - the
sqrt that computes it is dead arithmetic.

func_proc builds it in three steps (0x10054dfe-0x10054ec9):

    rx = ry = 拡散
    diag = trunc(sqrt(rx*rx + ry*ry))     ; the only FP in the filter
    ... per-axis clamps against the maximum canvas may shrink rx and/or ry ...
    if (diag > rx) diag = rx
    if (diag > ry) diag = ry

Read as geometry that looks deliberate: "the diagonal of the rx-by-ry box,
capped so it cannot exceed either side". But rx and ry are *the same trackbar*,
so before the clamps `sqrt(2)*d >= d` always holds, and the clamps only ever
shrink diag further. The sqrt result therefore never survives; the two clamps
alone decide the value, and it is always `min(rx, ry)`.

That matters for reading the diagonal workers: they smear along a 45-degree
line but their radius is measured in *steps*, not in pixels, so a diagonal ray
physically reaches `sqrt(2) * min(rx,ry)` pixels - about 41% further than the
straight-line rays of ライン(縦)/(横) with the same 拡散.

Section 3 checks the clamps do not resurrect it. The maximum-canvas clamp is
per-axis (0x10054e43 shrinks rx only, 0x10054ea9 shrinks ry only), so this
brute-forces every (rx, ry) pair that the clamps can produce, not just the
diagonal rx == ry.

Run via main.py:
    uv run main.py inspect/glow/verify_diag_radius.py
"""

import math

from tools.disasm import dump_range
from tools.pe_image import PEImage

SQRT_BLOCK = (0x10054DF0, 0x40)
CLAMP_BLOCK = (0x10054EB3, 0x16)

ANNOTATIONS = {
    0x10054DF0: "ebx = 拡散",
    0x10054E01: "ecx = rx * rx",
    0x10054E0C: "eax = ry * ry",
    0x10054E0F: "eax = rx*rx + ry*ry",
    0x10054E15: "fild (signed 32-bit)",
    0x10054E19: "fsqrt",
    0x10054E1B: "_ftol -> truncate toward zero",
    0x10054E26: "0x101b2028 = trunc(sqrt(rx^2 + ry^2))",
    0x10054EB3: "diag > rx ?",
    0x10054EB7: "yes: diag = rx",
    0x10054EBF: "diag > ry ?",
    0x10054EC3: "yes: diag = ry.  after these two lines the sqrt is gone",
}

TRACK_MAX = 200          # 拡散's registered range is 0..200


def diag_raw(rx: int, ry: int) -> int:
    """trunc(sqrt(rx*rx + ry*ry)) - the value before the clamps."""
    return int(math.sqrt(rx * rx + ry * ry))


def diag_final(spread: int, rx: int, ry: int) -> int:
    """0x101b2028 as func_proc leaves it. `spread` is the raw 拡散, which is
    what the sqrt is computed from; rx/ry are the post-clamp radii."""
    d = diag_raw(spread, spread)
    if d > rx:
        d = rx
    if d > ry:
        d = ry
    return d


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_range(img, *SQRT_BLOCK, label="func_proc: the sqrt", annotations=ANNOTATIONS)
    dump_range(img, *CLAMP_BLOCK, label="func_proc: the two clamps", annotations=ANNOTATIONS)

    print("\n--- 1. before the clamps: sqrt(2)*d vs d, for every reachable 拡散 ---")
    bad = [d for d in range(1, TRACK_MAX + 1) if diag_raw(d, d) < d]
    ties = [d for d in range(1, TRACK_MAX + 1) if diag_raw(d, d) == d]
    print("  MISMATCH: " + str(bad[:8]) if bad else
          f"  OK: trunc(sqrt(2*d^2)) >= d for all d in 1..{TRACK_MAX}, so the first")
    print(f"  clamp always fires (equality only at 拡散 = {ties}) and the sqrt is")
    print("  already discarded before the second one runs.")
    print(f"  {'拡散':>6}{'sqrt result':>13}{'min(rx,ry)':>12}")
    for d in (1, 2, 3, 10, 30, 200):
        print(f"  {d:>6}{diag_raw(d, d):>13}{d:>12}")

    print("\n--- 2. after the clamps: identical to min(rx, ry), all (rx, ry) pairs ---")
    mismatches = 0
    checked = 0
    for spread in range(1, TRACK_MAX + 1):
        # the maximum-canvas clamp can only shrink, and only down to 0
        for rx in range(0, spread + 1):
            for ry in (0, spread // 2, spread):
                checked += 1
                if diag_final(spread, rx, ry) != min(rx, ry):
                    mismatches += 1
    print(f"  {'MISMATCH on %d of' % mismatches if mismatches else 'OK: identical for all'}"
          f" {checked} (拡散, rx, ry) combinations.")

    print("\n--- 3. what it costs: reach of a diagonal ray vs a straight one ---")
    print("  the diagonal workers step by (+-1, +1) per sample, so `diag` samples")
    print("  cover diag pixels horizontally AND diag pixels vertically:")
    print(f"  {'拡散':>6}{'straight reach':>16}{'diagonal reach':>16}")
    for d in (10, 30, 60, 200):
        print(f"  {d:>6}{d:>16}{d * math.sqrt(2):>16.1f}")
    print("  クロス(8本) therefore does not draw an 8-pointed star with equal arms:")
    print("  the four diagonal arms are ~41% longer than the four straight ones.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
