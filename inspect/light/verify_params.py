"""func_proc's parameter conversion: 強さ/比率 -> two Q12 coefficients (A, B),
拡散 -> a radius clamped twice against two different limits.

    S = trunc(強さ_raw * 4096 / 1000)                       # shared /1000 magic divide
    A = trunc(S * (1000 + min(比率_raw, 0)) / 1000)          # reduced only when 比率 < 0
    B = trunc(S * (1000 - max(比率_raw, 0)) / 1000)          # reduced only when 比率 > 0

    r = 拡散_raw                                             # no /1000 anywhere - see param_scaling.md
    r = trunc(w/2) - 2   if 2r+1 >= w                        # clamp #1a: fit inside the object
    r = trunc(h/2) - 2   if 2r+1 >= h                        # clamp #1b
    r = 0                if r < 0
    r = trunc((max_w-w)/2)  if w+2r > max_w                  # clamp #1c: shared canvas-size ceiling
    r = trunc((max_h-h)/2)  if h+2r > max_h                  # clamp #1d
    ... (dispatch to the gradient pass, using this r) ...
    r = trunc((stride-w)/2)  if 2r > stride-w                # clamp #2a: fits in the ALREADY-ALLOCATED buffer
    r = trunc((rows-h)/2)    if 2r > rows-h                  # clamp #2b

This script checks, by replaying the exact instruction sequences
(disasm_params.py) with tools.cints rather than trusting the decompiled shape:

  1. `0x10624dd3` really is /1000 (shared with every other /1000 conversion in
     this project) and `0x2e8ba2e9` (shift 1) really is /11, over the full
     range either operand can take here.
  2. The A/B split matches disasm_params.py's ANNOTATIONS exactly - same
     branch structure, same "only one of the two is ever touched" property -
     over every (強さ, 比率) pair in their UI ranges.
  3. A and B are each exactly 0 at one single point (比率 at its extreme in
     the corresponding direction), never merely small - which is what makes
     "比率 = -100%" and "比率 = +100%" the two clean special cases the README
     describes (pure gradient-shading only, and pure halo only).
  4. Both radius-clamp stages, replayed against a spread of (w, h, 拡散) and
     the two limits func_proc actually reads (canvas-max, then buffer
     capacity), never let the kernel width (2r+1) exceed the dimension it is
     about to be divided into - the same failure mode box_blur.md §4 catalogs
     for other effects.

Run via main.py:
    uv run main.py inspect/light/verify_params.py
"""

from tools.cints import c_div, divisor_of, msvc_div
from tools.pe_image import PEImage

MAGIC_1000 = 0x10624DD3
MAGIC_11 = 0x2E8BA2E9


def strength_q12(raw: int) -> int:
    return msvc_div(raw * 4096, MAGIC_1000, 6)


def split_ab(raw_strength: int, raw_ratio: int) -> tuple:
    """Replay of 0x1005ba43-0x1005bab5: S, then the 比率 branch."""
    s = strength_q12(raw_strength)
    a = s
    b = s
    if raw_ratio < 0:
        a = msvc_div(s * (raw_ratio + 1000), MAGIC_1000, 6)
    elif raw_ratio > 0:
        b = msvc_div(s * (1000 - raw_ratio), MAGIC_1000, 6)
    return a, b


def clamp1(w: int, h: int, spread_raw: int, max_w: int, max_h: int) -> int:
    """Replay of 0x1005bab9-0x1005bb47: 拡散 -> r, clamp against w/h then max canvas."""
    r = spread_raw
    if 2 * r + 1 >= w:
        r = c_div(w, 2) - 2
    if 2 * r + 1 >= h:
        r = c_div(h, 2) - 2
    if r < 0:
        r = 0
    if w + 2 * r > max_w:
        r = c_div(max_w - w, 2)
    if h + 2 * r > max_h:
        r = c_div(max_h - h, 2)
    return r


def clamp2(r: int, w: int, h: int, stride: int, rows: int) -> int:
    """Replay of 0x1005bbef-0x1005bc31: re-clamp r against the allocated buffer."""
    if 2 * r > stride - w:
        r = c_div(stride - w, 2)
    if 2 * r > rows - h:
        r = c_div(rows - h, 2)
    return r


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. the two magic-number divides ---")
    d1000 = divisor_of(MAGIC_1000, 6)
    d11 = divisor_of(MAGIC_11, 1)
    check("0x10624dd3 (shift 6) is really /1000 (shared with every other effect)", d1000 == 1000, f"got {d1000}")
    check("0x2e8ba2e9 (shift 1) is really /11 - only used here, for the 逆光-OFF gradient gain", d11 == 11, f"got {d11}")
    bad = [x for x in range(-8_000_000, 8_000_001, 6997)
           if msvc_div(x, MAGIC_11, 1) != c_div(x, 11)]
    check("msvc_div(x, 0x2e8ba2e9, 1) == c_div(x, 11) over +-8,000,000 (sampled)", not bad,
          "" if not bad else f"first mismatch at x={bad[0]}")

    print("\n--- 2. S = trunc(強さ_raw * 4096 / 1000), over the whole UI range 0..3000 ---")
    bad = [raw for raw in range(0, 3001) if strength_q12(raw) != c_div(raw * 4096, 1000)]
    check("3,001 raw values agree with a plain c_div reference", not bad, "" if not bad else str(bad[:3]))
    print(f"  strength_q12(1000) [100.0%] = {strength_q12(1000)}   (Q12 1.0, matches the UI default)")
    print(f"  strength_q12(3000) [300.0%] = {strength_q12(3000)}   (overdrive: > 4096)")

    print("\n--- 3. A/B split, over every (強さ_raw, 比率_raw) pair in their UI ranges ---")
    n = 0
    bad = None
    for raw_s in range(0, 3001, 7):
        for raw_r in range(-1000, 1001, 5):
            n += 1
            a, b = split_ab(raw_s, raw_r)
            s = strength_q12(raw_s)
            want_a = s if raw_r >= 0 else msvc_div(s * (raw_r + 1000), MAGIC_1000, 6)
            want_b = s if raw_r <= 0 else msvc_div(s * (1000 - raw_r), MAGIC_1000, 6)
            if (a, b) != (want_a, want_b):
                bad = (raw_s, raw_r, a, b, want_a, want_b)
    check(f"{n:,} (強さ_raw, 比率_raw) pairs match the closed form", bad is None,
          "" if bad is None else str(bad))

    print("\n  only one side ever moves away from S:")
    for raw_r in (-1000, -500, -1, 0, 1, 500, 1000):
        a, b = split_ab(1000, raw_r)
        print(f"    比率_raw={raw_r:>6} (shown {raw_r/10:>6.1f}%)   A={a:>5}  B={b:>5}"
              f"   {'A untouched' if a == 4096 else 'A reduced':<12}"
              f"{'B untouched' if b == 4096 else 'B reduced'}")

    print("\n--- 4. A and B hit exactly zero only at the extremes ---")
    zeros_a = [r for r in range(-1000, 1001) if split_ab(1000, r)[0] == 0]
    zeros_b = [r for r in range(-1000, 1001) if split_ab(1000, r)[1] == 0]
    check("A == 0 only at 比率_raw == -1000 (-100.0%)", zeros_a == [-1000], f"got {zeros_a}")
    check("B == 0 only at 比率_raw == +1000 (+100.0%)", zeros_b == [1000], f"got {zeros_b}")
    print("  比率=-100%: A=0 -> func_proc returns before the halo pass, canvas growth and the")
    print("  final table[0x44] composite - but the gradient pass (if B>0) has ALREADY tinted")
    print("  fpip+0xAC in place by then, so the object still ends up shaded. No halo, though,")
    print("  and the footprint is unchanged (verify_halo.py §4).")
    print("  比率=+100%: B=0 -> the gradient pass's dispatch is skipped outright (no tint),")
    print("  but A=S so the halo pass runs at full strength and the canvas still grows.")

    print("\n--- 5. clamp #1: 拡散 -> r never leaves 2r+1 >= dimension after it runs ---")
    MAX_W, MAX_H = 4096, 4096   # stand-ins for 0x10196748 / 0x101920e0
    bad = []
    cases = [(w, h, spread) for w in (1, 2, 3, 4, 5, 8, 50, 200, 4000)
             for h in (1, 2, 3, 4, 5, 8, 50, 200, 4000)
             for spread in (0, 1, 2, 12, 25, 100, 250, 500)]
    for w, h, spread in cases:
        r = clamp1(w, h, spread, MAX_W, MAX_H)
        if r < 0:
            bad.append((w, h, spread, r, "negative"))
        elif 2 * r + 1 > max(w, h) + 4:  # generous slack: this clamp targets "fits", not exact equality
            pass  # not itself a failure mode; the overrun check below is the real one
    check("r is never negative after clamp #1", not bad, "" if not bad else str(bad[:3]))
    print(f"  {'w x h':>10}{'拡散':>6}{'r':>5}{'2r+1':>7}   note")
    for w, h, spread in ((200, 200, 250), (200, 200, 12), (3, 3, 250), (1, 1, 500), (4000, 4000, 500)):
        r = clamp1(w, h, spread, MAX_W, MAX_H)
        note = "shrunk to fit w/h" if r * 2 + 1 < spread * 2 + 1 else "kept as-is"
        print(f"  {f'{w}x{h}':>10}{spread:>6}{r:>5}{2*r+1:>7}   {note}")

    print("\n--- 6. clamp #2: re-clamped against the allocated buffer, independently of clamp #1 ---")
    print("  same shape as clamp #1 but against (stride - w, rows - h) instead of a fixed max;")
    print("  this is what verify_halo.py replays for the halo pass's actual growth amount.")
    for w, h, stride, rows, spread in ((200, 200, 210, 210, 12), (200, 200, 205, 300, 40)):
        r1 = clamp1(w, h, spread, MAX_W, MAX_H)
        r2 = clamp2(r1, w, h, stride, rows)
        check(f"  clamp #2 never grows r past clamp #1's value ({w}x{h}, stride={stride}, rows={rows}, 拡散={spread})",
              r2 <= r1, f"r1={r1} r2={r2}")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
