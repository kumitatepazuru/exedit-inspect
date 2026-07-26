"""Verify the averaging math, and the one place where the object-effect and
frame-filter versions genuinely differ: alpha weighting.

Frame filter (0x1006b470 / 0x1006ba40, 6-byte PIXEL_YC, no alpha) does the
obvious thing - three running sums and one integer divide each:

    0x1006b5ba  movsx eax, word [ecx]      ; y
    ...                                    ; cb, cr
    0x1006b613  idiv  ecx                  ; sum / count, per channel

Object effect (0x1006b180 / 0x1006b6b0, 8-byte PIXEL_YCA) instead builds a
premultiplied sum and divides by the summed alpha:

    0x1006b2e4  movsx ecx, word [eax + 6]  ; a
    0x1006b2ea  je    skip                 ; a == 0 -> contributes nothing
    0x1006b2f0  cmp   ecx, 0x1000
    0x1006b2f9  jge   unweighted           ; a >= 4096 -> use the raw value
    0x1006b2fb  imul  edx, ecx             ; else  (v * a) >> 12
    0x1006b2fe  sar   edx, 0xc
    ...
    0x1006b389  fild  [esp+0x10]           ; st0 = sum_a
    0x1006b38d  fild  [esp+0x38]           ; st0 = sum_y
    0x1006b391  fmul  qword [0x1009a3a0]   ; * 4096.0
    0x1006b397  fdiv  st(1)                ; / sum_a
    0x1006b399  call  0x10091ad8           ; _ftol - truncate toward zero
    ...
    0x1006b3d3  idiv  [esp+0x18]           ; alpha: sum_a / count (integer)

Three things this script pins down:

  * the colour divisor is sum_a, but the alpha divisor is the pixel COUNT,
    and the count includes fully transparent pixels. That asymmetry is what
    makes the block fade out at an object's edge instead of smearing the
    edge colour outward at full opacity.
  * the colour divide goes through x87 doubles, not integers. This script
    checks against exact rational arithmetic whether the double rounding can
    ever change the truncated result.
  * `sar` is a floor, `idiv`/_ftol truncate toward zero. Chroma is signed, so
    the two disagree, and both appear in the same expression.

Run via main.py:
    uv run main.py inspect/mozaic/verify_alpha_average.py
"""

import random
from fractions import Fraction

MUL4096 = 4096.0


def premul(v: int, a: int) -> int:
    """The exact 0x1006b2f0..0x1006b319 sequence: a>=4096 passes v through."""
    if a >= 0x1000:
        return v
    return (v * a) >> 12                    # sar -> arithmetic shift, floors


def ftol(x: float) -> int:
    """0x10091ad8: fldcw with RC=11 (truncate toward zero), then fistp."""
    return int(x)                           # Python int() also truncates toward zero


def average_object(block: list[tuple[int, int, int, int]]) -> tuple[int, int, int, int]:
    """0x1006b2d0..0x1006b3d7 - block is a flat list of (y, cb, cr, a)."""
    sum_y = sum_cb = sum_cr = sum_a = 0
    count = len(block)                      # incremented per ROW by bw, alpha-blind
    for y, cb, cr, a in block:
        if a == 0:
            continue
        sum_y += premul(y, a)
        sum_cb += premul(cb, a)
        sum_cr += premul(cr, a)
        sum_a += a
    if count == 0:
        return None
    if sum_a == 0:
        avg_y = avg_cb = avg_cr = 0
    else:
        avg_y = ftol(sum_y * MUL4096 / sum_a)
        avg_cb = ftol(sum_cb * MUL4096 / sum_a)
        avg_cr = ftol(sum_cr * MUL4096 / sum_a)
    avg_a = int(sum_a / count)              # idiv: truncates toward zero
    return avg_y, avg_cb, avg_cr, avg_a


def average_frame(block: list[tuple[int, int, int]]) -> tuple[int, int, int]:
    """0x1006b5ba..0x1006b62b - plain integer mean, truncating toward zero."""
    count = len(block)
    if count == 0:
        return None
    sy = sum(p[0] for p in block)
    scb = sum(p[1] for p in block)
    scr = sum(p[2] for p in block)
    return int(sy / count), int(scb / count), int(scr / count)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    rnd = random.Random(20260726)

    print("1) does the x87 double divide ever disagree with exact rational truncation?")
    bad = 0
    trials = 400000
    for _ in range(trials):
        # sums stay well inside int32: at most 2000*2000 pixels * 4096
        s = rnd.randint(-(1 << 30), 1 << 30)
        sa = rnd.randint(1, 1 << 31 - 1)
        got = ftol(s * MUL4096 / sa)
        want = int(Fraction(s * 4096, sa))   # Fraction -> int truncates toward zero
        if got != want:
            bad += 1
            if bad <= 3:
                print(f"   MISMATCH sum={s} sum_a={sa}: double={got} exact={want}")
    print(f"   {trials} random (sum, sum_a) pairs -> "
          f"{'OK, identical' if bad == 0 else f'{bad} mismatches'}")
    print("   (sum*4096 needs 43 bits and sums are int32, so the product is exact in")
    print("    a double; only the divide rounds, and it rounds to nearest, so it can")
    print("    only cross an integer when the exact value is already within 1 ulp)")

    print("\n2) transparent pixels dilute alpha but not colour")
    solid = (4096, 500, -300, 4096)
    clear = (0, 0, 0, 0)
    for n_clear in (0, 1, 2, 3):
        blk = [solid] * (4 - n_clear) + [clear] * n_clear
        y, cb, cr, a = average_object(blk)
        print(f"   {4 - n_clear} opaque + {n_clear} transparent -> "
              f"y={y} cb={cb} cr={cr} a={a}   (colour held, alpha = {4 - n_clear}/4)")

    print("\n3) colour is the alpha-weighted mean, not the plain mean")
    blk = [(4096, 0, 0, 4096), (0, 0, 0, 512)]      # bright+opaque, black+faint
    y, cb, cr, a = average_object(blk)
    plain = average_frame([(p[0], p[1], p[2]) for p in blk])
    print(f"   block = {blk}")
    print(f"   object effect : y={y}  a={a}      (= 4096*4096/(4096+512))")
    print(f"   frame filter  : y={plain[0]}          (= (4096+0)/2, alpha ignored)")

    print("\n4) an all-transparent block collapses to all zeros, not to a divide by 0")
    print(f"   {average_object([clear] * 9)}   (sum_a == 0 -> 0x1006b387 skips the fild block)")

    print("\n5) sar floors, idiv/_ftol truncate toward zero - both are live on chroma")
    for cb, a in [(-2048, 2048), (-1, 2048), (-3, 4095), (1, 1)]:
        print(f"   premul(cb={cb:6d}, a={a:4d}) = (cb*a)>>12 = {premul(cb, a):5d}   "
              f"(floor of {cb * a / 4096:+.4f})")
    for s, n in [(-7, 2), (7, 2), (-1, 4)]:
        print(f"   idiv({s:3d}, {n}) = {int(s / n):3d}   (Python // would give {s // n})")

    print("\n6) a >= 4096 is not just an optimisation")
    print("   PIXEL_YC values may leave their nominal range (filter.h says so), and")
    print("   at a > 4096 the two paths differ: the colour uses a=4096 while sum_a")
    print("   still accumulates the raw a, so the block darkens.")
    for a in (4096, 5000, 8192):
        y, cb, cr, av = average_object([(4096, 0, 0, a)])
        print(f"   single pixel y=4096 a={a:5d} -> y={y:5d} a={av:5d}")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
