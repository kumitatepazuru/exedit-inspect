"""The blur half of シャープ: four passes, which globals feed them, what the
divisors are, and where the chain breaks.

シャープ subtracts a blur from the original, so the blur is half the effect.
It is the ordinary separable alpha-weighted box average (box_blur.md), used in
its "renormalise at the edge" variant - the same one `ぼかし` uses when
`サイズ固定` is ON. Four claims:

(1) `範囲` splits into `r_hi = 範囲 - 範囲/2` and `r_lo = 範囲/2`, and the four
    passes V(r_hi), H(r_hi), V(r_lo), H(r_lo) convolve into a kernel whose
    support is exactly +-範囲 per axis - a triangle when 範囲 is even, a
    trapezoid with a flat top of 3 when it is odd. Identical to `ぼかし` and
    `シャドー`.

(2) Each worker reads only its own axis' pair of globals: the vertical one
    0x102320bc/0x102320c4, the horizontal one 0x102320c0/0x102320c8. That is
    what pins which is which, since both are handed the same `(fp, fpip)`.

(3) The alpha divisor is the number of samples still inside the image
    (`r+i+1` while the window grows, `2r+1` in the middle, `2r-i` while it
    shrinks), never the full kernel width. So the blur does **not** fade out
    at the object's border, and no canvas growth is needed - and indeed
    func_proc never touches `fpip+0xEC`/`+0xF0` or compares any radius against
    `w`/`h`.

(4) Which is also the bug: with no clamp at all, an object shorter than the
    kernel makes the middle phase count negative, the pass writes `2r+1` rows
    (columns) regardless, and the leading pointer reads past the end. This is
    box_blur.md §4's first bullet, inherited whole - `ぼかし` at least
    reaches that state only with `サイズ固定` ON, whereas シャープ has no such
    checkbox.

(5) "Inherited" is meant literally. Both workers are the *same code* as
    `ぼかし`'s `サイズ固定` ON pair (`0x1000f310` / `0x1000f7e0`): the same
    instruction count, and every single difference is either a branch with an
    identical relative displacement or one of four global addresses swapped
    from `ぼかし`'s block to シャープ's. Nothing else differs. Every property
    in (3) and (4) is a property of that shared code rather than a decision
    taken for シャープ.

Run via main.py:
    uv run main.py inspect/sharp/verify_blur_chain.py
"""

import re

from tools.cints import c_div
from tools.disasm import disasm_range, function_body, make_md
from tools.pe_image import PEImage

FUNC_PROC = (0x10089030, 0x186)
VERTICAL = 0x100891C0
HORIZONTAL = 0x10089690
COMBINE = 0x10089B60
# ぼかし's サイズ固定 ON pair, and the global renaming that turns one into the
# other. Sizes are the full function bodies, which happen to match exactly.
BLUR_TWINS = (("vertical", 0x1000F310, VERTICAL, 0x4D0),
              ("horizontal", 0x1000F7E0, HORIZONTAL, 0x4C6))
GLOBAL_MAP = {0x1011EC34: 0x102320BC, 0x1011EC38: 0x102320C0,
              0x1011EC3C: 0x102320C4, 0x1011EC40: 0x102320C8}
GLOBALS = {
    0x102320BC: "radius, vertical",
    0x102320C0: "radius, horizontal",
    0x102320C4: "kernel width, vertical",
    0x102320C8: "kernel width, horizontal",
}


# ------------------------------------------------------------------ (1)

def split(r):
    """func_proc 0x10089055-0x10089092: r -> (hi, lo)."""
    lo = c_div(r, 2)
    return r - lo, lo


def box(radius):
    return [1] * (2 * radius + 1)


def convolve(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] += x * y
    return out


# ------------------------------------------------------------------ (3)

class Acc:
    """The four running sums the box workers keep in registers/stack slots."""

    def __init__(self):
        self.y = self.cb = self.cr = self.a = 0

    def add(self, px, sign=1):
        y, cb, cr, a = px
        if a == 0:                       # test eax,eax / je - skipped entirely
            return
        if a < 0x1000:                   # cmp eax,0x1000 / jge
            self.y += sign * ((y * a) >> 12)
            self.cb += sign * ((cb * a) >> 12)
            self.cr += sign * ((cr * a) >> 12)
        else:
            self.y += sign * y
            self.cb += sign * cb
            self.cr += sign * cr
        self.a += sign * a

    def emit(self, divisor, prev=None):
        if self.a != 0:
            y = int(self.y * 4096.0 / self.a)      # fild / fmul 4096.0 / fdiv / _ftol
            cb = int(self.cb * 4096.0 / self.a)
            cr = int(self.cr * 4096.0 / self.a)
        else:
            y, cb, cr = prev if prev else (0, 0, 0)   # colour left untouched
        return (y, cb, cr, c_div(self.a, divisor))


def box_pass(src, radius):
    """One pass of 0x100891c0 / 0x10089690, transcribed.

    Returns (rows, overrun): `rows` is every emitted pixel in order, `overrun`
    is how many of them landed past the end of the line.
    """
    n, kernel = len(src), 2 * radius + 1
    acc, out, lead, trail = Acc(), [], 0, 0

    def read(i):
        return src[i] if 0 <= i < n else (0, 0, 0, 0)   # past the end: unknown, modelled as 0

    for _ in range(radius):                                  # phase 1: prefill, no output
        acc.add(read(lead)); lead += 1
    for i in range(kernel - radius):                         # phase 2: window grows
        acc.add(read(lead)); lead += 1
        out.append(acc.emit(radius + i + 1))
    for _ in range(max(0, n - kernel)):                      # phase 3: steady state
        acc.add(read(lead)); lead += 1
        acc.add(read(trail), sign=-1); trail += 1
        out.append(acc.emit(kernel))
    for i in range(radius):                                  # phase 4: window shrinks
        acc.add(read(trail), sign=-1); trail += 1
        out.append(acc.emit(kernel - i - 1))
    return out, max(0, len(out) - n)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("--- (1) 範囲 -> two radii -> one triangular kernel ---")
    bad = 0
    for r in range(0, 101):
        hi, lo = split(r)
        k = convolve(box(hi), box(lo))
        if hi + lo != r or (len(k) - 1) // 2 != r:
            bad += 1
    print(f"  範囲 = 0..100: hi + lo == 範囲 and support == 範囲 for all "
          f"({bad} mismatch(es))")
    for r in (1, 2, 3, 4, 6):
        hi, lo = split(r)
        k = convolve(box(hi), box(lo))
        shape = "triangle" if r % 2 == 0 else "trapezoid (flat top of 3)"
        print(f"    範囲={r}: box({2 * hi + 1}) * box({2 * lo + 1}) = {k}   {shape}")
    print("  範囲=1 is the degenerate case: r_lo = 0, so passes 3 and 4 are skipped")
    print("  and the 'triangle' is a single box of 3 (func_proc 0x10089122).")

    print("\n--- (2) which worker owns which global ---")
    for addr, label in ((VERTICAL, "0x100891c0"), (HORIZONTAL, "0x10089690"),
                        (COMBINE, "0x10089b60")):
        body = function_body(img, addr, limit=0x520)
        seen = {}
        for insn in body:
            for g, desc in GLOBALS.items():
                if f"0x{g:08x}" in insn.op_str:
                    seen[g] = seen.get(g, 0) + 1
        pretty = ", ".join(f"0x{g:08x} x{n} ({GLOBALS[g]})" for g, n in sorted(seen.items()))
        print(f"  {label}: {pretty or 'no shared globals at all'}")
    print("  -> disjoint. The split is by axis, not by pass number; func_proc writes")
    print("     the same radius into both halves each round (0x10089096/0x1008909b).")

    print("\n--- (3) the divisor at every idiv in the two box workers ---")
    for addr, label in ((VERTICAL, "vertical 0x100891c0"),
                        (HORIZONTAL, "horizontal 0x10089690")):
        print(f"\n  {label}")
        body = function_body(img, addr, limit=0x520)
        for i, insn in enumerate(body):
            if insn.mnemonic != "idiv":
                continue
            ctx = " ; ".join(f"{b.mnemonic} {b.op_str}" for b in body[max(0, i - 4):i])
            print(f"    0x{insn.address:08x}: idiv {insn.op_str:6s} <- {ctx}")
    print("""
  The first two idivs in each worker are the thread range (length*tid/n). The
  other three are the alpha divisor, one per phase:

      phase 2 (growing) : lea ecx,[radius + i + 1]      = samples seen so far
      phase 3 (steady)  : the kernel-width global       = 2*radius + 1
      phase 4 (shrinking): kernel width - i - 1          = samples still inside

  i.e. the "live sample count" variant of box_blur.md §3 - the border keeps
  its opacity, and nothing is treated as transparent outside the image.""")

    print("\n--- (3b) a worked column, 範囲 = 2 (passes V(1), H(1), V(1), H(1)) ---")
    col = [(4096, 0, 0, 4096)] * 3 + [(0, 0, 0, 4096)] * 3 + [(4096, 0, 0, 4096)] * 3
    print(f"  input  y: {[p[0] for p in col]}")
    cur = col
    for step in range(2):
        cur, _ = box_pass(cur, 1)
        print(f"  V({1}) #{step + 1} y: {[p[0] for p in cur]}")
    print("  (a step edge becomes a ramp; the combine worker then subtracts it)")

    print("\n--- (4) no clamp anywhere ---")
    lo, hi = FUNC_PROC
    touches = [f"0x{i.address:08x}: {i.mnemonic} {i.op_str}"
               for i, _ in disasm_range(img, lo, hi, resolve=False)
               if "0xec]" in i.op_str or "0xf0]" in i.op_str]
    print(f"  func_proc references to fpip+0xEC / +0xF0 (the allocated extents): "
          f"{touches or 'none'}")
    print("  func_proc reads fpip->w/h only to hand them to table[0x44]; neither is")
    print("  ever compared against a radius. So the kernel can exceed the object.")
    print()
    print("    範囲  kernel  smallest safe w/h   rows written for a 16px object")
    for rng in (1, 2, 5, 8, 10, 25, 50, 100):
        hi_r, _lo_r = split(rng)
        kw = 2 * hi_r + 1
        out, over = box_pass([(4096, 0, 0, 4096)] * 16, hi_r)
        print(f"    {rng:4d} {kw:7d} {kw:16d}   {len(out):3d}"
              + (f"   <- {over} past the end" if over else ""))
    print("""
  The first pass of each axis is the dangerous one: it uses r_hi, the larger
  radius. `ぼかし` avoids this by pre-growing the canvas (サイズ固定 off) or by
  being a user choice (サイズ固定 on); シャープ has neither escape hatch, and
  the object's own size is never consulted. The write lands in the pair buffer,
  which is allocated at the maximum canvas size, so nothing crashes - but the
  reads past the end are real, and the divisors for the last rows assume
  samples that were never there.""")

    print("\n--- (5) the two workers ARE ぼかし's サイズ固定 ON workers ---")
    md = make_md()
    for tag, blur_addr, sharp_addr, size in BLUR_TWINS:
        ia = list(md.disasm(img.code(blur_addr, size), blur_addr))
        ib = list(md.disasm(img.code(sharp_addr, size), sharp_addr))
        same = branch = swap = 0
        other = []
        for x, y in zip(ia, ib):
            if x.mnemonic == y.mnemonic and x.op_str == y.op_str:
                same += 1
                continue
            if x.mnemonic != y.mnemonic:
                other.append((x, y))
                continue
            if x.op_str.startswith("0x") and y.op_str.startswith("0x"):
                # a relative branch: identical displacement means identical code
                if (int(x.op_str, 16) - (x.address + x.size)
                        == int(y.op_str, 16) - (y.address + y.size)):
                    branch += 1
                    continue
            mx = re.search(r"\[(0x[0-9a-f]+)\]", x.op_str)
            my = re.search(r"\[(0x[0-9a-f]+)\]", y.op_str)
            if (mx and my
                    and GLOBAL_MAP.get(int(mx.group(1), 16)) == int(my.group(1), 16)
                    and x.op_str.replace(mx.group(1), "") == y.op_str.replace(my.group(1), "")):
                swap += 1
                continue
            other.append((x, y))
        print(f"  {tag:<10s} 0x{blur_addr:08x} vs 0x{sharp_addr:08x}: "
              f"{len(ia)} vs {len(ib)} instructions over 0x{size:x} bytes")
        print(f"             identical {same}, same relative branch {branch}, "
              f"global swapped {swap}, anything else {len(other)}")
        for x, y in other:
            print(f"      0x{x.address:08x}: {x.mnemonic} {x.op_str}")
            print(f"      0x{y.address:08x}: {y.mnemonic} {y.op_str}")
    print("""
  Zero unexplained differences in either pair. シャープ's blur is not "like"
  ぼかし's - it is the same function recompiled against a different pair of
  globals. That accounts for everything above at once: the live-sample-count
  divisor of (3), the absent clamp of (4), and (see verify_thread_split.py) the
  thread guard that never got ぼかし's `thread_num = 1` rescue - because the
  サイズ固定 workers do not have it either.""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
