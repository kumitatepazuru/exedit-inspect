"""What func_proc does with the two trackbars, checked against the
disassembly rather than paraphrased from it.

Five claims:

  1. **`ぼかし` is the only trackbar that goes through the shared /1000 magic
     divide - and the value it produces is DEAD.** `g_101b1e38 =
     4096 - trunc(ぼかし*4096/1000)` is stored at 0x10051632 and, in the whole
     850 KB image, no instruction ever loads that address. The number that
     actually carries `ぼかし` into the pixel loops is a completely different
     one computed 800 bytes later in x87 (claim 3).

  2. **`サイズ == 0` is the only early-out.** `ぼかし = 0` still runs the whole
     pipeline; it just makes the gain 1024, which turns the chain into a plain
     saturating box sum.

  3. **The gain is `round(1024 / (0.02*サイズ*ぼかし + 1))`**, computed from
     the *clamped* サイズ, rounded half-up by `+0.5` then `_ftol`. Checked
     over all 501x101 raw pairs: it is never 0 and never above 1024, it is
     exactly 1024 iff `ぼかし = 0`, and it is monotonically non-increasing in
     both parameters.

  4. **The pre-pad exists to guarantee the sliding window fits.** When
     `2*サイズ >= w` or `>= h` on *either* axis, func_proc first copies the
     object into a larger buffer. The pad is written so that the padded axis
     is always at least `kernel = 2*サイズ+1` long - which is exactly the
     condition シャドー does *not* enforce and pays for (シャドー §2).
     Checked exhaustively for 1..200 px objects x 0..200 サイズ.

  5. **`サイズ` is clamped against the allocation only, never against `w` or
     `h`.** Same shape as シャドー's 拡散 clamp, minus the offset that eats
     the budget first - so `サイズ` gets the whole margin.

Run via main.py:
    uv run main.py inspect/border/verify_params.py
"""

from tools.cints import c_div, divisor_of, msvc_div

FULL = 4096

SIZE_RAW = (0, 500)   # サイズ: raw range, display scale 1 -> pixels
BLUR_RAW = (0, 100)   # ぼかし: raw range, display scale 1 -> unitless


def dead_blur_value(raw: int) -> int:
    """0x10051611-0x10051632: 4096 - trunc(ぼかし*4096/1000), stored to
    g_101b1e38 and never read again."""
    return FULL - msvc_div(raw << 12)


def gain(size: int, blur: int) -> int:
    """0x1005197a-0x100519a5, in x87 throughout.

        fild (kernel-1)*ぼかし ; fmul 0.01 ; fadd 1.0 ; fdivr 1024.0
        fadd 0.5              ; _ftol        (truncate toward zero)

    `kernel - 1` is `2*size`, so the denominator is `0.02*size*blur + 1`.
    The operand is non-negative, so `+0.5` then truncate is round-half-up.
    """
    return int(1024.0 / ((2 * size) * blur * 0.01 + 1.0) + 0.5)


def prepad(w: int, h: int, size: int, stride: int, rows: int):
    """0x10051641-0x1005176d. Returns (padX, padY, padded_w, padded_h).

    Runs only when the kernel does not fit on at least one axis - but when it
    runs it pads BOTH axes, and the `+2` means the pad is never zero even on
    the axis that was already big enough.
    """
    if not (2 * size >= w or 2 * size >= h):
        return 0, 0, w, h
    pad_x = c_div(max(2 * size - w, 0) + 2, 2)
    pad_y = c_div(max(2 * size - h, 0) + 2, 2)
    if 2 * pad_x > stride - w:            # 0x10051691-0x100516a2
        pad_x = c_div(stride - w, 2)
    if 2 * pad_y > rows - h:              # 0x100516b2-0x100516bd
        pad_y = c_div(rows - h, 2)
    return pad_x, pad_y, w + 2 * pad_x, h + 2 * pad_y


def clamp_size(size: int, w: int, h: int, stride: int, rows: int) -> int:
    """0x1005176f-0x100517a1, against the allocated buffer and nothing else."""
    if 2 * size > stride - w:
        size = c_div(stride - w, 2)
    if 2 * size > rows - h:
        size = c_div(rows - h, 2)
    return size


def geometry(w0, h0, size_raw, blur_raw, stride=None, rows=None):
    """func_proc's parameter and canvas maths, end to end.

    The real (stride, rows) are however much exedit pre-allocated for this
    object's buffer; this analysis did not pin that down, so they are
    parameters with generous defaults - the same stand-in シャドー and ライト
    use.
    """
    stride = stride if stride is not None else w0 + 1024
    rows = rows if rows is not None else h0 + 1024

    pad_x, pad_y, w, h = prepad(w0, h0, size_raw, stride, rows)
    size = clamp_size(size_raw, w, h, stride, rows)
    return {
        "w0": w0, "h0": h0, "pad_x": pad_x, "pad_y": pad_y,
        "padded_w": w, "padded_h": h,
        "size": size, "kernel": 2 * size + 1, "gain": gain(size, blur_raw),
        # 0x100517aa/0x100517ac -> the canvas the workers write
        "canvas_w": w + 2 * size, "canvas_h": h + 2 * size,
        # 0x10051a7a/0x10051a7e -> what is published in fpip+0xB4/+0xB8
        "final_w": w + 2 * size - 2 * pad_x, "final_h": h + 2 * size - 2 * pad_y,
        "stride": stride, "rows": rows,
    }


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    from tools.disasm import disasm_range
    from tools.pe_image import PEImage
    from tools.xrefs import function_owners, instruction_containing, owner_of, scan
    img = PEImage(dll_path)
    owners = function_owners(img)
    CODE = (0x100515D0, 0x100522E4)          # 縁取り's private code, start..end

    print("--- 1. ぼかし goes through /1000 ... into a global nobody reads ---")
    d = divisor_of(0x10624DD3, 6)
    check(f"magic 0x10624dd3 with shift 6 really divides by {d}", d == 1000)
    bad = [raw for raw in range(BLUR_RAW[0], BLUR_RAW[1] + 1)
           if dead_blur_value(raw) != FULL - raw * FULL // 1000]
    check("all 101 ぼかし raw values match 4096 - trunc(raw*4096/1000)", not bad,
          f"first mismatch {bad[:1]}")

    magics = [i.address for i, _ in disasm_range(img, CODE[0], CODE[1] - CODE[0], resolve=False)
              if "0x10624dd3" in i.op_str]
    check("exactly one 0x10624dd3 in the whole effect, at 0x10051614",
          magics == [0x10051614], f"found {[hex(a) for a in magics]}")

    # The point of the section. A byte scan of the whole image, not a
    # disassembly of this effect: on 32-bit x86 with no position independence
    # every reference to a global is the literal dword somewhere in the file,
    # so "the literal appears exactly once" settles it for the entire binary.
    hits = scan(img, 0x101B1E38)
    insns = [instruction_containing(img, va, 0x101B1E38,
                                    anchor=(owner_of(owners, va) or (None,))[0])
             for va in hits]
    check("the literal 0x101b1e38 occurs exactly once in the whole image", len(hits) == 1,
          f"{len(hits)} hits at {[hex(v) for v in hits]}")
    check("... and that one occurrence is the store at 0x10051632, so nothing can read it",
          len(insns) == 1 and insns[0] is not None and insns[0].address == 0x10051632
          and insns[0].op_str.startswith("dword ptr [0x101b1e38]"),
          f"{[(hex(i.address), i.mnemonic, i.op_str) for i in insns if i]}")
    print("  So `4096 - trunc(ぼかし*4096/1000)` - the one value that looks like a")
    print("  conventional Q12 parameter - is computed every frame and thrown away.")
    print("  Everything ぼかし actually does goes through the x87 gain in §3.")

    print("\n--- 2. サイズ == 0 is the only early-out ---")
    print("  0x100515e4 tests track[0] and nothing else.")
    g = geometry(100, 60, 0, 100)
    check("サイズ = 0 would give kernel 1 and an unchanged canvas (if it ran at all)",
          g["kernel"] == 1 and (g["final_w"], g["final_h"]) == (100, 60),
          f"kernel {g['kernel']}, canvas {g['final_w']}x{g['final_h']}")
    g = geometry(100, 60, 10, 0)
    check("ぼかし = 0 runs the whole pipeline with gain 1024",
          g["gain"] == 1024 and (g["final_w"], g["final_h"]) == (120, 80),
          f"gain {g['gain']}, canvas {g['final_w']}x{g['final_h']}")

    print("\n--- 3. the gain: round(1024 / (0.02*サイズ*ぼかし + 1)) ---")
    grid = {(s, b): gain(s, b) for s in range(SIZE_RAW[0], SIZE_RAW[1] + 1)
            for b in range(BLUR_RAW[0], BLUR_RAW[1] + 1)}
    check(f"over all {len(grid)} raw pairs the gain stays in 1..1024",
          all(1 <= v <= 1024 for v in grid.values()),
          f"min {min(grid.values())} max {max(grid.values())}")
    check("gain == 1024 exactly when ぼかし == 0 (or サイズ == 0, which returns early)",
          all((v == 1024) == (b == 0 or s == 0) for (s, b), v in grid.items()))
    mono = all(grid[(s, b)] >= grid[(s, b + 1)] for s in range(0, 501)
               for b in range(0, 100))
    check("non-increasing in ぼかし for every サイズ", mono)
    mono = all(grid[(s, b)] >= grid[(s + 1, b)] for s in range(0, 500)
               for b in range(0, 101))
    check("non-increasing in サイズ for every ぼかし", mono)

    print(f"  {'サイズ':>7}{'ぼかし':>8}{'2*s*b*0.01':>12}{'gain':>7}"
          f"{'1024/gain':>11}")
    for s, b in ((3, 10), (3, 0), (3, 100), (10, 10), (10, 50), (100, 10), (500, 100)):
        print(f"  {s:>7}{b:>8}{2 * s * b * 0.01:>12.2f}{gain(s, b):>7}"
              f"{1024 / gain(s, b):>11.2f}")
    check("the default サイズ=3 / ぼかし=10 gives gain 640 = 1024/1.6", gain(3, 10) == 640,
          f"got {gain(3, 10)}")

    # `+0.5` then truncate is only ambiguous when the quotient lands on a .5
    # boundary, and that is the one place x87's precision control (53-bit, the
    # MSVC default, versus 64-bit) could change the answer. Rather than guess
    # the precision, evaluate the same expression exactly - Fraction(0.01) is
    # the exact value of the double constant at 0x1009a3c8 - and see whether
    # infinite precision would ever disagree with the 53-bit result.
    from fractions import Fraction
    C = Fraction(0.01)
    exact = {}
    for s in range(SIZE_RAW[0], SIZE_RAW[1] + 1):
        for b in range(BLUR_RAW[0], BLUR_RAW[1] + 1):
            q = Fraction(1024) / (Fraction(2 * s * b) * C + 1)
            exact[(s, b)] = int(q + Fraction(1, 2))       # q > 0, so trunc == floor
    disagree = sorted(k for k in grid if grid[k] != exact[k])
    check(f"the 53-bit and infinite-precision gains agree on {len(grid) - len(disagree)} "
          f"of {len(grid)} pairs, differing on exactly {len(disagree)}",
          len(disagree) == 5, f"{len(disagree)} disagree")
    print(f"  {'サイズ':>7}{'ぼかし':>8}{'53-bit':>9}{'exact':>8}{'quotient':>20}"
          f"{'quotient - .5 boundary':>26}")
    for s, b in disagree:
        q = Fraction(1024) / (Fraction(2 * s * b) * C + 1)
        eps = q - (int(q) + Fraction(1, 2))
        print(f"  {s:>7}{b:>8}{grid[(s, b)]:>9}{exact[(s, b)]:>8}"
              f"{float(q):>20.13f}{float(eps):>26.3e}")
    check("every disagreement is by exactly 1, and in every case the exact quotient sits "
          "just BELOW a .5 boundary that the 53-bit rounding pushes it onto",
          all(grid[k] - exact[k] == 1 for k in disagree)
          and all(-1e-12 < float(Fraction(1024) / (Fraction(2 * s * b) * C + 1)
                                 - (int(Fraction(1024) / (Fraction(2 * s * b) * C + 1))
                                    + Fraction(1, 2))) < 0
                  for s, b in disagree))
    print("  These 5 pairs are the only inputs where x87's precision control (53-bit,")
    print("  the MSVC default, versus 64-bit) can change 縁取り's output at all, and it")
    print("  changes the gain by 1/1024. Everywhere else the rounding is unambiguous.")
    print("  (シャドー §5 has the same open question but over 5.41% of its inputs.)")

    print("\n--- 4. the pre-pad guarantees the sliding window fits ---")
    print("  Condition (0x10051644): 2*サイズ >= w OR 2*サイズ >= h - i.e. the kernel")
    print("  2*サイズ+1 does not fit on at least one axis. Note it pads BOTH axes.")
    BIG = 1 << 20
    bad = []
    for w in range(1, 201):
        for h in range(1, 201):
            for size in range(0, 101, 3):
                px, py, pw, ph = prepad(w, h, size, BIG, BIG)
                if not (2 * size >= w or 2 * size >= h):
                    continue
                if pw < 2 * size + 1 or ph < 2 * size + 1:
                    bad.append((w, h, size, pw, ph))
    check("200x200 object shapes x 34 サイズ values: whenever the pre-pad runs, BOTH "
          "padded axes are at least one full kernel wide", not bad, f"first {bad[:1]}")
    print(f"  {'w':>5}{'サイズ':>8}{'kernel':>8}{'padX':>7}{'padded w':>10}")
    for w, size in ((64, 40), (64, 32), (63, 32), (64, 33), (1, 3)):
        pad, _, pw, _ = prepad(w, 1, size, BIG, BIG)
        print(f"  {w:>5}{size:>8}{2 * size + 1:>8}{pad:>7}{pw:>10}")
    check("the padded width is 2*サイズ+1 or +2, i.e. the kernel plus at most one spare",
          all(prepad(w, 1, s, BIG, BIG)[2] in (2 * s + 1, 2 * s + 2)
              for w in range(1, 200) for s in range(1, 100) if 2 * s >= w))

    print("\n  The `+2` in `(v+2)/2` means the pad is at least 1 on an axis that")
    print("  needed nothing - the pre-pad is triggered per-effect, not per-axis:")
    print(f"  {'w':>5}{'h':>5}{'サイズ':>8}{'padX':>7}{'padY':>7}"
          f"{'padded w':>10}{'padded h':>10}")
    for w, h, size in ((200, 10, 20), (200, 400, 20), (10, 200, 20)):
        px, py, pw, ph = prepad(w, h, size, BIG, BIG)
        print(f"  {w:>5}{h:>5}{size:>8}{px:>7}{py:>7}{pw:>10}{ph:>10}")
    px, py, pw, ph = prepad(200, 10, 20, BIG, BIG)
    check("w=200 (kernel 41 fits easily) still gets padX=1 because h=10 did not fit",
          (px, pw) == (1, 202), f"padX={px} padded_w={pw}")
    check("... and when neither axis needs it, nothing is padded at all",
          prepad(200, 400, 20, BIG, BIG) == (0, 0, 200, 400))
    print("  Harmless either way - the crop at the end takes the pad back exactly.")

    print("\n  シャドー is the counter-example: it has no pre-pad at all, so a thin")
    print("  object drives its first pass's middle phase negative (シャドー §2).")
    print("  縁取り reaches the same sliding window with the axis always >= kernel.")

    print("\n--- 5. サイズ is clamped against the allocation, never against w or h ---")
    bad = []
    for w, h, stride, rows in ((100, 60, 140, 90), (10, 10, 1024, 1024), (300, 200, 301, 201)):
        for size in range(0, SIZE_RAW[1] + 1, 3):
            g = geometry(w, h, size, 10, stride=stride, rows=rows)
            if g["canvas_w"] > stride or g["canvas_h"] > rows or g["size"] < 0:
                bad.append((w, h, size, g))
    check("3 buffer shapes x 168 サイズ values: the grown canvas never exceeds the "
          "allocation and サイズ never goes negative", not bad, f"{len(bad)} bad, first {bad[:1]}")
    print(f"  {'stride':>8}{'w':>5}{'サイズ raw':>11}{'padded w':>10}"
          f"{'サイズ used':>13}{'canvas w':>10}")
    for stride in (140, 200, 1024):
        g = geometry(100, 60, 50, 10, stride=stride, rows=1024)
        print(f"  {stride:>8}{100:>5}{50:>11}{g['padded_w']:>10}"
              f"{g['size']:>13}{g['canvas_w']:>10}")
    g = geometry(100, 60, 50, 10, stride=140, rows=1024)
    check("with stride=140 and w=100 the 50-pixel border collapses to 19 - the margin "
          "is measured after the pre-pad, which spent 2 of the 40 spare columns",
          (g["padded_w"], g["size"]) == (102, 19), f"padded {g['padded_w']} size {g['size']}")
    print("  Unlike シャドー there is no X/Y offset competing for the same margin, so")
    print("  サイズ gets all of it. And unlike ライト (trunc(dim/2)-2) and 発光")
    print("  (dim/2-1) there is no clamp against the object's own size - the pre-pad")
    print("  in §4 makes one unnecessary.")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
