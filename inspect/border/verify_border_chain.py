"""The two-pass chain itself: what it computes, and the two places it can go
wrong.

Six claims:

  1. **Two passes, one kernel - the impulse response is a FLAT BOX**
     `(2*サイズ+1)^2`, not the triangle ぼかし and シャドー build. Those split
     the radius in half and run two passes *per axis* so the boxes convolve;
     縁取り runs one pass per axis, so nothing convolves with anything.

  2. **There is no division in the pixel loop at all.** Every other box filter
     in exedit divides the window sum by the kernel width (box_blur.md §3);
     both of 縁取り's workers contain exactly two `idiv`s, and both of them are
     the thread-range split. The window sum is *scaled by the gain and
     saturated* instead, which is what turns a blur into a dilation.

  3. **Each pass emits `n + kernel - 1` outputs** from an `n`-long axis, so the
     chain fills exactly `(w + 2*サイズ) x (h + 2*サイズ)` - the canvas
     verify_canvas.py §1 publishes.

  4. **The gain is applied twice** (0x10051b6d and 0x10051d59), so a pixel deep
     inside the object goes through `min(4096, ...)` twice. With `ぼかし = 0`
     the gain is 1024, `sum*1024 >> 10` is the identity, and the chain
     degenerates to an exact binary dilation of the silhouette.

  5. **`imul` overflow.** The multiply is a signed 32-bit `imul` with no
     widening, and `kernel * 4096 * gain` can exceed 2^31. This works out
     exactly which trackbar settings can reach it: only `ぼかし = 0` combined
     with `サイズ >= 256`, and only where the window is fully covered by
     opaque pixels.

  6. **The head phase never reads outside the object** - the pre-pad
     (verify_params.py §4) guarantees `n >= kernel`, so the middle phase count
     `n - kernel` is never negative. This is the exact failure box_blur.md §4
     catalogues for クロマキー / カラーキー / 境界ぼかし and シャドー §2,
     and 縁取り is the first effect here that is immune to it.

Run via main.py:
    uv run main.py inspect/border/verify_border_chain.py
"""

from tools.cints import c_div, to_i32
from tools.disasm import function_body
from tools.pe_image import PEImage

FULL = 4096
PASS1 = 0x10051AE0
PASS2_COLOUR = 0x10051C80
PASS2_PATTERN = 0x10051EA0


def gain(size: int, blur: int) -> int:
    """0x1005197a-0x100519a5."""
    return int(1024.0 / ((2 * size) * blur * 0.01 + 1.0) + 0.5)


def saturate(total: int, g: int) -> int:
    """0x10051b6d-0x10051b86 / 0x10051d59-0x10051d75, verbatim.

        imul ecx, gain      ; signed, 32-bit, NO widening
        sar  ecx, 0xa
        cmp  ecx, 0x1000
        jge  store 0x1000
        mov  word ptr [esi], cx

    The `mov word` is what makes an overflowed (negative) result observable:
    it stores the low 16 bits, and the next pass reads them back with `movsx`.
    """
    v = to_i32(to_i32(total) * g) >> 10
    if v >= FULL:
        return FULL
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def sliding(samples, kernel, g):
    """One pass over one axis: head / middle / tail, exactly as the three loops
    at 0x10051b65, 0x10051bc0 and 0x10051c27 run them.

    Emits `len(samples) + kernel - 1` values. The trailing pointer stays put
    through the head phase and only starts moving in the middle, which is what
    makes the first `kernel` outputs a growing window.
    """
    n = len(samples)
    if n < kernel:
        # The real worker would read past the end of the axis here. §6 proves
        # the pre-pad makes that unreachable, so refuse rather than invent a
        # value and quietly model something exedit never does.
        raise ValueError(f"axis {n} shorter than kernel {kernel}: pre-pad should "
                         "have prevented this")
    out, total, lead, trail = [], 0, 0, 0
    for _ in range(kernel):                       # head
        total += samples[lead]; lead += 1
        out.append(saturate(total, g))
    for _ in range(max(0, n - kernel)):           # middle
        total += samples[lead] - samples[trail]; lead += 1; trail += 1
        out.append(saturate(total, g))
    for _ in range(kernel - 1):                   # tail
        total -= samples[trail]; trail += 1
        out.append(saturate(total, g))
    return out


def coverage(alpha, size, blur):
    """The whole chain: pass 1 down every column, pass 2 across every row.

    `alpha` is a list of rows. Returns the (h+2s) x (w+2s) coverage map that
    pass 2 turns into the border's alpha.
    """
    kernel, g = 2 * size + 1, gain(size, blur)
    h, w = len(alpha), len(alpha[0])
    cols = [sliding([alpha[y][x] for y in range(h)], kernel, g) for x in range(w)]
    scratch = [[cols[x][y] for x in range(w)] for y in range(h + kernel - 1)]
    return [sliding(row, kernel, g) for row in scratch]


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)

    print("--- 1. the impulse response is a flat box, not a triangle ---")
    bad = []
    for size in range(0, 7):
        n = 4 * size + 5
        img_in = [[0] * n for _ in range(n)]
        img_in[n // 2][n // 2] = 1              # amplitude 1: gain 1024 is the identity
        out = coverage(img_in, size, 0)
        lit = {(y, x) for y, row in enumerate(out) for x, v in enumerate(row) if v}
        want = {(y, x) for y in range(n // 2, n // 2 + 2 * size + 1)
                for x in range(n // 2, n // 2 + 2 * size + 1)}
        vals = {out[y][x] for y, x in lit}
        if lit != want or vals != {1}:
            bad.append((size, len(lit), sorted(vals)[:3]))
    check("サイズ 0..6: a unit impulse spreads to exactly (2s+1)^2 pixels, all of "
          "value 1", not bad, f"first {bad[:1]}")
    print("  ぼかし / シャドー run TWO passes per axis with kernels that sum to the")
    print("  radius, so their boxes convolve into a triangle (box_blur.md §2). 縁取り")
    print("  runs ONE pass per axis: the support is 2*サイズ+1 and the weights are flat,")
    print("  which is what makes the result a dilation of the silhouette rather than a")
    print("  smooth falloff.")

    print("\n--- 2. no division in the pixel loop ---")
    for label, addr in (("pass 1", PASS1), ("pass 2 colour", PASS2_COLOUR),
                        ("pass 2 pattern", PASS2_PATTERN)):
        body = function_body(img, addr)
        divs = [(hex(i.address), i.mnemonic, i.op_str) for i in body
                if i.mnemonic in ("idiv", "div")]
        check(f"{label} (0x{addr:08x}, {len(body)} instructions): exactly two idivs, "
              "both in the thread-range prologue", len(divs) == 2
              and all(int(a, 16) < addr + 0x60 for a, _, _ in divs), f"{divs}")
    print("  Every other exedit box filter ends its window with `idiv kernel_width`.")
    print("  Here the window sum goes straight into `imul gain ; sar 10 ; saturate`,")
    print("  so a fully covered window does not average to 4096 - it *exceeds* 4096 and")
    print("  gets clipped there. That difference is the whole effect.")

    print("\n--- 3. each pass emits n + kernel - 1 outputs ---")
    bad = []
    for n in range(1, 60):
        for size in range(0, 30):
            kernel = 2 * size + 1
            if n < kernel:
                continue           # the pre-pad rules this out; §6
            if len(sliding([FULL] * n, kernel, 1024)) != n + kernel - 1:
                bad.append((n, size))
    check("all reachable (axis length, サイズ) pairs emit exactly n + 2*サイズ outputs",
          not bad, f"first {bad[:1]}")
    out = coverage([[FULL] * 8 for _ in range(5)], 2, 0)
    check("a 8x5 opaque rectangle with サイズ=2 fills a 12x9 canvas",
          (len(out[0]), len(out)) == (12, 9), f"{len(out[0])}x{len(out)}")

    print("\n--- 4. the gain is applied twice; ぼかし = 0 is an exact dilation ---")
    check("gain(size, 0) == 1024 for every size, and 1024 * s >> 10 == s",
          all(gain(s, 0) == 1024 for s in range(0, 501))
          and all(to_i32(v * 1024) >> 10 == v for v in range(0, FULL + 1)))
    solid = [[FULL] * 9 for _ in range(9)]
    out = coverage(solid, 3, 0)
    binary = {v for row in out for v in row} <= {0, FULL}
    check("ぼかし = 0 over a solid rectangle: every output pixel is 0 or 4096",
          binary, f"values {sorted({v for row in out for v in row})[:5]}")
    print("\n  With ぼかし > 0 the gain scales the sum down, so the window has to be")
    print("  more than `1024/gain` samples deep in the silhouette to saturate. Profile")
    print("  across a horizontal edge (top half transparent, bottom half opaque, wide")
    print("  enough that the horizontal pass is saturated everywhere), サイズ = 8:")
    size, top = 8, 16
    wide = 4 * size + 3
    half = [[0] * wide for _ in range(top)] + [[FULL] * wide for _ in range(top)]
    edge = top + size          # canvas row of the first pixel below the object's edge
    dists = list(range(0, 2 * size + 1, 2))
    print(f"  {'ぼかし':>7}{'gain':>6}  " + "".join(f"{d:>5}" for d in dists)
          + "   <- pixels above the edge")
    profiles = {}
    for blur in (0, 25, 50, 75, 100):
        profiles[blur] = [row[wide // 2] for row in coverage(half, size, blur)]
        print(f"  {blur:>7}{gain(size, blur):>6}  "
              + "".join(f"{profiles[blur][edge - 1 - d]:>5}" for d in dists))
    check("ぼかし = 0 is a hard step: every pixel of the profile is 0 or 4096",
          set(profiles[0]) == {0, FULL}, f"values {sorted(set(profiles[0]))[:5]}")
    check("ぼかし = 100 never reaches full opacity anywhere in the border",
          max(profiles[100]) < FULL, f"max {max(profiles[100])}")
    print("  So ぼかし is not only an edge softener: past a point it makes the whole")
    print("  border translucent, because the same gain multiplies the saturated core.")

    print("\n--- 5. the imul can overflow, and only here ---")
    print("  Worst case per pass is a window entirely inside opaque pixels:")
    print("  sum = kernel * 4096, so the product is kernel * 4096 * gain.")
    over = [(s, b) for s in range(0, 501) for b in range(0, 101)
            if (2 * s + 1) * FULL * gain(s, b) > 0x7FFFFFFF]
    blurs = sorted({b for _, b in over})
    sizes = sorted({s for s, _ in over})
    check("of all 50601 trackbar pairs, the ones that can overflow are exactly "
          "ぼかし = 0 with サイズ >= 256", blurs == [0] and sizes == list(range(256, 501)),
          f"blurs {blurs[:3]}, sizes {sizes[:1]}..{sizes[-1:]}")
    print(f"  {len(over)} of 50601 pairs. The threshold is (2*サイズ+1)*gain >= 524288;")
    print("  with gain 1024 that is kernel >= 512, i.e. サイズ >= 256.")
    demo_size, kernel = 300, 601
    total = kernel * FULL
    print(f"  サイズ={demo_size}, ぼかし=0, a fully opaque 601-row window:")
    print(f"    sum          = {total}")
    print(f"    sum * 1024   = {total * 1024} (> 2^31 = {0x80000000})")
    print(f"    as int32     = {to_i32(total * 1024)}")
    print(f"    stored alpha = {saturate(total, 1024)}   (instead of 4096)")
    check("the wrapped result is stored, not clamped: it is negative before the "
          "`>= 4096` test, so the saturation branch is not taken",
          saturate(total, 1024) != FULL and to_i32(total * 1024) < 0)
    print("  The affected pixels are the ones whose whole window is opaque, i.e. deep")
    print("  inside the silhouette - where the object is composited on top anyway. It")
    print("  shows only through transparent holes in the object, and needs an object")
    print("  more than 512 px across in the affected axis to happen at all.")

    print("\n--- 6. the pre-pad makes the middle phase count non-negative ---")
    bad = []
    for w in range(1, 200):
        for h in range(1, 200, 3):
            for size in range(0, 100, 3):
                pw, ph = w, h
                if 2 * size >= w or 2 * size >= h:
                    pw = w + 2 * c_div(max(2 * size - w, 0) + 2, 2)
                    ph = h + 2 * c_div(max(2 * size - h, 0) + 2, 2)
                kernel = 2 * size + 1
                if pw - kernel < 0 or ph - kernel < 0:
                    bad.append((w, h, size, pw, ph, kernel))
    check("199 x 67 x 34 shapes: after the pre-pad, both axes are at least kernel long, "
          "so no head phase reads past the object", not bad, f"first {bad[:1]}")
    print("  Pass 2's input is `h + kernel - 1` rows long, which is >= kernel for any")
    print("  h >= 1, so it was never at risk. It is pass 1 - reading the object itself -")
    print("  that the pre-pad protects, and that is exactly the pass シャドー leaves")
    print("  unprotected (シャドー §2).")
    print("  The one way to break it is a tight allocation: the pre-pad's own clamp")
    print("  against fpip+0xEC / +0xF0 can cut the pad below what the kernel needs.")
    lost = []
    for stride in range(10, 200, 7):
        for w in range(1, min(stride, 120)):
            for size in range(0, 60):
                if not (2 * size >= w):
                    continue
                pad = c_div(max(2 * size - w, 0) + 2, 2)
                if 2 * pad > stride - w:
                    pad = c_div(stride - w, 2)
                pw = w + 2 * pad
                # サイズ is then re-clamped against the same margin
                s = size if 2 * size <= stride - pw else c_div(stride - pw, 2)
                if pw < 2 * s + 1:
                    lost.append((stride, w, size, pw, s))
    check("... but the サイズ re-clamp at 0x1005176f always shrinks the kernel back "
          "under the padded width, so even a tight allocation stays safe", not lost,
          f"{len(lost)} bad, first {lost[:1]}")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
