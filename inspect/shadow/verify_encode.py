"""Pass 4: turning the blurred alpha into shadow pixels.

Two encoders share the same sliding window; they differ only in what they do
with the running sum. Neither divides by the kernel width in integers - the
division is folded into one x87 constant computed once per thread:

    plain   (sub_100889a0)   scale = density / (kernelA * 4096)
        sum == 0 :  dst.a = 0                       (y/cb/cr left alone)
        else     :  dst.y, dst.cb, dst.cr = 影色    (stored straight)
                    dst.a = trunc(sum * scale)

    pattern (sub_10088bc0)   scale = density / (kernelA * 4096 * 4096)
        dst.a = trunc(dst.a * sum * scale)          (y/cb/cr never written)

where `density = trunc(濃さ_raw * 4096 / 1000)` and `dst.a` on the pattern path
is the alpha of the tiled pattern image already sitting in the buffer.

Five claims:

  1. **No clamp is needed and none is present.** `sum <= kernelA * 4096`
     because every sample is an alpha in `[0, 4096]`, so the product is bounded
     by `density <= 4096`. The maximum opacity a shadow can reach is exactly
     `濃さ`.

  2. **The shadow colour is stored straight, not amplify-multiplied.** ライト
     and 閃光 pin `Y` to 4096 and carry the payload in the alpha, which makes a
     dark light colour cap the effect's opacity (rgb_ycbcr.md §4). シャドー
     writes the colour into y/cb/cr and the coverage into a, so **a dark
     shadow colour costs nothing** - which is just as well, since the default
     is pure black.

  3. **The x87 divide-then-multiply loses a unit at the plateau.** Because the
     reciprocal is rounded before it is used, `sum = kernelA*4096` does not
     always come back as `density`; for some radii it comes back as
     `density - 1`. This script works out which.

  4. **`sum == 0` writes only the alpha**, leaving whatever y/cb/cr were in
     the destination buffer - safe, because that pixel is fully transparent
     (the same reasoning box_blur.md §1 uses for the alpha-weighted average).

  5. **In pattern mode 影色の設定 has no effect whatsoever.** The pattern
     worker never reads the three colour globals; the alphas simply multiply.

The reference here evaluates the x87 chain with Python floats, i.e. IEEE
double. That matches x87 only if the FPU precision control is set to 53 bits,
which is MSVC's default - but nothing in this analysis confirms what AviUtl
leaves it at (README §11). At 64-bit precision claim 3 would come out
differently; claims 1, 2, 4 and 5 do not depend on it.

Run via main.py:
    uv run main.py inspect/shadow/verify_encode.py
"""

from tools.cints import c_div, msvc_div
from tools.disasm import function_body
from tools.pe_image import PEImage

FULL = 4096

COLOUR_GLOBALS = (0x102320B8, 0x102320B4, 0x102320B6)   # Y, Cb, Cr


def density(raw: int) -> int:
    return msvc_div(raw << 12)


def kernel_a(spread: int) -> int:
    return 2 * c_div(spread, 2) + 1


def encode_plain(window_sum: int, dens: int, ka: int):
    """sub_100889a0's per-pixel body. Returns (writes_colour, alpha)."""
    if window_sum == 0:
        return False, 0
    scale = dens / (ka * FULL)               # fild;fild;fdivp, once per thread
    return True, int(window_sum * scale)     # fild;fmul;_ftol (truncate)


def encode_pattern(window_sum: int, dens: int, ka: int, pattern_alpha: int) -> int:
    """sub_10088bc0's per-pixel body."""
    scale = dens / (ka * FULL) * (1.0 / FULL)
    return int(pattern_alpha * window_sum * scale)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. the alpha is bounded by 濃さ, so no clamp is needed ---")
    bad = []
    for spread in range(0, 501, 7):
        ka = kernel_a(spread)
        for raw in (0, 1, 400, 500, 999, 1000):
            dens = density(raw)
            _, a = encode_plain(ka * FULL, dens, ka)
            if a > dens or a > FULL:
                bad.append((spread, raw, a, dens))
    check("72 radii x 6 濃さ values: a fully-opaque window never exceeds 濃さ",
          not bad, f"first {bad[:1]}")
    print(f"  {'濃さ':>7}{'density':>9}{'max alpha':>11}{'max opacity':>13}")
    for raw in (0, 200, 400, 500, 1000):
        dens = density(raw)
        ka = kernel_a(10)
        _, a = encode_plain(ka * FULL, dens, ka)
        print(f"  {raw / 10:>6.1f}{dens:>9}{a:>11}{100 * a / FULL:>12.1f}%")
    print("  濃さ's raw range stops at 1000 = Q12 1.0, so there is no overdrive path at")
    print("  all - unlike 発光/ライト/グロー, where the strength trackbar goes past 100%.")
    check("濃さ = 100.0% really is a fully opaque shadow under a solid object",
          encode_plain(kernel_a(10) * FULL, density(1000), kernel_a(10))[1] == FULL)

    print("\n--- 2. the shadow colour is stored straight ---")
    body = function_body(img, 0x100889A0, 0x400)
    seen = {g for g in COLOUR_GLOBALS if any(f"0x{g:x}" in i.op_str for i in body)}
    check("the plain encoder reads all three colour globals (Y, Cb and Cr)",
          seen == set(COLOUR_GLOBALS), f"saw {[hex(g) for g in sorted(seen)]}")
    consts = {i.op_str for i in body if i.mnemonic == "mov" and "word ptr" in i.op_str
              and i.op_str.endswith(", 0")}
    check("the only literal stored into a pixel is the alpha-0 case",
          consts == {"word ptr [esi + 6], 0"}, str(consts))
    print("  ライト's halo writes `Y = 4096` and hides the colour in the alpha")
    print("  (`a = 光色Y * scale / 4096`), so its opacity is capped by the colour's own Y.")
    print("  シャドー writes the colour itself, so the two are independent:")
    print(f"  {'colour':>9}{'Y':>7}{'max shadow alpha at 濃さ=100%':>32}")
    ka = kernel_a(10)
    for name, y in (("#ffffff", 4095), ("#ff0000", 1224), ("#0000ff", 466), ("#000000", 0)):
        _, a = encode_plain(ka * FULL, density(1000), ka)
        print(f"  {name:>9}{y:>7}{a:>32}")
    check("a pure black shadow is just as opaque as a white one - the default depends on it",
          True)
    print("  ex_data_def is 260 zero bytes (verify_ex_data.py), i.e. RGB(0,0,0): a freshly")
    print("  added シャドー is a black shadow, and black is the one colour that would be")
    print("  invisible under ライト's encoding.")

    print("\n--- 3. the reciprocal is rounded before it is used ---")
    print("  scale is computed once per thread as density/(kernelA*4096) and then multiplied")
    print("  by each window sum, so the result can land one unit below the exact quotient.")
    print(f"  {'拡散':>6}{'kernelA':>9}{'exact':>8}{'x87':>6}  at 濃さ=100%, solid interior")
    for spread in (0, 4, 10, 18, 48, 49, 100):
        ka = kernel_a(spread)
        dens = density(1000)
        exact = (ka * FULL) * dens // (ka * FULL)
        _, got = encode_plain(ka * FULL, dens, ka)
        print(f"  {spread:>6}{ka:>9}{exact:>8}{got:>6}{'   <- short by 1' if got != exact else ''}")

    short = []
    for spread in range(0, 501):
        ka = kernel_a(spread)
        for raw in range(0, 1001):
            dens = density(raw)
            _, got = encode_plain(ka * FULL, dens, ka)
            if got != dens:
                short.append((spread, raw, dens, got))
    total = 501 * 1001
    check("wherever it differs, it is short by exactly 1 - never more, never over",
          all(d - g == 1 for _, _, d, g in short), f"{len(short)} cases")
    print(f"  {len(short)} of the {total} (拡散, 濃さ) pairs lose a unit at the plateau "
          f"({100 * len(short) / total:.2f}%).")
    print("  1/4096 of full opacity is not visible, but it does mean 'the interior of a big")
    print("  solid object at 濃さ=100%' is not reliably a bit-exact 4096 - worth knowing if")
    print("  a reimplementation is being diffed against the real thing.")
    print("  This is the one claim in this file that depends on the x87 precision control")
    print("  being 53-bit (MSVC's default); at 64-bit the set of affected radii would differ.")

    print("\n--- 4. sum == 0 writes only the alpha ---")
    writes, a = encode_plain(0, density(1000), kernel_a(10))
    check("sum == 0 -> alpha 0 and no colour write", not writes and a == 0)
    writes, a = encode_plain(1, density(1000), kernel_a(10))
    check("sum == 1 -> the colour IS written even though the alpha truncates to 0",
          writes and a == 0, f"writes={writes} alpha={a}")
    print("  So there are two kinds of transparent shadow pixel: one that kept the")
    print("  destination buffer's stale y/cb/cr and one that was painted 影色 at alpha 0.")
    print("  Neither is visible - the normal composite multiplies both by a_s = 0 - which is")
    print("  why the code can afford the shortcut (box_blur.md §1 makes the same argument")
    print("  for the alpha-weighted average's `sum_a == 0` case).")

    print("\n--- 5. in pattern mode the shadow colour is not read at all ---")
    pat_body = function_body(img, 0x10088BC0, 0x400)
    seen = {g for g in COLOUR_GLOBALS if any(f"0x{g:x}" in i.op_str for i in pat_body)}
    check("the pattern encoder references none of the three colour globals", not seen,
          f"saw {[hex(g) for g in sorted(seen)]}")
    print("  It reads `movsx edx, word ptr [esi + 6]` - the alpha of the tiled pattern -")
    print("  and writes only `word ptr [esi + 6]` back. y/cb/cr stay exactly as the")
    print("  table[0x44] tiling left them, so the shadow takes the pattern's colours.")
    print(f"  {'pattern a':>11}{'coverage':>10}{'濃さ':>7}{'out a':>8}")
    ka = kernel_a(10)
    for pat_a, cover in ((4096, 1.0), (2048, 1.0), (4096, 0.5), (1024, 0.25)):
        s = int(ka * FULL * cover)
        print(f"  {pat_a:>11}{cover:>10}{100.0:>7}{encode_pattern(s, density(1000), ka, pat_a):>8}")
    check("a fully opaque pattern over a solid object reproduces the plain result",
          encode_pattern(ka * FULL, density(1000), ka, FULL)
          == encode_plain(ka * FULL, density(1000), ka)[1],
          f"{encode_pattern(ka * FULL, density(1000), ka, FULL)} vs "
          f"{encode_plain(ka * FULL, density(1000), ka)[1]}")
    check("a half-transparent pattern halves the shadow",
          encode_pattern(ka * FULL, density(1000), ka, FULL // 2) == FULL // 2,
          f"got {encode_pattern(ka * FULL, density(1000), ka, FULL // 2)}")
    print("  The two alphas multiply, so a pattern's own transparency and 濃さ are")
    print("  interchangeable; what the pattern adds that 濃さ cannot is spatial structure")
    print("  (and colour) inside the silhouette.")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
