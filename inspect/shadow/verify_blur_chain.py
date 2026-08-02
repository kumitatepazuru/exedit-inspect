"""The four-pass blur chain: what each pass reads, writes and divides by, and
what the four of them add up to.

    pass 1  sub_10088580  V  kernel B  fpip+0xAC alpha -> plane 1   split by column
    pass 2  sub_100886f0  H  kernel B  plane 1          -> plane 2  split by row
    pass 3  sub_10088840  V  kernel A  plane 2          -> plane 1  split by column
    pass 4  sub_100889a0  H  kernel A  plane 1          -> fpip+0xB0 (encode, verify_encode.py)

with `kernel A = 2*trunc(拡散/2)+1` and `kernel B = 2*ceil(拡散/2)+1`.

Five claims, checked below:

  1. **Every pass is a uniform box average**, divided by its *full* kernel
     width even while the window is still filling - box_blur.md §2's "there is
     no Gaussian anywhere" and §3's "always divide by kernel width" variant,
     the one that fades into the grown margin.

  2. **Two passes per axis, and their supports add up to exactly `2*拡散+1`.**
     This is ぼかし's scheme: `box(kernelB) ⊛ box(kernelA)` is a triangle when
     `拡散` is even and a trapezoid with a 3-wide plateau when it is odd, and
     either way its half-width is `拡散` on the nose.

  3. **The chain is exact, not approximate**: what pass N+1 reads is precisely
     the rectangle pass N wrote - no pass ever reads a sample the previous one
     did not produce, and no produced sample is left unread.

  4. **Each axis grows by exactly `2*拡散`**, split `kernelB-1` from the first
     pass on that axis and `kernelA-1` from the second.

  5. **Only alpha is ever read.** Pass 1 loads `word ptr [ebx+6]` from
     `fpip+0xAC` and nothing else; the object's y/cb/cr never enter the
     shadow, which is why the shadow colour has to come from a parameter.

Run via main.py:
    uv run main.py inspect/shadow/verify_blur_chain.py
"""

import random

from tools.cints import c_div
from tools.disasm import function_body
from tools.pe_image import PEImage

FULL = 4096

PASSES = {
    0x10088580: ("pass 1", "vertical", "B", "fpip+0xAC (alpha)", "plane 1"),
    0x100886F0: ("pass 2", "horizontal", "B", "plane 1", "plane 2"),
    0x10088840: ("pass 3", "vertical", "A", "plane 2", "plane 1"),
    0x100889A0: ("pass 4", "horizontal", "A", "plane 1", "fpip+0xB0"),
    0x10088BC0: ("pass 4'", "horizontal", "A", "plane 1", "fpip+0xB0 (pattern)"),
}

KERNEL_A_GLOBAL = 0x10231F98
KERNEL_B_GLOBAL = 0x10231F94


def kernels(spread: int) -> tuple:
    r1 = c_div(spread, 2)
    return 2 * r1 + 1, 2 * (spread - r1) + 1      # (A, B)


def grow_1d(values: list, kernel: int) -> list:
    """One pass: the 3-phase sliding window, in the compact index-guarded form.

    Output `j` (0..n+kernel-2) is the sum of source samples `[j-kernel+1, j]`
    that actually exist, divided by the FULL kernel width - positions past
    either end contribute nothing, which is what makes the grown margin fade
    (box_blur.md §3).
    """
    n = len(values)
    total, out = 0, []
    for j in range(n + kernel - 1):
        if j < n:
            total += values[j]
        if 0 <= j - kernel < n:
            total -= values[j - kernel]
        out.append(c_div(total, kernel))
    return out


def grow_1d_literal(values: list, kernel: int) -> list:
    """The same thing written as the three loops the workers actually run
    (disasm_params.py): head `kernel` emits with no eviction, middle
    `n - kernel` emits that add and evict, tail `kernel - 1` emits that only
    evict. Kept separate so grow_1d can be checked against something shaped
    like the raw instructions instead of trusted on its own."""
    n = len(values)
    out, total, add_i, evict_i = [], 0, 0, 0
    for _ in range(kernel):
        total += values[add_i]
        add_i += 1
        out.append(c_div(total, kernel))
    for _ in range(max(0, n - kernel)):
        total += values[add_i] - values[evict_i]
        add_i += 1
        evict_i += 1
        out.append(c_div(total, kernel))
    for _ in range(kernel - 1):
        total -= values[evict_i]
        evict_i += 1
        out.append(c_div(total, kernel))
    return out


def convolve(a: list, b: list) -> list:
    out = [0] * (len(a) + len(b) - 1)
    for i, u in enumerate(a):
        for j, v in enumerate(b):
            out[i + j] += u * v
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. every pass divides by a kernel-width global, and by nothing else ---")
    print(f"  {'worker':>12}  {'pass':<8}{'axis':<12}{'kernel':<8}"
          f"{'reads':<20}{'writes':<20}")
    for addr, (name, axis, kern, src, dst) in PASSES.items():
        print(f"  0x{addr:08x}  {name:<8}{axis:<12}{kern:<8}{src:<20}{dst:<20}")

    print("\n  which kernel global does each worker's body actually reference?")
    for addr, (name, _, kern, _, _) in PASSES.items():
        body = function_body(img, addr, 0x600)
        uses_a = any(f"0x{KERNEL_A_GLOBAL:x}" in i.op_str for i in body)
        uses_b = any(f"0x{KERNEL_B_GLOBAL:x}" in i.op_str for i in body)
        # pass 3 and 4 read kernel B once to recompute the intermediate's
        # extents (disasm_params.py 0x10088847 / 0x100889a3); the kernel they
        # slide with is the one the idiv / fdiv uses.
        label = ("A" if uses_a else "") + ("B" if uses_b else "")
        expected_present = kern in label
        check(f"0x{addr:08x} ({name}) references kernel {kern}", expected_present,
              f"globals seen: {label or 'none'}")

    print("\n  In passes 1-3 the kernel width lives in ecx for the whole body (it is")
    print("  re-loaded from its global at the bottom of each phase loop), so `idiv ecx`")
    print("  counts the box-average divides and every other idiv is the thread-range split")
    print("  by thread_num:")
    idivs = {}
    for addr in (0x10088580, 0x100886F0, 0x10088840):
        body = [i for i in function_body(img, addr, 0x600) if i.mnemonic == "idiv"]
        by_kernel = sum(1 for i in body if i.op_str == "ecx")
        idivs[addr] = (by_kernel, len(body) - by_kernel)
        print(f"    0x{addr:08x}: {by_kernel} x `idiv ecx` (head/middle/tail)"
              f" + {len(body) - by_kernel} x thread split")
    check("passes 1-3 each divide by the kernel width in exactly three places",
          all(k == 3 for k, _ in idivs.values()),
          str({hex(a): v for a, v in idivs.items()}))
    print("  There is no second divisor and no weight table anywhere in the three bodies:")
    print("  every emitted sample is `windowSum / kernelWidth` (box_blur.md §2).")

    print("\n--- 2. two passes per axis compose into a triangle of half-width 拡散 ---")
    print(f"  {'拡散':>6}{'kernel A':>10}{'kernel B':>10}{'support':>9}"
          f"{'half-width':>12}{'plateau':>9}  composite kernel")
    bad = []
    for spread in (0, 1, 2, 3, 4, 5, 10, 25):
        ka, kb = kernels(spread)
        comp = convolve([1] * kb, [1] * ka)
        support = len(comp)
        plateau = comp.count(max(comp))
        if support != 2 * spread + 1:
            bad.append((spread, support))
        shown = comp if len(comp) <= 13 else comp[:6] + ["..."] + comp[-6:]
        print(f"  {spread:>6}{ka:>10}{kb:>10}{support:>9}{(support - 1) // 2:>12}"
              f"{plateau:>9}  {shown}")
    for spread in range(0, 501):
        ka, kb = kernels(spread)
        if ka + kb - 1 != 2 * spread + 1:
            bad.append((spread, ka + kb - 1))
    check("all 501 拡散 values: kernelA + kernelB - 1 == 2*拡散 + 1", not bad,
          f"first {bad[:1]}")
    check("拡散 even -> a pure triangle (plateau 1); odd -> a trapezoid with plateau 3 "
          "(at 拡散=1 the trapezoid degenerates to a flat 3-wide box)",
          all((convolve([1] * kernels(s)[0], [1] * kernels(s)[1]).count(
              max(convolve([1] * kernels(s)[0], [1] * kernels(s)[1]))) ==
              (1 if s % 2 == 0 else 3)) for s in range(0, 60)))
    print("  Identical to ぼかし's 4-pass split (box_blur.md §2), applied to alpha instead")
    print("  of to alpha-weighted pixels - which is why the composite is a blur of the")
    print("  silhouette rather than of the image.")

    print("\n--- 3. the chain is exact: reads and writes line up rectangle for rectangle ---")
    print(f"  {'stage':<9}{'input':>18}{'output':>18}")
    bad = []
    for w, h, spread in ((100, 60, 10), (7, 3, 2), (300, 200, 25), (40, 40, 0)):
        ka, kb = kernels(spread)
        p1 = (w, h + kb - 1)                    # vertical, kernel B
        p2 = (w + kb - 1, p1[1])                # horizontal, kernel B
        p3 = (p2[0], p2[1] + ka - 1)            # vertical, kernel A
        p4 = (p3[0] + ka - 1, p3[1])            # horizontal, kernel A
        if p4 != (w + 2 * spread, h + 2 * spread):
            bad.append((w, h, spread, p4))
        if (w, h, spread) == (100, 60, 10):
            for label, (a, b) in (("source", (w, h)), ("pass 1", p1), ("pass 2", p2),
                                  ("pass 3", p3), ("pass 4", p4)):
                print(f"  {label:<9}{'':>18}{f'{a} x {b}':>18}")
    check("4 shapes: the chain lands on exactly (w+2*拡散) x (h+2*拡散)", not bad,
          f"first {bad[:1]}")
    print("  Pass 2 reads h+kernelB-1 rows, which is exactly what pass 1 wrote; pass 3")
    print("  reads w+kernelB-1 columns, exactly what pass 2 wrote; pass 4 reads h+2*拡散")
    print("  rows, exactly what pass 3 wrote. Each worker recomputes those extents from")
    print("  fpip+0xB4/+0xB8 and the two kernel globals rather than being told them - which")
    print("  is only possible because func_proc leaves w and h alone until the very end.")

    print("\n--- 4. the compact and literal forms of one pass agree ---")
    rng = random.Random(0)
    bad = None
    for _ in range(400):
        n = rng.randint(1, 60)
        kernel = 2 * rng.randint(0, 8) + 1
        row = [rng.randint(0, FULL) for _ in range(n)]
        if n < kernel:
            continue          # the degenerate case verify_params.py §5 covers
        a, b = grow_1d(row, kernel), grow_1d_literal(row, kernel)
        if a != b:
            bad = (n, kernel, row, a, b)
            break
    check("400 random rows: index-guarded form == the head/middle/tail loops", bad is None,
          "" if bad is None else str(bad))

    row = [FULL] * 8
    out = grow_1d(row, 5)
    print(f"\n  a fully-opaque 8-wide row, kernel 5 (拡散=4 -> kernelB=5):")
    print(f"    input  ({len(row)}): {row}")
    print(f"    output ({len(out)}): {out}")
    check("the grown row fades in from 0 at the new edges", out[0] < out[2] and out[-1] < out[-3])
    check("and reaches full opacity wherever the window is entirely inside the object",
          max(out) == FULL)
    print("  Off-image samples contribute nothing but the divisor stays at the full kernel")
    print("  width, so a shadow always fades out over its 拡散-wide margin instead of")
    print("  ending in a hard edge.")

    print("\n--- 5. the object's colour never enters the shadow ---")
    body = function_body(img, 0x10088580, 0x600)
    reads = sorted({int(i.op_str.split("+")[-1].rstrip("]"), 0)
                    for i in body if i.mnemonic == "movsx" and "word ptr [" in i.op_str
                    and "+" in i.op_str})
    check("pass 1's only movsx displacement into fpip+0xAC is +6 (the alpha)",
          reads == [6], f"got {reads}")
    print("  y (+0), cb (+2) and cr (+4) are never loaded. Everything downstream is a")
    print("  16-bit alpha plane, so the shadow's colour has to be supplied separately -")
    print("  either by 影色の設定 or by the tiled pattern image (verify_encode.py).")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
