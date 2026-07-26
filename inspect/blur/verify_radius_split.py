"""Re-implement ぼかし's radius arithmetic in Python, instruction for
instruction, and check it over the whole reachable input domain.

Two separate claims from disasm_params.py are checked here.

(1) The `imul 0x10624dd3 / sar 6 / add sign` sequence really is a truncating
    signed divide by 1000. The magic constant is only an approximation of
    1/1000 (0.0010000000002037268), so "close enough" is not an argument -
    this brute-forces every product the filter can actually form,
    範囲 in [0,1000] x 縦横比 in [-1000,1000], i.e. 2,002,001 cases.

(2) Splitting a radius r into (r - r//2, r//2) and running two box passes
    gives a kernel whose total support is exactly +-r, so 範囲 is the true
    pixel radius of the blur - not 2x it. The two boxes convolve into a
    trapezoid (a triangle when r is even), which is why ぼかし looks smooth
    even though every individual pass is an unweighted box average.

Run via main.py:
    uv run main.py inspect/blur/verify_radius_split.py
"""

MAGIC = 0x10624DD3


def _to_signed32(v):
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


def magic_div_1000(x):
    """The literal instruction sequence at 0x1000e31f / 0x1000e33f.

        mov  eax, 0x10624dd3
        imul ecx            ; edx:eax = (signed)eax * (signed)ecx
        sar  edx, 6
        mov  eax, edx / shr eax, 31 / add edx, eax
    """
    prod = MAGIC * x                      # imul: full 64-bit signed product
    edx = _to_signed32(prod >> 32)        # high half
    edx >>= 6                             # sar edx, 6  (arithmetic)
    sign = (edx & 0xFFFFFFFF) >> 31       # shr eax, 31
    return _to_signed32(edx + sign)


def trunc_div(a, b):
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def radii(rng, aspect):
    """func_proc 0x1000e2f9-0x1000e353: 範囲/縦横比 -> (rx, ry) in pixels."""
    rx = ry = rng
    if aspect > 0:
        ry = magic_div_1000((1000 - aspect) * rng)
    elif aspect < 0:
        rx = magic_div_1000((1000 + aspect) * rng)
    return rx, ry


def split(r):
    """func_proc 0x1000e3a3-0x1000e3c3: r -> (hi, lo) for the two box passes."""
    lo = trunc_div(r, 2)
    return r - lo, lo


def box(radius):
    """One unweighted box pass as a kernel: 2*radius+1 taps of weight 1."""
    return [1] * (2 * radius + 1)


def convolve(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] += x * y
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("--- (1) magic-number divide by 1000 over every reachable product ---")
    bad = 0
    checked = 0
    for rng in range(0, 1001):
        for aspect in range(-1000, 1001):
            if aspect > 0:
                x = (1000 - aspect) * rng
            elif aspect < 0:
                x = (1000 + aspect) * rng
            else:
                continue
            checked += 1
            if magic_div_1000(x) != trunc_div(x, 1000):
                bad += 1
                if bad <= 5:
                    print(f"  MISMATCH 範囲={rng} 縦横比={aspect}: "
                          f"magic={magic_div_1000(x)} trunc={trunc_div(x, 1000)}")
    print(f"  checked {checked} products, {bad} mismatch(es) -> "
          f"{'exact truncating divide by 1000' if bad == 0 else 'NOT a plain divide'}")

    print("\n--- (2) radius split and the resulting kernel ---")
    bad = 0
    for r in range(0, 1001):
        hi, lo = split(r)
        kernel = convolve(box(hi), box(lo))
        support = (len(kernel) - 1) // 2
        if hi + lo != r or support != r:
            bad += 1
            if bad <= 5:
                print(f"  MISMATCH r={r}: hi={hi} lo={lo} support={support}")
    print(f"  r = 0..1000: hi+lo == r and kernel support == r for all "
          f"({bad} mismatch(es))")

    print("\n  example kernels (weights of the two chained box passes):")
    for r in (1, 2, 3, 4, 6):
        hi, lo = split(r)
        k = convolve(box(hi), box(lo))
        shape = "triangle" if r % 2 == 0 else "trapezoid (flat top of 3)"
        print(f"    範囲={r}: box({2 * hi + 1}) * box({2 * lo + 1}) = {k}   {shape}")

    print("\n--- (3) reference table: 範囲/縦横比 -> the four box passes ---")
    print("    範囲  縦横比 |  rx   ry | pass1 V(ry_hi) pass2 H(rx_hi) "
          "pass3 V(ry_lo) pass4 H(rx_lo)")
    for rng, aspect in ((5, 0), (5, 500), (5, -500), (5, 1000), (5, -1000),
                        (20, 0), (20, 250), (100, 0), (100, -750), (1000, 0)):
        rx, ry = radii(rng, aspect)
        rx_hi, rx_lo = split(rx)
        ry_hi, ry_lo = split(ry)
        print(f"    {rng:4d} {aspect:6d} | {rx:4d} {ry:4d} |"
              f" {ry_hi:13d} {rx_hi:13d} {ry_lo:13d} {rx_lo:13d}")

    print(
        "\n"
        "Verdict:\n"
        "  範囲 is the blur radius in pixels of the *unshrunk* axis, and the\n"
        "  effective kernel reaches exactly that far - a pass with radius 0 is\n"
        "  skipped entirely by func_proc, so 範囲=1 is a plain 3x3 box and only\n"
        "  範囲>=2 gets the two-pass triangular shape.\n"
        "  縦横比 shrinks one axis toward 0; at +-1000 that axis reaches 0 and\n"
        "  the blur becomes purely horizontal (+1000) or purely vertical (-1000).\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
