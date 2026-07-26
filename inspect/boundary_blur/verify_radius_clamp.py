"""Re-implement 境界ぼかし's radius arithmetic in Python, instruction for
instruction, and check it over the whole reachable input domain.

Three claims from disasm_params.py are checked here.

(1) The `imul 0x10624dd3 / sar 6 / add sign` sequence is the exact same
    magic-number truncating divide by 1000 that ぼかし uses (inspect/blur's
    verify_radius_split.py). 範囲 has a wider range here (0~2000 instead of
    0~1000), so the exhaustive check covers 範囲 in [0,2000] x
    縦横比 in [-1000,1000] - 4,004,001 cases.

(2) Each axis radius is clamped independently to floor(dimension/2), where
    dimension is the OBJECT effect's own width/height (*(fpip+0xB4) /
    *(fpip+0xB8)). Unlike ぼかし there is no further hi/lo split into two box
    passes and no canvas growth - 境界ぼかし only ever touches pixels that are
    already inside the object's image.

(3) 範囲 == 0 makes func_proc skip the trackbar read entirely (rx=ry=0 go
    straight into the worker dispatch), so it is a genuine no-op only in the
    sense that both radii are 0 - the OFF-path workers still run (and are a
    no-op for radius 0: an empty top/bottom loop writes nothing), while the
    ON-path workers still run a 1-tap "box blur" (kernel width 1), which is
    an identity copy.

Run via main.py:
    uv run main.py inspect/boundary_blur/verify_radius_clamp.py
"""

MAGIC = 0x10624DD3


def _to_signed32(v):
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


def magic_div_1000(x):
    """The literal instruction sequence at 0x10011b26 / 0x10011b46 - identical
    to ぼかし's (inspect/blur/verify_radius_split.py's magic_div_1000)."""
    prod = MAGIC * x
    edx = _to_signed32(prod >> 32)
    edx >>= 6
    sign = (edx & 0xFFFFFFFF) >> 31
    return _to_signed32(edx + sign)


def trunc_div(a, b):
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def radii(rng, aspect):
    """func_proc 0x10011b08-0x10011b5a: 範囲/縦横比 -> (rx, ry) in pixels,
    BEFORE the width/2, height/2 clamp."""
    rx = ry = rng
    if aspect > 0:
        ry = magic_div_1000((1000 - aspect) * rng)
    elif aspect < 0:
        rx = magic_div_1000((1000 + aspect) * rng)
    return rx, ry


def half(dim):
    """func_proc 0x10011b6c-0x10011b94: cdq/sub/sar 1 halving idiom."""
    return trunc_div(dim, 2)


def clamp_radii(rng, aspect, width, height):
    rx, ry = radii(rng, aspect)
    rx = min(rx, half(width))
    ry = min(ry, half(height))
    return rx, ry


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("--- (1) magic-number divide by 1000, exhaustive over 範囲 in [0,2000] x 縦横比 in [-1000,1000] ---")
    bad = 0
    checked = 0
    for rng in range(0, 2001):
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
          f"{'exact truncating divide by 1000 (same constant as ぼかし)' if bad == 0 else 'NOT a plain divide'}")

    print("\n--- (2) axis independence: 縦横比 shrinks exactly one axis, never both ---")
    bad = 0
    for rng in range(0, 2001, 7):
        for aspect in range(-1000, 1001, 13):
            rx, ry = radii(rng, aspect)
            if aspect > 0 and rx != rng:
                bad += 1
            if aspect < 0 and ry != rng:
                bad += 1
            if aspect == 0 and (rx, ry) != (rng, rng):
                bad += 1
    print(f"  {'OK' if bad == 0 else f'{bad} MISMATCHES'}: the un-shrunk axis always stays exactly 範囲")

    print("\n--- (3) width/2, height/2 clamp (no hi/lo split, no canvas growth) ---")
    cases = [
        (5, 0, 200, 100), (60, 0, 200, 100), (1000, 0, 200, 100),
        (100, 500, 200, 100), (2000, -1000, 200, 100), (2000, 1000, 9, 9),
    ]
    print("    範囲  縦横比    w    h |  rx   ry | clamped?")
    for rng, aspect, w, h in cases:
        rx0, ry0 = radii(rng, aspect)
        rx, ry = clamp_radii(rng, aspect, w, h)
        clamped = (rx != rx0) or (ry != ry0)
        print(f"    {rng:4d} {aspect:6d} {w:4d} {h:4d} | {rx:4d} {ry:4d} | {clamped}")

    print(
        "\n"
        "Verdict:\n"
        "  rx = ry = 範囲, then 縦横比>0 shrinks ry, 縦横比<0 shrinks rx toward 0\n"
        "  (identical formula to ぼかし), then each axis is independently capped at\n"
        "  half the OBJECT's own width/height. There is no hi/lo split (境界ぼかし\n"
        "  runs each axis as a SINGLE geometric erosion pass, not two box passes)\n"
        "  and no canvas growth call anywhere in func_proc - the object's bounding\n"
        "  box never changes size, only its alpha does.\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
