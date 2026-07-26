"""Numerically re-verify the 強さ/しきい値 conversion and consumption math.

disasm_params.py established the instruction sequence for 強さ/しきい値 by
reading capstone output and eyeballing what a "multiply by 0x10624dd3, sar 6,
sign-fix" sequence probably does (a magic-number division by 1000). That's a
reasonable read but it was never checked against a real execution of those
exact instructions - "probably divides by 1000" and "actually divides by
1000, with these exact rounding semantics" are different claims. This script
closes that gap two ways, independent of angr's decompiler:

  1. re-implements the literal instruction sequence from func_proc
     (0x10053115-0x1005312d for 強さ, 0x10053161-0x1005317b for しきい値,
     see disasm_params.py's dump of func_proc) in Python with real 32-bit
     wraparound arithmetic, and checks it against plain integer division for
     every raw trackbar value 0..2000 - not just a couple of samples, so any
     off-by-one or rounding-mode mistake would show up somewhere in the
     range;
  2. re-implements the consumption side (the per-pixel branch in
     sub_100533c0, see disasm_params.py/decompile_glow.py) and runs it
     through the clamp/overflow edge cases (raw=0, the default 1000, and the
     max 2000) to confirm the "strength > 100% raises a flat floor, not just
     a multiplier" reading actually falls out of the arithmetic rather than
     being an assumption.

Takeaway that corrects the first draft of README.md: the magic-number
division truncates toward zero (no rounding bias), unlike the pow()-based
diffusion radius loop in func_proc which does add an explicit 0.5 before
truncating. The two are easy to conflate but are not the same operation.

Run via main.py:
    uv run main.py inspect/glow/verify_strength_threshold.py
"""

MAGIC = 0x10624DD3


def _to_signed32(x: int) -> int:
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x >= 0x80000000 else x


def magic_divide_by_1000(raw: int) -> int:
    """Re-implements: shl ecx,0xc / mov eax,MAGIC / imul ecx / sar edx,6 /
    mov ecx,edx / shr ecx,0x1f / add edx,ecx  (see 0x10053115.. in disasm_params.py)."""
    ecx = _to_signed32(raw << 12)
    magic_signed = _to_signed32(MAGIC)
    product = magic_signed * ecx  # true integer product, no overflow in Python
    edx = _to_signed32((product & 0xFFFFFFFFFFFFFFFF) >> 32)
    edx >>= 6  # arithmetic shift (Python's >> on an int is already arithmetic)
    sign_bit = (edx & 0xFFFFFFFF) >> 31
    return edx + sign_bit


def strength_gain_and_overflow(raw_strength: int) -> tuple[int, int]:
    """Re-implements the clamp-to-4096-with-overflow logic at 0x10053139-0x1005315b."""
    unclamped = magic_divide_by_1000(raw_strength)
    if unclamped <= 0x1000:
        return unclamped, 0
    return 0x1000, unclamped - 0x1000


def extract_brightness(y: int, threshold_fixed: int, gain: int, overflow: int) -> int:
    """Re-implements the per-pixel branch in sub_100533c0 (0x10053433-0x10053465)."""
    diff = y - threshold_fixed
    if diff < 0:
        return 0
    v = (diff * gain) >> 12
    v += overflow
    return min(v, 0x1000)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    print("--- checking magic_divide_by_1000 against plain integer division, raw=0..2000 ---")
    mismatches = []
    for raw in range(0, 2001):
        got = magic_divide_by_1000(raw)
        want = (raw * 4096) // 1000  # truncating division; raw is always >= 0 here
        if got != want:
            mismatches.append((raw, got, want))
    if mismatches:
        print(f"MISMATCH on {len(mismatches)} values, first few: {mismatches[:10]}")
    else:
        print("OK: matches raw*4096//1000 (truncating, NOT rounding) for all 2001 values.")

    print("\n--- strength gain/overflow at representative raw values ---")
    for raw in [0, 1, 500, 999, 1000, 1001, 1500, 2000]:
        gain, overflow = strength_gain_and_overflow(raw)
        print(f"  raw={raw:5d}  ->  gain={gain:5d}  overflow={overflow:5d}")

    print("\n--- default settings sanity check: raw強さ=1000, rawしきい値=800 ---")
    gain, overflow = strength_gain_and_overflow(1000)
    threshold_fixed = magic_divide_by_1000(800)
    print(f"  gain={gain} overflow={overflow} threshold_fixed={threshold_fixed}")
    for y in [0, 800, 801, 3276, 3277, 4096]:
        b = extract_brightness(y, threshold_fixed, gain, overflow)
        print(f"  y={y:5d}  threshold={threshold_fixed}  -> brightness={b}")

    print("\n--- strength cranked to raw=2000 (200%): does the overflow saturate immediately above threshold? ---")
    gain, overflow = strength_gain_and_overflow(2000)
    threshold_fixed = magic_divide_by_1000(800)
    print(f"  gain={gain} overflow={overflow} threshold_fixed={threshold_fixed}")
    for y in [threshold_fixed, threshold_fixed + 1, threshold_fixed + 10, 4096]:
        b = extract_brightness(y, threshold_fixed, gain, overflow)
        print(f"  y={y:5d}  -> brightness={b}  (4096 = fully saturated)")


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
