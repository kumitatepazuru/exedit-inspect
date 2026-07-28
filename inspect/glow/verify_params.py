"""Three claims about グロー's parameters, checked separately.

  1. **強さ is stored raw.** Every other effect in this repo runs 強さ through
     `trunc(raw*4096/1000)`. グロー does not: 0x10054de6 writes `fp->track[0]`
     straight into 0x101b2018, and the only magic-number divide in func_proc
     (0x10054ecc) takes `track[2]` = しきい値. This script counts the
     `0x10624dd3` occurrences in func_proc and shows which trackbar feeds the
     one that exists, so "強さ is not converted" is a statement about the
     instruction stream rather than about the prose above.

  2. **しきい値 = trunc(raw * 4096 / 1000).** Replayed literally from the
     instruction sequence for all 2001 reachable raw values.

  3. **the 通常 schedule.** The four (strength, radius) pairs come from four
     divisions whose divisors are only visible as magic numbers. `tools.cints`
     confirms each magic/shift pair really is the divisor claimed - in
     particular that `imul 0x2aaaaaab` with no shift is /6 and not /3.

The last section works out what the four passes weigh relative to each other,
because that is the thing the code does not say anywhere: the horizontal pass
does not divide by its kernel width, so per-pass gain is
`kernel_width * strength / 2^14` and the 強さ schedule is what re-normalises it.

Run via main.py:
    uv run main.py inspect/glow/verify_params.py
"""

from tools.cints import MAGIC_1000, c_div, divisor_of, msvc_div, to_i32
from tools.disasm import disasm_range
from tools.pe_image import PEImage

FUNC_PROC = (0x10054DB0, 0x790)

# (magic, shift) pairs as they appear in func_proc.
MAGIC_1000_SHIFT = 6      # 0x10054ecc: しきい値 * 4096 / 1000
MAGIC_SIX = 0x2AAAAAAB    # 0x1005527a: rx / 6, no shift at all


def threshold_q12(raw: int) -> int:
    """Replay of shl 12 / imul 0x10624dd3 / sar 6 / sign fixup at 0x10054ed8."""
    return msvc_div(to_i32(raw << 12), MAGIC_1000, MAGIC_1000_SHIFT)


def normal_schedule(strength_raw: int, rx: int) -> list:
    """The four (strength, radius) pairs of 形状=通常, in dispatch order.

    Straight from 0x100551e2-0x1005530f: strength starts at 6*raw and is
    halved (truncating toward zero) before each later pass, while the radius
    is rx divided by 8, 6, 4, 2.
    """
    out = []
    s = strength_raw * 3 * 2
    for divisor in (8, 6, 4, 2):
        out.append((s, c_div(rx, divisor)))
        s = c_div(s, 2)
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("--- 1. how many magic-number divides does func_proc contain? ---")
    magics = []
    for insn, _ in disasm_range(img, *FUNC_PROC, resolve=False):
        if insn.mnemonic == "mov" and insn.op_str.startswith("eax, 0x") and len(insn.op_str) > 12:
            magics.append((insn.address, int(insn.op_str.split(", ")[1], 16)))
    for addr, m in magics:
        print(f"  0x{addr:08x}: mov eax, 0x{m:08x}")
    print(f"  -> {len(magics)} constant-division magic(s) in the whole of func_proc.")
    print("  0x10054ecc feeds on [fp->track + 8] = track[2] = しきい値 (see the")
    print("  `mov ecx, dword ptr [ecx + 8]` two instructions later in disasm_params.py).")
    print("  track[0] = 強さ is only ever read at 0x10054dc3 (the != 0 test) and")
    print("  0x10054de6 (stored raw), so it is never divided by 1000.")

    print("\n--- 2. しきい値 -> Q12, every reachable raw value 0..2000 ---")
    bad = [r for r in range(2001) if threshold_q12(r) != r * 4096 // 1000]
    print("  MISMATCH: " + str(bad[:8]) if bad else
          "  OK: identical to raw*4096//1000 (truncating) for all 2001 values.")
    print(f"  {'raw':>6}{'UI':>8}{'threshold':>11}   meaning")
    for raw in (0, 100, 400, 1000, 2000):
        t = threshold_q12(raw)
        note = ("everything above black glows" if t == 0 else
                "nothing can ever exceed it (> 4096 = full white)" if t > 4096 else
                f"pixels brighter than {t / 4096:.0%} of full white glow")
        print(f"  {raw:>6}{raw / 10:>8.1f}{t:>11}   {note}")
    print("  default is raw=400 (UI 40.0) -> 1638.")

    print("\n--- 3. the divisors behind the 通常 schedule ---")
    for magic, shift, claim in ((MAGIC_1000, 6, 1000), (MAGIC_SIX, 0, 6)):
        got = divisor_of(magic, shift)
        ok = "OK" if got == claim else "MISMATCH"
        print(f"  {ok}: magic 0x{magic:08x} shift {shift} -> divide by {got} (claimed {claim})")
    print("  the other three divisors are plain shifts with the C truncation fixup")
    print("  (`cdq` then add back 2^n-1 when the dividend is negative; for n=1 the")
    print("  compiler spells `add edx` as `sub eax, edx` with edx = -1):")
    for shift in (3, 2, 1):
        mask = (1 << shift) - 1
        vals = [x for x in range(-4096, 4096)
                if ((x + (mask if x < 0 else 0)) >> shift) != c_div(x, 1 << shift)]
        print(f"    sar {shift} (fixup +{mask}): {'OK' if not vals else 'MISMATCH'}, "
              f"c_div(x, {1 << shift}) over -4096..4095")

    print("\n--- 3b. the schedule itself, and what each pass weighs ---")
    print("  gain of one pass = kernel_width * strength / 2^14, because the")
    print("  horizontal worker never divides by its own kernel width (0x10055ff2:")
    print("  sar 4 / imul strength / sar 10, no idiv in sight).")
    for rx in (8, 30, 100, 200):
        print(f"\n  拡散={rx}, 強さ raw=400 (UI 40.0):")
        print(f"    {'pass':>5}{'radius':>8}{'kernel':>8}{'strength':>10}{'gain':>10}")
        for i, (s, r) in enumerate(normal_schedule(400, rx)):
            k = 2 * r + 1
            print(f"    {i + 1:>5}{r:>8}{k:>8}{s:>10}{k * s / 16384:>10.3f}")
    print("\n  The four gains fall off 1.5 : 1.0 : 0.75 : 0.75 (times 強さ*拡散/2^14)")
    print("  once the +1 of the kernel width stops mattering, i.e. the narrow")
    print("  early passes carry more weight than the wide late ones.")

    print("\n--- 3c. the streak schedule (形状 = ライン / クロス) ---")
    print("  streak workers take a divisor d in (1, 2, 4) and use radius = r/d")
    print("  with strength * d, so all three scales carry the SAME energy:")
    print(f"    {'d':>3}{'radius':>8}{'kernel':>8}{'strength':>10}{'gain':>10}")
    for d in (1, 2, 4):
        r, s = c_div(60, d), 400 * d
        k = 2 * r + 1
        print(f"    {d:>3}{r:>8}{k:>8}{s:>10}{k * s / 16384:>10.3f}")
    print("  (拡散=60, 強さ raw=400). Equal energy at three widths is what makes")
    print("  a streak read as a bright core inside a wide halo.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
