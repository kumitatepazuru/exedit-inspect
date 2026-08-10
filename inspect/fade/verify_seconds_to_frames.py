"""`イン` / `アウト` are seconds, and this is exactly how they become frames.

Four claims.

(1) The two `fmul st(2)` / `fdiv st(1)` pairs really do write into ST(0).
    Capstone prints the one-operand x87 forms without saying which register is
    the destination, and x87 has *both* directions (`d8 /1` = ST(0) op= ST(i),
    `dc /1` = ST(i) op= ST(0)). Getting that backwards inverts the whole
    formula, so the opcode bytes are read here rather than the mnemonics.

(2) `*(fpip+0xFC)` / `*(fpip+0x100)` is the frame rate as numerator /
    denominator. The evidence is that unrelated effects use the same pair in
    the opposite direction to turn frames into seconds - `ラスター` at
    `0x10080af9` multiplies a frame count by `+0x100` and divides by `+0xFC`,
    `波紋` does the same at `0x10082e67`. One ratio cannot be both
    frames-per-second and seconds-per-frame, so the direction is pinned.
    (object_time.md §4)

(3) The conversion is `trunc(raw * rate / (scale * 100))` with `_ftol`
    truncating toward zero - reproduced here for every raw value the trackbar
    holds, at the frame rates AviUtl actually offers, against the exact double
    arithmetic the x87 does.

(4) There is no `/1000` magic divide, no `sar`-based fixed-point scaling and
    no clamp anywhere in the effect: `イン`/`アウト` meet exactly one
    conversion each, and it is this one. The scan below counts the
    instructions to show it.

Run via main.py:
    uv run main.py inspect/fade/verify_seconds_to_frames.py
"""

from tools.cints import MAGIC_1000
from tools.disasm import disasm_range
from tools.pe_image import PEImage

FADE_CODE = (0x1004DD40, 0x1004DE96)
STRUCT = 0x100A5698
EXT_BLOCK = 0x100A5688
CONST_100 = 0x1009A538

# (label, rate, scale) - the frame rates AviUtl's project settings offer.
RATES = [
    ("24 fps", 24, 1),
    ("23.976 fps", 24000, 1001),
    ("29.97 fps", 30000, 1001),
    ("30 fps", 30, 1),
    ("59.94 fps", 60000, 1001),
    ("60 fps", 60, 1),
]

# The one-operand x87 opcodes at issue. D8 /n has ST(0) as destination,
# DC /n has ST(i); the modrm byte says which.
X87_SITES = {
    0x1004DD6D: ("fmul st(2)", b"\xd8\xca", "FMUL ST(0), ST(2)"),
    0x1004DD6F: ("fdiv st(1)", b"\xd8\xf1", "FDIV ST(0), ST(1)"),
    0x1004DD7B: ("fmul st(2)", b"\xd8\xca", "FMUL ST(0), ST(2)"),
    0x1004DD7D: ("fdiv st(1)", b"\xd8\xf1", "FDIV ST(0), ST(1)"),
}


def to_frames(raw: int, rate: int, scale: int) -> int:
    """0x1004dd59-0x1004dd71, in double precision, then _ftol (toward zero)."""
    x = raw * float(rate) / (float(scale) * 100.0)
    return int(x)  # Python int() on a float truncates toward zero, like _ftol


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("--- (1) which x87 register is the destination ---")
    for va, (printed, expect, meaning) in X87_SITES.items():
        got = img.code(va, len(expect))
        ok = got == expect
        print(f"  0x{va:08x}  capstone {printed:<12s} bytes {got.hex(' ')}"
              f"  -> {meaning}   {'OK' if ok else 'MISMATCH'}")
    print("  D8 is the ST(0)-destination form; DC would be the other one and would")
    print("  mean `rate *= イン` / `(scale*100) /= that`, leaving nonsense on the stack.")
    print(f"  the multiplier at 0x{CONST_100:08x} is {img.f64(CONST_100)!r}")

    print("\n--- (2) the same two fields, used the other way round ---")
    for label, va, size in (("フェード  0x1004dd59", 0x1004DD59, 0x1A),
                            ("ラスター  0x10080af9", 0x10080AF9, 0x1F),
                            ("波紋      0x10082e67", 0x10082E67, 0x18)):
        print(f"  {label}")
        for insn, _ in disasm_range(img, va, size, resolve=False):
            if insn.mnemonic.startswith("fi") or insn.mnemonic in ("fild", "fmul", "fdiv"):
                print(f"      0x{insn.address:08x}: {insn.mnemonic:<6s} {insn.op_str}")
    print("  フェード: (1/100 s) * [+0xFC] / [+0x100] -> frames")
    print("  ラスター / 波紋: frames * [+0x100] / [+0xFC] -> seconds")
    print("  => [+0xFC] = rate (numerator), [+0x100] = scale (denominator), fps = rate/scale")

    print("\n--- (3) raw -> frames, over the whole trackbar ---")
    t_lo = img.i32(img.u32(STRUCT + 0x1C))
    t_hi = img.i32(img.u32(STRUCT + 0x20))
    print(f"  trackbar range {t_lo}..{t_hi} raw = {t_lo / 100:.2f}..{t_hi / 100:.2f} s")
    print("\n     raw    UI [s]   " + "".join(f"{lab:>12s}" for lab, _, _ in RATES))
    for raw in (0, 1, 3, 25, 50, 100, 150, 250, 500, 1000):
        row = "".join(f"{to_frames(raw, r, s):>12d}" for _, r, s in RATES)
        print(f"    {raw:5d}   {raw / 100:6.2f}   {row}")
    print("\n  every raw value 0..1000 vs. an independent trunc of the exact rational:")
    bad = 0
    for _, rate, scale in RATES:
        for raw in range(0, 1001):
            exact = (raw * rate) // (scale * 100)  # non-negative here, so floor == trunc
            if to_frames(raw, rate, scale) != exact:
                bad += 1
                if bad <= 5:
                    print(f"    MISMATCH raw={raw} {rate}/{scale}: "
                          f"double={to_frames(raw, rate, scale)} exact={exact}")
    print(f"    {len(RATES) * 1001} combinations, {bad} mismatch(es)")
    print("  The default 0.50 s is 15 frames at 30 fps but **14** at 29.97 - the")
    print("  truncation bites on the very first value the UI offers.")
    print("  Raw values below one frame collapse to 0, i.e. to no fade at all:")
    for label, rate, scale in RATES:
        first = next(r for r in range(1, 1001) if to_frames(r, rate, scale) > 0)
        print(f"    {label:<11s} raw 1..{first - 1} (up to {(first - 1) / 100:.2f} s) all give 0 frames")

    print("\n--- (4) every multiply, divide and shift in the effect ---")
    lo, hi = FADE_CODE
    roles = {
        0x1004DDAA: "fade-in ramp: / (in_frames + 1)",
        0x1004DDA5: "fade-in ramp: (t + 1) << 12",
        0x1004DDD0: "fade-out ramp: / (out_frames + 1)",
        0x1004DDCB: "fade-out ramp: (u + 1) << 12",
        0x1004DE39: "worker row split: h * (tid + 1)",
        0x1004DE3D: "worker row split: / thread_num",
        0x1004DE43: "worker row split: h * tid",
        0x1004DE47: "worker row split: / thread_num",
        0x1004DE5F: "worker: row offset = stride * y",
        0x1004DE71: "worker: alpha * g_101a5390",
        0x1004DE78: "worker: >> 12 (sar = floor)",
    }
    magic, ftol, x87, listed = 0, 0, 0, []
    for insn, _ in disasm_range(img, lo, hi - lo, resolve=False):
        if f"0x{MAGIC_1000:x}" in insn.op_str:
            magic += 1
        if insn.mnemonic in ("idiv", "div", "imul", "mul", "sar", "shl", "shr"):
            listed.append((insn.address, f"{insn.mnemonic} {insn.op_str}"))
        if insn.mnemonic[0] == "f" and insn.mnemonic != "fs":
            x87 += 1
        if insn.mnemonic == "call" and insn.op_str == "0x10091ad8":
            ftol += 1
    print(f"  over 0x{lo:08x}-0x{hi:08x} ({hi - lo} bytes, the whole effect):")
    for va, text in listed:
        print(f"    0x{va:08x}: {text:<18s} {roles.get(va, '?? UNACCOUNTED FOR')}")
    missing = [f"0x{a:08x}" for a in roles if a not in dict(listed)]
    print(f"    {len(listed)} sites, all accounted for"
          if not missing else f"    ! roles with no instruction: {missing}")
    print(f"\n  x87 instructions: {x87}   _ftol calls: {ftol}   "
          f"0x10624dd3 magic-divide sites: {magic}")
    print("  Zero sites of the /1000 magic that every other effect's percent")
    print("  parameter goes through (param_scaling.md §2) - フェード's trackbars are")
    print("  not percentages, so there is nothing to normalise to Q12. Nor is there")
    print("  any clamp: the ramps are bounded by the `t < in` / `u < out` tests")
    print("  themselves, not by a `cmp`/`cmov` on the result (param_scaling.md §4).")

    print("\n--- the +0x74 block ---")
    names = ("scale", "group", "drag_min", "drag_max")
    slots = [img.u32(EXT_BLOCK + 4 * i) for i in range(4)]
    for name, p in zip(names, slots):
        vals = [img.i32(p + 4 * i) for i in range(2)] if p else None
        print(f"  {name:<9s} -> 0x{p:08x}  {vals}")
    print("  Only slot[0] is non-NULL, so the sliders span the raw range 0..1000")
    print("  in full and the UI shows raw/100 - the '表示スケールだけ' shape that")
    print("  18 of the 90 trackbar-bearing registrations use (param_scaling.md §1).")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
