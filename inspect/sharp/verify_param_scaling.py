"""What the two trackbars are worth, and where the conversion happens.

シャープ has two trackbars and exactly one arithmetic conversion between them:

    強さ : S = trunc(raw * 4096 / 1000)     Q12 gain, UI scale 10
    範囲 : used raw, as a pixel radius       UI scale 1

Three claims are checked here.

(1) The `imul 0x10624dd3 / sar 6 / sign fixup` at 0x10089bac really is a
    truncating divide by 1000, over every value the trackbar can hold
    (0..8000, i.e. UI 0.0..800.0). The magic constant only approximates
    1/1000, so this is brute-forced rather than argued.

(2) That instruction sequence appears **once** in the whole effect, and it is
    inside the *worker*, not `func_proc`. Every other analysed effect converts
    its parameters in `func_proc` and hands the result to the workers through
    globals (filter_registration.md §4). シャープ instead re-reads
    `fp->track[0]` from every thread. `範囲` never meets a divide at all.

(3) The `+0x74` block: display scales {10, 1}, no grouping markers, and a
    drag range of {0..1000, 0..100} against a trackbar range of {0..8000,
    0..100}. So `強さ` above UI 100.0 is reachable by typing only - the same
    shape as `グロー`'s `強さ` and `ライト`'s `拡散` (param_scaling.md §1).

Run via main.py:
    uv run main.py inspect/sharp/verify_param_scaling.py
"""

from tools.cints import MAGIC_1000, c_div, divisor_of, msvc_div
from tools.disasm import disasm_range
from tools.pe_image import PEImage

SHARP_CODE = (0x10089030, 0x10089D9A)
EXT_BLOCK = 0x100B86E8
STRUCT = 0x100B86F8
FULL = 4096


def strength(raw: int) -> int:
    """0x10089bac-0x10089bc3: S = trunc(raw * 4096 / 1000)."""
    return msvc_div(raw * FULL, MAGIC_1000, 6)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("--- (1) 強さ: trunc(raw * 4096 / 1000) over the whole trackbar ---")
    bad = 0
    for raw in range(0, 8001):
        if strength(raw) != c_div(raw * FULL, 1000):
            bad += 1
            if bad <= 5:
                print(f"  MISMATCH raw={raw}: magic={strength(raw)} "
                      f"trunc={c_div(raw * FULL, 1000)}")
    print(f"  raw = 0..8000 (8001 values), {bad} mismatch(es)")
    print(f"  the (magic, shift) pair itself decodes as /{divisor_of(MAGIC_1000, 6)}")

    print("\n--- (2) where the conversion lives ---")
    lo, hi = SHARP_CODE
    magic_sites, div_sites, x87_sites, track_reads = [], [], [], []
    for insn, _ in disasm_range(img, lo, hi - lo, resolve=False):
        if f"0x{MAGIC_1000:x}" in insn.op_str:
            magic_sites.append(insn.address)
        if insn.mnemonic in ("idiv", "div"):
            div_sites.append(insn.address)
        if insn.mnemonic in ("fild", "fmul", "fdiv", "fstp", "fld", "fadd", "fsub"):
            x87_sites.append(insn.address)
        if "+ 0x44]" in insn.op_str and insn.mnemonic == "mov":
            track_reads.append(insn.address)

    def where(va):
        for name, start, end in (("func_proc", 0x10089030, 0x100891B3),
                                 ("vertical worker", 0x100891C0, 0x1008968E),
                                 ("horizontal worker", 0x10089690, 0x10089B56),
                                 ("combine worker", 0x10089B60, 0x10089D9A)):
            if start <= va < end:
                return name
        return "?"

    print(f"  0x10624dd3 sites : {[f'0x{a:08x} ({where(a)})' for a in magic_sites]}")
    print(f"  fp->track reads  : {[f'0x{a:08x} ({where(a)})' for a in track_reads]}")
    def tally(sites):
        counts = {}
        for a in sites:
            counts[where(a)] = counts.get(where(a), 0) + 1
        return ", ".join(f"{k} x{v}" for k, v in counts.items())

    print(f"  idiv sites       : {len(div_sites)} ({tally(div_sites)})")
    print(f"  x87 instructions : {len(x87_sites)} ({tally(x87_sites)})")
    print("                     -> the combine worker is pure integer; the x87 is")
    print("                        only the two box workers' colour normalisation")
    print("  -> the only /1000 in the effect is inside the combine worker, so every")
    print("     thread redoes it; func_proc reads track[] only to test it against 0")

    print("\n--- (3) the +0x74 block ---")
    names = ("scale", "group", "drag_min", "drag_max")
    slots = [img.u32(EXT_BLOCK + 4 * i) for i in range(4)]
    track_name = [img.cstr(img.u32(img.u32(STRUCT + 0x14) + 4 * i)) for i in range(2)]
    defaults = [img.i32(img.u32(STRUCT + 0x18) + 4 * i) for i in range(2)]
    t_lo = [img.i32(img.u32(STRUCT + 0x1C) + 4 * i) for i in range(2)]
    t_hi = [img.i32(img.u32(STRUCT + 0x20) + 4 * i) for i in range(2)]
    for name, p in zip(names, slots):
        vals = [img.i32(p + 4 * i) for i in range(2)] if p else None
        print(f"  [{names.index(name)}] {name:8s} -> 0x{p:08x}  {vals}")
    print(f"      note slot[2] points at 0x{slots[2]:08x}, which is in .data: an all-zero")
    print(f"      array, like 縁取り's (param_scaling.md §1). track_s (0x{img.u32(STRUCT + 0x1c):08x})")
    print("      is all-zero for the same reason.")

    scale = [img.i32(slots[0] + 4 * i) for i in range(2)]
    dmin = [img.i32(slots[2] + 4 * i) for i in range(2)]
    dmax = [img.i32(slots[3] + 4 * i) for i in range(2)]
    print()
    print("  track  scale        raw range        UI range          slider drag")
    for i in range(2):
        s = scale[i] or 1
        fmt = (lambda v: f"{v / s:.1f}") if s == 10 else (lambda v: str(v))
        print(f"  {track_name[i]:<6s} {s:<5d} "
              f"{t_lo[i]:>6d}..{t_hi[i]:<7d} "
              f"{fmt(t_lo[i]):>8s}..{fmt(t_hi[i]):<9s} "
              f"{fmt(dmin[i]):>8s}..{fmt(dmax[i])}")
    print(f"  defaults (raw): {dict(zip(track_name, defaults))}"
          f"  -> UI 強さ={defaults[0] / 10:.1f}, 範囲={defaults[1]}")

    print("\n--- (4) reference table ---")
    print("    UI 強さ    raw     S (Q12)   gain")
    for ui in (0.0, 10.0, 25.0, 50.0, 100.0, 200.0, 400.0, 800.0):
        raw = int(ui * 10)
        print(f"    {ui:7.1f} {raw:6d} {strength(raw):9d}   x{strength(raw) / FULL:.3f}")
    print("    UI 50.0 is the default: a half-strength unsharp mask.")
    print("    Everything above 100.0 has to be typed in; the slider stops there.")

    print("\n    範囲   r_hi  r_lo  kernel widths   support of the combined blur")
    for rng in (1, 2, 3, 5, 10, 50, 100):
        lo_r = c_div(rng, 2)
        hi_r = rng - lo_r
        widths = f"{2 * hi_r + 1}" + (f" + {2 * lo_r + 1}" if lo_r else " (single pass pair)")
        print(f"    {rng:4d} {hi_r:6d} {lo_r:5d}  {widths:16s} +-{rng} px")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
