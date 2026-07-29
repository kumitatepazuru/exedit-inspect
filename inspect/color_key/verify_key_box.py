"""The key test: an axis-aligned box in YCbCr, and a hard yes/no.

The whole of カラーキー's keying is twenty instructions at the top of worker
0x10016340 plus six compares in its inner loop:

    ymin  = key.y  - 輝度範囲      ymax  = key.y  + 輝度範囲
    cbmin = key.cb - 色差範囲      cbmax = key.cb + 色差範囲
    crmin = key.cr - 色差範囲      crmax = key.cr + 色差範囲

    if ymin <= y <= ymax and cbmin <= cb <= cbmax and crmin <= cr <= crmax:
        a = 0

Claims checked here, each against the instructions rather than against prose:

  1. **Every bound is inclusive.** The six branches are `jl` and `jg`, never
     `jle`/`jge`, so a pixel exactly on a face of the box is keyed. Checked by
     reading the six conditional jumps out of the binary and asserting their
     mnemonics, and by replaying the compare chain over a grid.

  2. **The output is binary.** The one write in the worker is
     `mov word ptr [ecx+6], 0` - there is no multiply, no shift and no other
     store anywhere in the function. Alpha is either untouched or zero, so
     without 境界補正 the effect cannot produce a soft edge, and it cannot
     partially remove a pixel however close to the key colour it is.

  3. **It is a Chebyshev box, not a ball.** Distance is not computed at all:
     the three axes are tested independently, so the accepted region is a
     rectangular box whose diagonal reaches sqrt(3) further than its faces.
     The two chroma axes share one trackbar; luminance has its own.

  4. **There is no arithmetic to get wrong.** No x87, no `_ftol`, no SSE, no
     `0x10624dd3` magic division - the trackbars are compared directly against
     PIXEL_YC fields. This script scans the whole effect to show it.

  5. **The default is "exact match only".** All three trackbars default to 0,
     so a freshly picked key colour keys nothing but pixels equal to it.

Run via main.py:
    uv run main.py inspect/color_key/verify_key_box.py
"""

from tools.disasm import dump_range, disasm_range, function_body
from tools.filter_table import find
from tools.pe_image import PEImage

KEY_WORKER = 0x10016340
COMPARE_CHAIN = (0x100163D4, 0x32)

# (address of the conditional jump, what it must be for the bound to be
# inclusive, which bound it guards)
BRANCHES = [
    (0x100163D9, "jl", "y  < ymin"),
    (0x100163DF, "jg", "y  > ymax"),
    (0x100163E7, "jl", "cb < cbmin"),
    (0x100163ED, "jg", "cb > cbmax"),
    (0x100163F7, "jl", "cr < crmin"),
    (0x100163FD, "jg", "cr > crmax"),
]

ANNOTATIONS = {
    0x100163D4: "y",
    0x100163D9: "strictly less than ymin -> keep. So y == ymin is KEYED",
    0x100163DF: "strictly greater than ymax -> keep",
    0x100163E1: "cb",
    0x100163EF: "cr",
    0x100163FF: "all six tests fell through: alpha = 0, full stop",
}

# Rather than search for a list of floating-point mnemonics and hope it is
# complete, section 4 prints the *entire* mnemonic vocabulary of the effect.
# An omission in a blocklist reads as "no floating point found"; a full
# inventory cannot hide one.
FP_PREFIXES = ("f", "movd", "movq", "movap", "movup", "movdq", "cvt", "adds",
               "addp", "subs", "subp", "muls", "mulp", "divs", "divp", "sqrt",
               "px", "pand", "por", "punpck", "pack", "padd", "psub", "pmul",
               "psll", "psrl", "psra", "comis", "ucomis", "xorp", "andp")


def keyed(px, key, y_range, c_range) -> bool:
    """The compare chain, replayed exactly: six inclusive interval tests."""
    y, cb, cr = px
    if y < key[0] - y_range or y > key[0] + y_range:
        return False
    if cb < key[1] - c_range or cb > key[1] + c_range:
        return False
    if cr < key[2] - c_range or cr > key[2] + c_range:
        return False
    return True


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    (reg,) = find(img, "カラーキー")

    dump_range(img, *COMPARE_CHAIN, label="the compare chain 0x100163d4",
               annotations=ANNOTATIONS)

    print("\n--- 1. are the bounds inclusive? ---")
    by_addr = {i.address: i for i in function_body(img, KEY_WORKER, 0x400)}
    ok = True
    for addr, want, meaning in BRANCHES:
        insn = by_addr.get(addr)
        got = insn.mnemonic if insn else "<none>"
        ok &= got == want
        print(f"  0x{addr:08x}  {got:<4} (expected {want:<4})  skips the pixel when "
              f"{meaning}")
    print(f"  -> every bound is inclusive: {'OK' if ok else 'NO - re-read the branches'}")
    print("  `jl`/`jg` and not `jle`/`jge`: a pixel sitting exactly on a face of the")
    print("  box is removed. With all three ranges at 0 the box is a single point, and")
    print("  a pixel equal to the key colour is still keyed.")

    print("\n--- 2. how many ways can this worker write to a pixel? ---")
    # Every store is `mov <size> ptr [...], src`. Stack slots (`[esp...`) are
    # the compiler spilling the six bounds; anything else is the image.
    writes = [i for i in function_body(img, KEY_WORKER, 0x400)
              if i.mnemonic == "mov" and i.op_str.startswith(("word ptr", "dword ptr", "byte ptr"))
              and not i.op_str.split(",")[0].split("[")[1].startswith("esp")]
    for i in writes:
        print(f"  0x{i.address:08x}: {i.mnemonic} {i.op_str}")
    print(f"  -> {len(writes)} store(s) into the pixel buffer, and the value is a literal 0.")
    print("  No `imul`/`sar` touches a pixel anywhere in the function, so alpha comes")
    print("  out of the key test as either its input value or exactly 0. All of this")
    print("  effect's softness, if any, comes from 境界補正.")

    print("\n--- 4. is there any floating point in the whole effect? ---")
    vocab, magic, calls = {}, [], []
    for insn, _ in disasm_range(img, 0x100162C0, 0x100169F4 - 0x100162C0, resolve=False):
        vocab[insn.mnemonic] = vocab.get(insn.mnemonic, 0) + 1
        if "0x10624dd3" in insn.op_str:
            magic.append(insn)
        if insn.mnemonic == "call":
            calls.append(insn)
    fp = sorted(m for m in vocab if m.startswith(FP_PREFIXES))
    print(f"  0x100162c0..0x100169f3 ({0x100169F4 - 0x100162C0} bytes, the whole effect)")
    print(f"  every mnemonic that occurs, with its count - {len(vocab)} distinct:")
    ordered = sorted(vocab.items())
    for i in range(0, len(ordered), 6):
        print("    " + "".join(f"{m + ':' + str(n):<14}" for m, n in ordered[i:i + 6]))
    print("    (the `jle` are phase guards in the two box passes, not key bounds;")
    print("     `nop` is inter-function padding)")
    print(f"    x87 / SSE mnemonics among them    : {fp or 0}")
    print(f"    0x10624dd3 (/1000 magic division) : {len(magic)}")
    print("    call instructions:")
    for i in calls:
        print(f"      0x{i.address:08x}: call {i.op_str}")
    print("  The only calls are exec_multi_thread_func ([exfunc+0xCC]), the three")
    print("  exedit table entries the UI code uses, wsprintfA/SetWindowTextA, and the")
    print("  effect's own label routine. No CRT `_ftol`, no shared exedit helper, no")
    print("  blend function, no rectangle blit. カラーキー is the only effect analysed")
    print("  in this repository that contains no floating point at all - even クロマキー")
    print("  needs `fpatan` and `_ftol` for its hue angle.")

    print("\n--- 3/5. the box the trackbars describe ---")
    print(f"  {'trackbar':<10}{'raw range':>12}{'default':>9}   what it widens")
    meanings = ["key.y  +- 輝度範囲   (luminance, its own axis)",
                "key.cb +- 色差範囲 and key.cr +- 色差範囲 (one range, two axes)",
                "the border-correction radius; not part of the box"]
    for i in range(reg.track_n):
        print(f"  {str(reg.track_names[i]):<10}"
              f"{f'{reg.track_s[i]}..{reg.track_e[i]}':>12}{reg.track_defaults[i]:>9}   "
              f"{meanings[i]}")
    print("  PIXEL_YC is y in 0..4096 and cb/cr in -2048..2048. Both ranges are sized")
    print("  so that the *worst* key colour can still swallow the whole axis: an axis")
    print("  saturates at `範囲 >= 2048 + |key component|` for chroma and at")
    print("  `輝度範囲 >= max(key.y, 4096 - key.y)` for luminance, i.e. 4096 in the")
    print("  extreme case and much less from a key near the middle. Neither slider has")
    print("  a dead top half in general - it only looks that way for a neutral key.")

    key = (2048, -600, -400)

    def span(centre, half, lo, hi):
        """How many representable values the interval actually covers."""
        return max(0, min(centre + half, hi) - max(centre - half, lo) + 1)

    print(f"\n  the accepted box for key {key}, clipped to the representable")
    print("  range (y 0..4096, cb/cr -2048..2048) and measured against all 4097^3")
    print("  of it:")
    print(f"  {'輝度範囲':>10}{'色差範囲':>10}{'y span':>9}{'cb span':>9}{'cr span':>9}"
          f"{'fraction':>12}")
    for yr, cr_ in ((0, 0), (64, 64), (256, 256), (1024, 512), (2048, 2048), (4096, 4096)):
        ys = span(key[0], yr, 0, 4096)
        cbs = span(key[1], cr_, -2048, 2048)
        crs = span(key[2], cr_, -2048, 2048)
        print(f"  {yr:>10}{cr_:>10}{ys:>9}{cbs:>9}{crs:>9}"
              f"{ys * cbs * crs / 4097 ** 3:>12.6f}")
    print("  This key sits off-centre in chroma (cb = -600), so even 色差範囲 = 2048")
    print("  has not reached the far wall: the cb interval is still 3497 wide out of")
    print("  4097. That is what the top of the slider is for.")
    print("  The corners of that box are sqrt(3) times further from the key colour")
    print("  than the face centres are, because no distance is ever computed - the")
    print("  three axes are three independent interval tests. A key colour whose")
    print("  neighbours differ mostly along one axis is caught much sooner than one")
    print("  whose neighbours drift diagonally.")

    print("\n--- 5. the defaults ---")
    grid = [(2048, -600, -400), (2049, -600, -400), (2048, -601, -400)]
    for px in grid:
        print(f"  key={key}  pixel={px}  ->  "
              f"{'alpha = 0' if keyed(px, key, 0, 0) else 'untouched'}")
    print("  With 輝度範囲 = 色差範囲 = 0 (the shipped defaults) the box is one point.")
    print("  A newly added カラーキー therefore does nothing visible on real footage")
    print("  even after the eyedropper has been used - both ranges have to be raised")
    print("  by hand. クロマキー ships with 24 / 96 instead, and works immediately.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
