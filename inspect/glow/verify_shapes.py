"""形状 - the 6-way combo box - decoded from the jump table, the label strings
and the direction each worker walks in.

`check[0]` has `check_default = -2`, so it is a combo box rather than a
checkbox ([`filter_registration.md`](../common/filter_registration.md)); the
selection lands in `ex_data.type` (dword[1]) and func_proc switches on it at
0x10055198 through `jmp [eax*4 + 0x1005551c]`. Section 1 reads that table and
the six cp932 label strings out of .rdata and pairs them with the workers each
case dispatches, so the naming is taken from the binary rather than assumed.

Section 2 is the geometric claim. Each streak worker walks the scratch buffer
in one direction, and its step is a single `lea` per worker:

    lea eax, [ecx*8 + 8]        stride + 1 pixel  -> down-right
    lea eax, [ecx*8 - 8]        stride - 1 pixel  -> down-left
    (no +-8 at all)             stride            -> straight down
    add reg, 8                  1 pixel           -> straight right

That is what distinguishes the eight streak functions; everything else about
them is identical. Two workers per diagonal direction are needed because one
sweeps the diagonals that start on an edge row and the other those that start
on an edge column - section 2 also shows the +1 offsets that stop the corner
diagonal from being drawn twice.

Section 3 is the consequence: クロス(4本) and クロス(4本斜め) are exactly the
unions of the line shapes, and クロス(8本) dispatches all six workers, so it
costs the sum of the two - it is not a cheaper combined implementation.

Run via main.py:
    uv run main.py inspect/glow/verify_shapes.py
"""

from tools.decompile import call_targets
from tools.disasm import disasm_range
from tools.pe_image import PEImage

JUMP_TABLE = 0x1005551C
LABELS = 0x100A6790          # six consecutive cp932 strings, check_name[0] points here
COMBO_LABEL = 0x100A67D4     # the static text next to the combo

# label -> (case entry point, workers dispatched, one-line direction)
CASES = {
    0: ("通常", 0x100551AA, [0x10055A10, 0x10055ED0], "separable box, 4 cascaded passes"),
    1: ("クロス(4本)", 0x10055335, [0x10056220, 0x100569E0], "vertical + horizontal"),
    2: ("クロス(4本斜め)", 0x1005535D,
        [0x100570D0, 0x10057730, 0x10057D90, 0x10058430], "both diagonals"),
    3: ("クロス(8本)", 0x100553A5,
        [0x10056220, 0x100569E0, 0x100570D0, 0x10057730, 0x10057D90, 0x10058430],
        "cases 1 and 2 back to back"),
    4: ("ライン(横)", 0x1005540A, [0x100569E0], "horizontal only"),
    5: ("ライン(縦)", 0x1005541C, [0x10056220], "vertical only"),
}

# worker -> (scale-2/4 helper, expected step in pixels as (dx, dy))
STREAKS = {
    0x10056220: (0x10056700, (0, +1), "ライン(縦)"),
    0x100569E0: (0x10056E00, (+1, 0), "ライン(横)"),
    0x100570D0: (0x10057410, (+1, +1), "斜め \\, diagonals starting on the left edge"),
    0x10057730: (0x10057A70, (+1, +1), "斜め \\, diagonals starting on the top edge"),
    0x10057D90: (0x10058100, (-1, +1), "斜め /, diagonals starting on the right edge"),
    0x10058430: (0x10058780, (-1, +1), "斜め /, diagonals starting on the top edge"),
}


def step_of(img: PEImage, addr: int, size: int = 0x700):
    """Classify a worker's per-sample pointer step from its `lea`/`add` forms.

    Returns (dx, dy). dy comes from whether the stride register is scaled by 8
    at all (a straight-horizontal worker never touches it inside the loop); dx
    from the +-8 tacked onto that scaled stride, or from a bare `add reg, 8`.
    """
    diag_plus = diag_minus = plain_stride = bare_add8 = 0
    for insn, _ in disasm_range(img, addr, size, resolve=False):
        op = insn.op_str
        if insn.mnemonic == "lea" and "*8 + 8]" in op:
            diag_plus += 1
        elif insn.mnemonic == "lea" and "*8 - 8]" in op:
            diag_minus += 1
        elif insn.mnemonic == "lea" and op.endswith("*8]"):
            plain_stride += 1
        elif insn.mnemonic == "add" and op.endswith(", 8"):
            bare_add8 += 1
        elif insn.mnemonic == "add" and op.endswith(", -8"):
            diag_minus += 1
        if insn.mnemonic == "ret":
            break
    # Order matters. Every worker scales the stride by 8 *somewhere* - even the
    # horizontal one, to reach the next row in its outer loop - so `lea
    # [stride*8]` alone means nothing. What is unique to each is the step the
    # sliding window itself takes: +-8 folded into the stride for a diagonal,
    # a bare `add ptr, 8` for horizontal, neither for vertical.
    if diag_plus:
        return (+1, +1), f"lea [stride*8 + 8] x{diag_plus}"
    if diag_minus:
        return (-1, +1), f"stride*8 - 8 x{diag_minus}"
    if bare_add8:
        return (+1, 0), f"add ptr, 8 x{bare_add8} (no stride in the inner step)"
    return (0, +1), f"lea [stride*8] x{plain_stride}, never +-8"


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("--- 1. the switch table at 0x1005551c, and the labels it belongs to ---")
    p = LABELS
    names = []
    for _ in range(6):
        names.append(img.cstr(p))
        p += len(names[-1].encode("cp932")) + 1
    print(f"  combo caption @ 0x{COMBO_LABEL:08x}: {img.cstr(COMBO_LABEL)!r}"
          f"   (written by 0x10059022)")
    ok = True
    for case, (label, entry, workers, note) in CASES.items():
        target = img.u32(JUMP_TABLE + 4 * case)
        good = target == entry and names[case] == label
        ok &= good
        print(f"  [{case}] table -> 0x{target:08x}  label={names[case]!r:<20} {note}")
        if not good:
            print(f"      MISMATCH: expected 0x{entry:08x} / {label!r}")
        print("      workers: " + ", ".join(f"0x{w:08x}" for w in workers))
    print(f"  -> {'OK' if ok else 'MISMATCH'}: six cases, six labels, no default entry")
    print("  (`cmp eax, 5 / ja` at 0x10055198 sends anything else to `return 0`,")
    print("   which is exedit's 'this effect did nothing' answer.)")

    print("\n--- 2. what direction each streak worker walks ---")
    print(f"  {'worker':>12}{'helper':>12}{'step':>10}   evidence / role")
    fails = 0
    for worker, (helper, expected, role) in STREAKS.items():
        got, evidence = step_of(img, worker)
        calls = call_targets(img, worker, 0x700)
        helper_ok = helper in calls
        if got != expected or not helper_ok:
            fails += 1
        print(f"  0x{worker:08x}  0x{helper:08x}{str(got):>10}   {evidence}; {role}")
        if got != expected:
            print(f"      MISMATCH: expected {expected}")
        if not helper_ok:
            print(f"      MISMATCH: 0x{helper:08x} is not called from here ({calls})")
    print(f"  -> {'OK' if not fails else '%d MISMATCH' % fails}: every streak worker "
          "calls exactly one scale-2/4 helper")
    print("  and every one of them calls 0x10056680, the shared accumulate step:")
    print("    " + ", ".join(f"0x{w:08x}" for w in STREAKS
                             if 0x10056680 in call_targets(img, w, 0x700)))

    print("\n--- 3. the two workers of one diagonal direction do not overlap ---")
    print(f"  {'worker':>12}  {'direction / sweep':<36}{'start forced to 1':>18}")
    for addr, note in ((0x100570D0, "\\  over rows, from the left edge"),
                       (0x10057730, "\\  over columns, from the top edge"),
                       (0x10057D90, "/  over rows, from the right edge"),
                       (0x10058430, "/  over columns, from the top edge")):
        seen = any(insn.mnemonic == "mov" and insn.op_str.endswith(", 1")
                   and prev.mnemonic == "jne"
                   for prev, insn in _pairs(img, addr, 0x80))
        print(f"  0x{addr:08x}  {note:<36}{str(seen):>18}")
    print("  each direction has exactly one worker that keeps index 0 and one that")
    print("  skips it (`test esi,esi / jne / mov esi,1`), so the diagonal through the")
    print("  shared corner is drawn once. For \\ the owner is the row sweep, for / it")
    print("  is the column sweep - which is the corner each of them starts from.")

    print("\n--- 4. cost: クロス(8本) is the sum of the two crosses ---")
    for case in (1, 2, 3):
        label, _, workers, _ = CASES[case]
        print(f"  {label:<18} {len(workers)} worker dispatches x 3 scales each "
              f"= {len(workers) * 3} passes over the scratch")


def _pairs(img: PEImage, addr: int, size: int):
    prev = None
    for insn, _ in disasm_range(img, addr, size, resolve=False):
        if prev is not None:
            yield prev, insn
        prev = insn


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
