"""What runs, on what, and with what state - the shape of the effect.

ルミナンスキー is the plainest dispatcher in this repository, and this script
exists to show that the plainness is real rather than an artefact of reading a
truncated range. Claims checked here:

  1. **Four workers, four combobox items, one dispatch each.** The `push
     0x100650..` operands in func_proc are matched against the four cp932
     strings the combobox is built from, and each worker address is searched
     for as a raw dword across the whole 850 KB image: exactly one occurrence
     apiece, all four inside func_proc. Nothing else in exedit reaches them.

  2. **There are no globals at all.** Every other effect analysed here has to
     park its derived parameters somewhere, because `exec_multi_thread_func`
     takes only two of them (filter_registration.md §6). ルミナンスキー needs
     none: the workers read `fp->track[]` themselves. The evidence is that the
     effect's entire 959-byte code range contains exactly one absolute `[0x...]`
     memory operand, and it is the `SendMessageA` import thunk.

  3. **Nothing but alpha is ever written.** Every store into the image is
     `mov word ptr [reg + 6], ...`. y, cb and cr pass through untouched, so the
     effect can only ever remove opacity.

  4. **It is fully in place, with no scratch buffer.** `*(fpip+0xAC)` is read;
     `*(fpip+0xB0)` - the pair buffer every blur-like effect uses - never
     appears. Neither does any canvas-growth call.

  5. **There is no `flag & 0x20` branch.** One registration, object effect
     only, so pixels are always 8-byte PIXEL_YCA.

  6. **Every worker splits by row**, with the same `(tid+1)*h/thread_num`
     idiom, and `w`/`h`/stride come from the same three fpip fields.

  7. **No floating point and no magic division**, shown by printing the entire
     mnemonic vocabulary of the effect rather than by searching a blocklist -
     an omission in a blocklist would read as agreement.

Run via main.py:
    uv run main.py inspect/luma_key/verify_dispatch.py
"""

import re

from tools.disasm import disasm_range, function_body
from tools.filter_table import find
from tools.pe_image import PEImage
from tools.xrefs import scan

FUNC_PROC = 0x10064EE0
CODE_LO, CODE_HI = 0x10064EE0, 0x1006529F      # the whole effect, ret to ret

WORKERS = [
    (0, 0x10064F60, "暗い部分を透過"),
    (1, 0x10065020, "明るい部分を透過"),
    (2, 0x100650E0, "明暗部分を透過"),
    (3, 0x100651B0, "明暗部分を透過(ぼかし無し)"),
]

# Same inventory-not-blocklist approach as inspect/color_key/verify_key_box.py.
FP_PREFIXES = ("f", "movd", "movq", "movap", "movup", "movdq", "cvt", "adds",
               "addp", "subs", "subp", "muls", "mulp", "divs", "divp", "sqrt",
               "px", "pand", "por", "punpck", "pack", "padd", "psub", "pmul",
               "psll", "psrl", "psra", "comis", "ucomis", "xorp", "andp")

# `[reg + 0xNN]` - a struct field access. Displacements below 0x40 are stack
# frame and pixel offsets; the interesting ones are the fpip/fp fields.
_FIELD = re.compile(r"\[(e[a-z]{2}) \+ (0x[0-9a-f]+)\]")
_ABS = re.compile(r"\[(0x[0-9a-f]{7,8})\]")

FIELD_MEANING = {
    0x44: "fp->track",
    0x4C: "fp->ex_data_ptr",
    0x60: "fp->exfunc",
    0x64: "fp->+0x64, exedit's internal table",
    0xAC: "fpip->+0xAC, the object pixel buffer",
    0xB0: "fpip->+0xB0, the PAIR buffer - should not appear",
    0xB4: "fpip->+0xB4, w",
    0xB8: "fpip->+0xB8, h",
    0xCC: "exfunc->exec_multi_thread_func",
    0xE4: "fp->+0xE4, the opaque UI handle",
    0xEC: "fpip->+0xEC, row stride in pixels",
}


def _combo_items(img, reg, n):
    """The combobox item names: n consecutive cp932 strings from check_name[0].

    filter_registration.md §5: a `check_default` of -2 marks a combobox whose
    items are packed back to back, the first doubling as the checkbox name.
    """
    p = img.u32(img.u32(reg.struct_va + 0x28))
    out = []
    for _ in range(n):
        s = img.cstr(p)
        out.append((p, s))
        p += len(s.encode("cp932")) + 1
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    (reg,) = find(img, "ルミナンスキー")

    body = list(disasm_range(img, CODE_LO, CODE_HI - CODE_LO, resolve=False))
    insns = [i for i, _ in body]

    print("--- 1. four dispatches, four combobox items ---")
    pushes = [i for i in insns if i.mnemonic == "push" and i.op_str.startswith("0x1006")
              and CODE_LO <= int(i.op_str, 16) < CODE_HI]
    items = _combo_items(img, reg, 4)
    print(f"  check_n = {reg.check_n}, check_default[0] = {reg.check_defaults[0]}"
          f" -> combobox (filter_registration.md §5)")
    print(f"  {'type':>5}  {'worker':<12}{'pushed at':<12}{'item string':<30}{'string VA'}")
    ok = len(pushes) == 4
    for (t, worker, name), push, (sva, s) in zip(WORKERS, pushes, items):
        good = int(push.op_str, 16) == worker and s == name
        ok &= good
        print(f"  {t:>5}  0x{worker:08x}  0x{push.address:08x}  {s:<30}0x{sva:08x}"
              f"{'' if good else '   <-- MISMATCH'}")
    print(f"  -> the combobox index selects the worker directly: {'OK' if ok else 'NO'}")

    print("\n  who else in the image references these four addresses?")
    for t, worker, _ in WORKERS:
        hits = scan(img, worker)
        inside = [h for h in hits if FUNC_PROC <= h < CODE_HI]
        print(f"    0x{worker:08x}: {len(hits)} occurrence(s) in the whole file, "
              f"{len(inside)} of them inside func_proc")
    print("  One apiece, all in func_proc. No worker is shared with another effect and")
    print("  none is dispatched twice - unlike カラーキー, whose key worker is pushed")
    print("  twice from its own func_proc.")

    print("\n  and every branch really does dispatch:")
    calls = [i for i in insns if i.mnemonic == "call" and "0xcc" in i.op_str]
    rets = [i for i in insns if i.address < 0x10064F60 and i.mnemonic == "ret"]
    print(f"    exec_multi_thread_func calls in func_proc : {len(calls)}")
    print(f"    `ret` instructions in func_proc           : {len(rets)}"
          f"  (one per branch, each preceded by `mov eax, 1`)")
    print("  There is no early return. 基準輝度 and ぼかし are never tested before the")
    print("  dispatch, so even ぼかし = 0 walks every pixel - contrast ぼかし/閃光/拡散光,")
    print("  which bail out on a zero first trackbar (param_scaling.md §3).")

    print("\n--- 2. globals: how much shared state does this effect have? ---")
    abs_ops = [i for i in insns if _ABS.search(i.op_str)]
    for i in abs_ops:
        va = int(_ABS.search(i.op_str).group(1), 16)
        sect = "import thunk" if 0x1009A000 <= va < 0x1009B000 else "?"
        print(f"  0x{i.address:08x}: {i.mnemonic} {i.op_str}   ({sect})")
    print(f"  -> {len(abs_ops)} absolute memory operand(s) in "
          f"0x{CODE_LO:08x}..0x{CODE_HI - 1:08x} ({CODE_HI - CODE_LO} bytes).")
    print("  Not one of them is a variable. This is the only effect analysed here with")
    print("  ZERO globals: nothing has to be handed to the workers, because the only")
    print("  two derived quantities (base-blur and base+blur) are one `sub`/`add` from")
    print("  fp->track[] and each worker computes its own.")

    print("\n--- 3./4. which struct fields does the effect touch? ---")
    seen = {}
    for i in insns:
        for _, disp in _FIELD.findall(i.op_str):
            d = int(disp, 16)
            if d >= 0x40:
                seen.setdefault(d, i.address)
    for d in sorted(seen):
        print(f"    +0x{d:02x}  first at 0x{seen[d]:08x}   "
              f"{FIELD_MEANING.get(d, '(unclassified)')}")
    print(f"  0xB0 present: {0xB0 in seen}  -> the pair buffer is never touched, so the")
    print("  effect is entirely in place on *(fpip+0xAC). No buffer swap, no canvas")
    print("  growth, no rectangle blit, no offscreen render (canvas_growth.md).")

    print("\n  every store the workers make:")
    stores = []
    for t, worker, _ in WORKERS:
        for i in function_body(img, worker, 0x400):
            if not i.mnemonic.startswith("mov") or "ptr [" not in i.op_str:
                continue
            dest = i.op_str.split(",")[0]
            if not dest.endswith("]") or "[esp" in dest:
                continue
            stores.append((t, i))
    for t, i in stores:
        print(f"    type {t}  0x{i.address:08x}: {i.mnemonic} {i.op_str}")
    alpha_only = all(i.op_str.split(",")[0].strip().startswith("word ptr")
                     and i.op_str.split(",")[0].strip().endswith("+ 6]")
                     for _, i in stores)
    print(f"  -> every store is 16 bits at pixel+6 = alpha: {alpha_only}")
    print("  y, cb and cr are read (the `movsx ..., word ptr [reg]` at the top of each")
    print("  inner loop reads y) but never written. There is no spill suppression, no")
    print("  colour correction, nothing like クロマキー's 色彩補正 - the effect's whole")
    print("  output is an alpha map multiplied into the alpha that was already there.")

    print("\n--- 5./6. the worker prologues ---")
    print(f"  {'type':>5}  {'worker':<12}{'split':<10}{'w':<8}{'h':<8}{'stride':<9}{'buffer'}")
    for t, worker, _ in WORKERS:
        b = function_body(img, worker, 0x400)
        text = " ".join(f"{i.mnemonic} {i.op_str}" for i in b)
        print(f"  {t:>5}  0x{worker:08x}  {'row' if 'idiv' in text else '?':<10}"
              f"{'+0xb4' if '0xb4' in text else '-':<8}"
              f"{'+0xb8' if '0xb8' in text else '-':<8}"
              f"{'+0xec' if '0xec' in text else '-':<9}"
              f"{'+0xac' if '0xac' in text else '-'}")
    print("  All four share the prologue: y0 = tid*h/thread_num, y1 = (tid+1)*h/thread_num,")
    print("  byte offset = y0 * (*(fpip+0xEC)) * 8. The `* 8` is PIXEL_YCA and there is")
    print("  no 6-byte path, because there is no frame-filter registration to have one:")
    print(f"  ルミナンスキー has {len(find(img, 'ルミナンスキー'))} registration, flag = 0x{reg.flag:02x}"
          f" ({reg.role}).")

    print("\n--- 7. the instruction vocabulary of the whole effect ---")
    vocab, magic = {}, []
    for i in insns:
        vocab[i.mnemonic] = vocab.get(i.mnemonic, 0) + 1
        if "0x10624dd3" in i.op_str:
            magic.append(i)
    fp = sorted(m for m in vocab if m.startswith(FP_PREFIXES))
    ordered = sorted(vocab.items())
    print(f"  0x{CODE_LO:08x}..0x{CODE_HI - 1:08x}, {len(vocab)} distinct mnemonics:")
    for i in range(0, len(ordered), 6):
        print("    " + "".join(f"{m + ':' + str(n):<14}" for m, n in ordered[i:i + 6]))
    print(f"    x87 / SSE mnemonics among them    : {fp or 0}")
    print(f"    0x10624dd3 (/1000 magic division) : {len(magic)}")
    print("    call instructions:")
    for i in insns:
        if i.mnemonic == "call":
            print(f"      0x{i.address:08x}: call {i.op_str}")
    print("  Four dispatches, one exedit table entry and one SendMessageA. No CRT")
    print("  `_ftol`, no shared exedit helper, no blend function. Together with")
    print("  カラーキー this is one of only two effects analysed here that contain no")
    print("  floating point at all - and this one is smaller, with 23 mnemonics in")
    print(f"  {CODE_HI - CODE_LO} bytes against カラーキー's 28 in 1,844.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
