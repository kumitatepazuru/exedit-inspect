"""Which worker runs, and why the two checkboxes behave like radio buttons.

`輝度エッジを抽出` and `透明度エッジを抽出` are ordinary checkboxes in
`fp->check[]`, but func_proc treats them as a three-way choice:

    check[0] != 0            -> 0x100234c0   luminance gradient
    check[0] == 0, check[1]  -> 0x10023880   alpha gradient
    both zero                -> 0x10022e30   y, cb and cr gradients

so "both ticked" is not a fourth mode - check[0] simply wins. The UI never
produces that state, and section 2 shows why: `func_WndProc` intercepts the
checkbox notification and clears the *other* box whenever both end up set. A
hand-edited `.exo` can still reach it, and then the alpha box does nothing.

Section 3 is the general finding behind that: exedit's settings window packs
`(control index << 16) | id` into `wParam` of message 0x702, and builds one id
per kind of control in four consecutive stretches of the same dispatch:

    0x1e19  sender 0x10041358      a trackbar moved (inferred from its position)
    0x1e1a  sender 0x100413d7      a checkbox was toggled
    0x1e1b  sender 0x10041456      a button was pressed
    0x1e1c  sender 0x10041500      a combo box selection changed

`0x1e1b` was already known from 発光 / 閃光 / グロー / クロマキー
([`filter_registration.md`](../common/filter_registration.md)). `0x1e1a` is what
エッジ抽出 adds: its handler indexes `fp->check[]` with the high word, which is
what identifies the id as "checkbox" rather than "trackbar". Section 3 also
scans the image for every other handler of each id, so the claim about who uses
them is counted rather than assumed.

Section 4 covers what func_proc does *not* do: no early return, no canvas
growth, no `flag & 0x20` branch. What it does do is swap the two buffers, which
is what makes the effect a replacement rather than a composite.

Run via main.py:
    uv run main.py inspect/edge_extraction/verify_dispatch.py
"""

from tools.disasm import dump_all
from tools.filter_table import find
from tools.filter_table import walk as _walk
from tools.pe_image import PEImage
from tools.xrefs import function_owners, scan, section_of

WORKERS = {
    0x100234C0: "輝度エッジを抽出 on",
    0x10023880: "輝度エッジ off, 透明度エッジ on",
    0x10022E30: "both off",
}

DISPATCH = (0x10022DBF, 0x6A)
WNDPROC = (0x10023AF0, 0x100 - 0x5)

# where exedit builds the wParam for each kind of control
SENDERS = {
    0x1E19: (0x10041355, 0x14, "trackbar moved (inferred: position in the chain)"),
    0x1E1A: (0x100413D4, 0x14, "checkbox toggled"),
    0x1E1B: (0x10041453, 0x14, "button pressed"),
    0x1E1C: (0x100414FD, 0x14, "combo box selection changed"),
}

ANNOTATIONS = {
    0x10022DC9: "check[0] = 輝度エッジを抽出",
    0x10022DCF: "  zero -> look at check[1]; otherwise the luminance worker, full stop",
    0x10022DD4: "0x100234c0",
    0x10022DE1: "check[1] = 透明度エッジを抽出",
    0x10022DEB: "0x10023880",
    0x10022DFB: "0x10022e30 - the expensive one is what you get by ticking *nothing*",
    0x10022E06: "the workers wrote into *(fpip+0xB0) ...",
    0x10022E15: "... so swap it with *(fpip+0xAC) to make it the object",
    0x10022E21: "return TRUE",
    # ---- func_WndProc ---------------------------------------------------
    0x10023AF0: "message",
    0x10023AF6: "esi = fp (arg 6)",
    0x10023AFA: "0x702 = exedit's settings-window notification",
    0x10023B00: "ebx = fp->ex_data_ptr",
    0x10023B09: "edi = wParam",
    0x10023B0F: "low word = the control id ...",
    0x10023B14: "... 0x1e1a = a checkbox moved",
    0x10023B1B: "... 0x1e1b = a button was pressed",
    0x10023B22: "0x1e1b: fp->0xe4, the exedit-side object this FILTER belongs to",
    0x10023B37: "colour dialog, flag 2 - no 「指定なし」 (verify_ex_data.py)",
    0x10023B41: "cancelled -> return FALSE",
    0x10023B4F: "mark the 'color' field dirty for undo",
    0x10023B5C: "rewrite the button's label to RGB ( r , g , b )",
    0x10023B6D: "0x1e1a path",
    0x10023B7F: "eax = wParam >> 16 ...",
    0x10023B87: "... = which checkbox. 0 = 輝度エッジ",
    0x10023B8C: "fp->check",
    0x10023B8F: "  both ticked ...",
    0x10023B9A: "  ... -> untick 透明度エッジ",
    0x10023BAB: "redraw the settings window",
    0x10023BB9: "index 1 = 透明度エッジ",
    0x10023BCD: "  both ticked -> untick 輝度エッジ instead",
    0x10023BEB: "any other message: FALSE, i.e. 'not handled'",
    # ---- the senders ----------------------------------------------------
    0x10041355: "index << 16 ...",
    0x10041358: "... | 0x1e19",
    0x100413D4: "index << 16 ...",
    0x100413D7: "... | 0x1e1a",
    0x10041453: "index << 16 ...",
    0x10041456: "... | 0x1e1b",
    0x100414FD: "index << 16 ...",
    0x10041500: "... | 0x1e1c",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    regs = find(img, "エッジ抽出")
    owners = function_owners(img)

    print("--- 1. one registration, three workers ---")
    for r in regs:
        print(f"  struct 0x{r.struct_va:08x} flag=0x{r.flag:08x} -> {r.role}")
        print(f"    checkboxes: " + ", ".join(f"{n!r}(default {d})"
              for n, d in zip(r.check_names, r.check_defaults)))
    print(f"  -> {len(regs)} registration(s): エッジ抽出 exists only as an object effect,")
    print("     so there is no `flag & 0x20` branch and no 6-byte pixel path.")
    print()
    print(f"  {'worker':>12}  {'reached when':<34}{'references to its address':>27}")
    for addr, when in WORKERS.items():
        hits = [va for va in scan(img, addr) if section_of(img, va) == ".text"]
        where = ", ".join(sorted({_owner(owners, va) for va in hits}))
        print(f"  0x{addr:08x}  {when:<34}{len(hits):>10}  ({where})")
    print("  -> each worker address appears exactly once in the image, in the `push`")
    print("     inside func_proc. Nothing else can reach them.")

    print("\n--- 2. func_proc's dispatch, and the WndProc that keeps it unambiguous ---")
    dump_all(img, {"dispatch + buffer swap": DISPATCH, "func_WndProc": WNDPROC},
             annotations=ANNOTATIONS)
    print()
    print("  The two `cmp dword ptr [eax], 1` / `cmp dword ptr [eax+4], 1` pairs at")
    print("  0x10023b8f and 0x10023bc7 fire only when *both* boxes read 1, and each")
    print("  clears the one the user did not just click. That makes them radio buttons")
    print("  with a third, unlabelled state - 'neither' - which is the colour mode.")

    print("\n--- 3. exedit's settings-window control ids ---")
    wnd = {r.func_wndproc: r.name for r in _walk(img) if r.func_wndproc}
    for cid, (lo, _, meaning) in SENDERS.items():
        others = [va for va in _mentions(img, cid)
                  if not lo <= va < lo + 0x20 and section_of(img, va) == ".text"]
        who = sorted({_owner(owners, va).split(".")[0] for va in others})
        print(f"  0x{cid:04x}  built at 0x{lo:08x}   {meaning}")
        print(f"          other .text mentions: {', '.join(who) or '(none)'}")
    print("  -> エッジ抽出 and パーティクル出力 are the only filters that react to a")
    print("     checkbox at all; everyone else just reads fp->check[] in func_proc.")
    print("     (エッジ抽出 does not appear on the 0x1e1b row because its handler")
    print("      reaches that case by `sub eax, 0x1e1a` + `dec eax`, so the constant")
    print("      never appears - a byte scan is a lower bound, not a census.")
    print(f"      Its func_WndProc is registered as "
          f"0x{[a for a, n in wnd.items() if n == 'エッジ抽出'][0]:08x}.)")
    dump_all(img, {f"wParam for 0x{cid:04x}": (lo, size)
                   for cid, (lo, size, _) in SENDERS.items()}, annotations=ANNOTATIONS)
    print("\n  All four go through the same `sub_1004a050(fp_index, wParam, ctrl, ..)`,")
    print("  so the high word is the control's index within its kind - which is how")
    print("  エッジ抽出 tells checkbox 0 from checkbox 1, and how パーティクル出力")
    print("  singles out its checkbox 4 (0x1006f385).")

    print("\n--- 4. what func_proc does not do ---")
    print("  * no early return: 強さ = 0 still runs a full pass and writes a fully")
    print("    transparent image, unlike ぼかし / 閃光 / 拡散光 / グロー")
    print("    ([param_scaling.md](../common/param_scaling.md) section 3).")
    print("  * no canvas growth and no サイズ固定: the output is bounded by the input")
    print("    rectangle by construction, and the border ring is cleared instead")
    print("    ([canvas_growth.md](../common/canvas_growth.md) - none of the four")
    print("    methods applies here).")
    print("  * no read of fpip->flag, fpip->frame, or any blend function: the result")
    print("    replaces the object outright.")


def _mentions(img: PEImage, value: int) -> list[int]:
    """Every place the 16-bit constant appears, as an imm16 or an imm32."""
    out, pos = [], 0
    needle = value.to_bytes(2, "little")
    while True:
        i = img.data.find(needle, pos)
        if i == -1:
            return out
        out.append(i + img.image_base)
        pos = i + 1


def _owner(owners, va: int) -> str:
    prev = None
    for addr, label in owners:
        if addr > va:
            break
        prev = label
    return prev or "?"


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
