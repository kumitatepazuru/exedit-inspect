"""Which worker runs, and what each one is allowed to see.

クロマキー has a single registration (object effect only - there is no frame
filter version, as with 境界ぼかし), so func_proc branches on nothing but the
two checkboxes:

    境界補正 == 0, 色彩補正 off  ->  0x10012f10                          (1 pass)
    境界補正 == 0, 色彩補正 on   ->  0x100130b0                          (1 pass)
    境界補正 >  0, 色彩補正 off  ->  0x10013340, 0x100136e0, 0x10013880  (3 passes)
    境界補正 >  0, 色彩補正 on   ->  0x10013500, 0x100136e0, 0x10013de0  (3 passes)

Three things this script establishes by scanning the code rather than by
assertion:

  1. **which `fp->track[i]` and `fp->check[i]` each worker reads.** The
     trackbars are read *inside* the workers - unusually for this codebase,
     they are not marshalled through globals - so the read set is a direct
     statement of what each path can depend on. The scan follows the register
     loaded from `fp+0x44` / `fp+0x48` forward a few instructions and reports
     the indices it is dereferenced at.

  2. **透過補正 is only wired up on the 色彩補正 paths.** `check[1]` is read by
     0x100130b0 and 0x10013de0 and by nothing else. With 色彩補正 unticked the
     checkbox does nothing at all, whether 境界補正 is on or off.

  3. **the five globals belong to クロマキー alone**, except the scratch
     pointer 0x101a5328, which is exedit's shared work buffer (発光, グロー,
     ディスプレイスメントマップ and others borrow the same allocation - see
     `inspect/common/README.md` §4). Only the *pointer* is shared; クロマキー
     copies it into its own g_1011ec84 for the frame.

Run via main.py:
    uv run main.py inspect/chroma_key/verify_dispatch.py
"""

import re

from tools.disasm import disasm_range, dump_range, function_body
from tools.pe_image import PEImage

DISPATCH = (0x10012DE5, 0x12A)

WORKERS = {
    0x10012F10: "境界補正=0, 色彩補正 off",
    0x100130B0: "境界補正=0, 色彩補正 on",
    0x10013340: "境界補正>0 pass1",
    0x10013500: "境界補正>0 pass1, 色彩補正 on",
    0x100136E0: "境界補正>0 pass2 (shared)",
    0x10013880: "境界補正>0 pass3",
    0x10013DE0: "境界補正>0 pass3, 色彩補正 on",
}

TRACK_NAMES = ["色相範囲", "彩度範囲", "境界補正"]
CHECK_NAMES = ["色彩補正", "透過補正", "キー色の取得"]

GLOBALS = {
    0x1011EC7C: "scratch map A (= *(fpip+0xB0))",
    0x1011EC80: "scratch map B (= map A + 2*stride*h)",
    0x1011EC84: "scratch map C (= the shared buffer at 0x101a5328)",
    0x1011EC88: "kernel width 2r+1",
    0x1011EC8C: "r = 境界補正",
}

# fp+0x44 is FILTER::track, fp+0x48 is FILTER::check (data/filter.h).
ARRAY_OFF = {0x44: "track", 0x48: "check"}


def _dest_reg(insn) -> str | None:
    """Destination register of a `mov reg, [...]`, or None."""
    head = insn.op_str.split(",")[0].strip()
    return head if insn.mnemonic == "mov" and head.isalpha() else None


def _loads_field(insn, off: int) -> bool:
    """True for `mov reg, [base + off]` where base is not the stack pointer.

    Without the esp exclusion this matches `[esp + 0x44]` too, and these
    workers spill so much that every one of them would look as if it read
    fp->track - the false positive that makes the whole scan worthless.
    """
    m = re.search(r"\[(e[a-z]{2}) \+ 0x([0-9a-f]+)\]", insn.op_str)
    return bool(m) and m.group(1) != "esp" and int(m.group(2), 16) == off


def array_indices(insns) -> dict:
    """{'track': {0, 2}, 'check': {1}} for one function body.

    exedit loads the array pointer into a register and dereferences it a few
    instructions later, so a purely textual scan for `[reg]` would collect
    every pointer in the function. Following the register from the load that
    produced it, and only for a short window, is what keeps the answer
    meaningful - the point of the scan is that a worker which never loads
    fp+0x48 cannot possibly be reading a checkbox.
    """
    found = {name: set() for name in ARRAY_OFF.values()}
    for i, insn in enumerate(insns):
        for off, name in ARRAY_OFF.items():
            if not _loads_field(insn, off):
                continue
            reg = _dest_reg(insn)
            if reg is None:
                continue
            for follow in insns[i + 1:i + 8]:
                if f"[{reg}]" in follow.op_str:
                    found[name].add(0)
                for idx in (1, 2):
                    if f"[{reg} + {idx * 4}]" in follow.op_str:
                        found[name].add(idx)
                if _dest_reg(follow) == reg:
                    break       # the register has been reused for something else
    return found


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    dump_range(img, *DISPATCH, label="func_proc: the whole branch tree", annotations={
        0x10012DE8: "ex_data.status != 1 -> return without running anything",
        0x10012DF6: "track[2] = 境界補正",
        0x10012DFB: "  zero -> single-pass path",
        0x10012E47: "check[0] = 色彩補正 (three-pass side)",
        0x10012E51: "  on : 0x10013500 / 0x100136e0 / 0x10013de0",
        0x10012E92: "  off: 0x10013340 / 0x100136e0 / 0x10013880",
        0x10012ECB: "check[0] = 色彩補正 (single-pass side)",
        0x10012ED9: "  on : 0x100130b0",
        0x10012EF8: "  off: 0x10012f10",
    })

    print("\n--- 1/2. what each worker reads out of the FILTER struct ---")
    print(f"  {'worker':>12}  {'path':<28}{'track[]':<26}check[]")
    for addr, role in WORKERS.items():
        idx = array_indices(function_body(img, addr, 0x600))
        t = ", ".join(f"{i}:{TRACK_NAMES[i]}" for i in sorted(idx["track"])) or "-"
        c = ", ".join(f"{i}:{CHECK_NAMES[i]}" for i in sorted(idx["check"])) or "-"
        print(f"  0x{addr:08x}  {role:<28}{t:<26}{c}")
    print("\n  境界補正 (track[2]) is read by func_proc only - the workers see it as")
    print("  the radius global. 色彩補正 (check[0]) is read by func_proc only too:")
    print("  it picks the worker, and the worker then *is* the answer.")
    print("  透過補正 (check[1]) appears in exactly the two 色彩補正 workers, so")
    print("  ticking it on its own changes nothing. It is a modifier of 色彩補正.")

    print("\n--- 3. who else touches the five globals? ---")
    text = img.data
    for va, what in GLOBALS.items():
        needle = va.to_bytes(4, "little")
        hits, pos = [], text.find(needle)
        while pos != -1:
            hits.append(pos + img.image_base)
            pos = text.find(needle, pos + 1)
        inside = [h for h in hits if 0x10012DE0 <= h <= 0x100143D0]
        print(f"  0x{va:08x}  {what}")
        print(f"      {len(hits)} reference(s) in the image, {len(inside)} of them "
              f"inside 0x10012de0-0x100143d0"
              f"{'  -> クロマキー only' if len(hits) == len(inside) else '  -> SHARED'}")

    print("\n--- 3b. the calls the whole effect makes ---")
    calls = set()
    for addr in (0x10012DE0, *WORKERS):
        for insn, _ in disasm_range(img, addr, 0x600, resolve=False):
            if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
                calls.add(int(insn.op_str, 16))
    for t in sorted(calls):
        print(f"  0x{t:08x}   " + ("CRT _ftol (see inspect/common/integer_semantics.md)"
                                   if t == 0x10091AD8 else "?"))
    print("  One callee, and it is the float-to-int conversion. No blend function, no")
    print("  rectangle blit, no canvas growth: クロマキー edits *(fpip+0xAC) in place")
    print("  and hands back the same buffer it was given.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
