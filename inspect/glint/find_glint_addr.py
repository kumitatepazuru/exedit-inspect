"""Locate 閃光 (glint) in exedit.auf and dump everything the registration says
about it, then go looking for the registration that is *not* in the table.

The first half is just tools/filter_table.py pointed at 閃光: one entry,
flag=0x20, so unlike ぼかし/発光/モザイク this effect exists only as an object
effect and there is no flag&0x20 branch to disentangle inside func_proc.

The second half is the part worth having a script for. Scanning .data for
structs that *look* like a registration - a pointer to a known effect name at
+0x0C, a plausible func_proc at +0x30 - turns up a second, fully built 閃光
registration at 0x100a5b20 that the 0x100a3e28 pointer array never mentions:
flag=0, i.e. the frame(video)-filter variant, with only 光色の設定 among its
checkboxes (exactly how 発光's frame variant differs from its object one) and
its own func_proc at 0x1004f260. tools/xrefs.py confirms nothing in the image
references that struct address. Its func_proc computes the same parameters as
the real one and then just swaps ycp_edit/ycp_temp and returns, so it renders
nothing - an abandoned port, left in the binary but unregistered.

Run via main.py:
    uv run main.py inspect/glint/find_glint_addr.py
    uv run main.py inspect/glint/find_glint_addr.py --name 発光
"""

import argparse

from tools.filter_table import (HEAD_VA, OFF_CHECK_DEFAULT, OFF_CHECK_N, OFF_CHECK_NAME,
                                OFF_FUNC_PROC, OFF_NAME, OFF_TRACK_N, dump, read_entry,
                                summarize, walk)
from tools.pe_image import PEImage
from tools.xrefs import scan

TARGET = "閃光"


def find_unregistered(img: PEImage, registered: list, name: str) -> list:
    """Struct-shaped .data that names `name` but is missing from the table.

    The scan is anchored on the name pointer rather than on any code address:
    every registration must hold one at +0x0C, so every candidate base is
    (address of a dword equal to the name pointer) - 0x0C. Requiring a
    plausible func_proc on top of that is enough to reject coincidences.
    """
    name_ptr = img.u32(registered[0].struct_va + OFF_NAME)
    known = {r.struct_va for r in registered}
    out = []
    for va in scan(img, name_ptr):
        base = va - OFF_NAME
        if base in known or not img.valid(base, 0x80):
            continue
        func_proc = img.u32(base + OFF_FUNC_PROC)
        if not func_proc or not img.valid(func_proc):
            continue
        if img.cstr(img.u32(base + OFF_NAME)) != name:
            continue
        out.append(read_entry(img, base))
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default=TARGET)
    args = parser.parse_args(argv or [])

    img = PEImage(dll_path)
    regs = [r for r in walk(img) if r.name == args.name]
    if not regs:
        print(f"no effect named {args.name!r}")
        return

    print(f"### registered entries for {args.name!r} (from the 0x{HEAD_VA:08x} array)")
    for r in regs:
        dump(r)
    summarize(regs, args.name)

    ghosts = find_unregistered(img, regs, args.name)
    print(f"\n### struct-shaped .data naming {args.name!r} but absent from the array")
    if not ghosts:
        print("  none - every registration of this effect is reachable")
        return
    for g in ghosts:
        dump(g)
        refs = scan(img, g.struct_va)
        print(f"  references to 0x{g.struct_va:08x} anywhere in the image: {len(refs)}"
              f"{'' if refs else '  <- dead struct, nothing can reach it'}")
        # The give-away that this is the frame-filter twin: same trackbars, and
        # its checkbox list is the tail of the object entry's (no サイズ固定,
        # no 前方に合成) - the same trimming 発光's frame registration does.
        obj = regs[0]
        print(f"  trackbars identical to the registered entry: "
              f"{g.track_names == obj.track_names and g.track_defaults == obj.track_defaults}")
        print(f"  checkboxes: {[c for c in g.check_names]}  (registered entry has "
              f"{[c for c in obj.check_names]})")
        print(f"  shares func_WndProc: 0x{g.func_wndproc:08x} == 0x{obj.func_wndproc:08x} -> "
              f"{g.func_wndproc == obj.func_wndproc}")
        print(f"  its own func_proc: 0x{g.func_proc:08x}  (registered: 0x{obj.func_proc:08x})")
        print(f"  track_n={img.u32(g.struct_va + OFF_TRACK_N)} "
              f"check_n={img.u32(g.struct_va + OFF_CHECK_N)} "
              f"check_name=0x{img.u32(g.struct_va + OFF_CHECK_NAME):08x} "
              f"check_default=0x{img.u32(g.struct_va + OFF_CHECK_DEFAULT):08x}"
              f"   <- these point *into* the registered entry's arrays, at [1]")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
