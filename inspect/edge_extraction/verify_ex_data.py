"""`色の設定` - a mandatory colour, not an optional one.

発光, 閃光, グロー and グラデーション all keep the picked colour in an `ex_data`
that has a **`no_color` byte** next to it: bit24 of the first dword, the
「指定なし (元画像の色)」 flag ([`rgb_ycbcr.md`](../common/rgb_ycbcr.md)).
エッジ抽出's `ex_data` is the same 4 bytes but declares the fourth as an
*unnamed pad*, and nothing in the effect ever tests bit24.

That is not a detail of the table; it is visible in three independent places,
which is what this script lines up:

  1. the `+0x70` field table calls byte 3 nothing at all,
  2. `func_WndProc` opens the colour dialog with flag **2**, where the four
     effects that do have 「指定なし」 pass **0x102** - and the correlation holds
     across every caller of that dialog in the binary, which is what makes
     `0x100` = "offer 指定なし" more than a guess,
  3. the label rebuilder `0x10023c00` formats `RGB ( %d , %d , %d )`
     unconditionally, where 発光's `0x10054d10` starts with
     `test dword ptr [eax], 0x1000000`.

It follows from what the effect *does*: the output pixel's y/cb/cr are the
picked colour and nothing else (verify_output_encoding.py), so there is no
"each pixel's own colour" to fall back to.

Run via main.py:
    uv run main.py inspect/edge_extraction/verify_ex_data.py
"""

import re
import struct

from tools.disasm import disasm_range
from tools.filter_table import OFF_EX_DATA_DEF, walk
from tools.pe_image import PEImage

OFF_EX_DATA_NAMES = 0x70

# the RGB->YCbCr rows exedit's shared converter loads, Q14 (rgb_ycbcr.md)
YC_ROWS = {"B": 0x100A989C, "G": 0x100A98A4, "R": 0x100A98AC}

LABEL_FN = (0x10023C00, 0x54)
LUMINOUS_LABEL_FN = 0x10054D10


def fields(img: PEImage, reg):
    """Walk the +0x70 table until ex_data_size bytes are accounted for."""
    p = img.u32(reg.struct_va + OFF_EX_DATA_NAMES)
    if not p or not img.valid(p) or not reg.ex_data_size:
        return []
    out, off = [], 0
    for i in range(32):
        kind, size = img.u16(p + 8 * i), img.u16(p + 8 * i + 2)
        name_ptr = img.u32(p + 8 * i + 4)
        if size == 0 and kind == 0:
            break
        out.append((off, kind, size,
                    img.cstr(name_ptr) if name_ptr and img.valid(name_ptr) else None))
        off += size
        if off >= reg.ex_data_size:
            break
    return out


def dialog_calls(img: PEImage):
    """(caller VA, flag) for every `call [reg+0x6c]` - exedit's colour dialog.

    Found by byte pattern (`ff /r 6c`) rather than by disassembling, because the
    callers are spread over filters this project has not mapped. The flag is the
    last immediate pushed before the call.
    """
    sec = next(s for s in img.pe.sections if s.Name.rstrip(b"\x00") == b".text")
    base = img.image_base + sec.VirtualAddress
    blob = img.data[sec.VirtualAddress:sec.VirtualAddress + sec.Misc_VirtualSize]
    out = []
    for m in re.finditer(rb"\xff[\x50-\x57]\x6c", blob):
        va = base + m.start()
        pushes = [i.op_str for i, _ in disasm_range(img, va - 0x10, 0x12, resolve=False)
                  if i.mnemonic == "push"]
        imm = [p for p in pushes if p.startswith("0x") or p.isdigit()]
        out.append((va, int(imm[-1], 0) if imm else None))
    return out


def owner_names(img: PEImage):
    return sorted({(r.func_proc, r.name) for r in walk(img) if r.func_proc})


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    regs = walk(img)
    edge = next(r for r in regs if r.name == "エッジ抽出")

    print("--- 1. エッジ抽出's ex_data, field by field ---")
    default = img.code(img.u32(edge.struct_va + OFF_EX_DATA_DEF), edge.ex_data_size)
    print(f"  ex_data_size={edge.ex_data_size}  default bytes = {default.hex(' ')}"
          f"  (= 0x{int.from_bytes(default, 'little'):08x})")
    print(f"  {'off':>4}{'kind':>6}{'size':>6}  {'name':<12} bytes")
    for off, kind, size, name in fields(img, edge):
        print(f"  {off:>4}{kind:>6}{size:>6}  {str(name or '<unnamed>'):<12} "
              f"{default[off:off + size].hex(' ')}")
    print("  -> byte 3 has no name. Compare the four effects that do have one:")
    for r in regs:
        fs = fields(img, r)
        if any(n == "no_color" for _, _, _, n in fs):
            print(f"     {r.name:<14} " +
                  ", ".join(f"{n or '<unnamed>'}[{s}]" for _, _, s, n in fs))

    print("\n--- 2. the colour dialog flag, over every caller in the binary ---")
    names = owner_names(img)
    print(f"  {'caller':<12}{'flag':>7}  {'no_color field?':<17}filter (nearest func_proc)")
    rows = []
    for va, flag in dialog_calls(img):
        owner = "?"
        for addr, nm in names:
            if addr <= va:
                owner = nm
        has = any(n == "no_color" for r in regs if r.name == owner
                  for _, _, _, n in fields(img, r))
        rows.append((va, flag, has, owner))
        print(f"  0x{va:08x}{('0x%x' % flag) if flag is not None else '-':>7}  "
              f"{str(has):<17}{owner}")
    decided = [(f, h) for _, f, h, _ in rows if f in (2, 0x102)]
    agree = all((f == 0x102) == h for f, h in decided)
    print(f"  -> of the {len(rows)} `call [reg+0x6c]` sites in .text, {len(decided)} push a")
    print(f"     literal 2 or 0x102, and bit 0x100 agrees with 'has a no_color field'")
    print(f"     in every one of them: {agree}")
    print("     (the rest either build the flag in a register - 拡張色設定 ors in 0x400 -")
    print("      or are a different +0x6c call altogether, with only two arguments.)")

    print("\n--- 3. the label rebuilders ---")
    print(f"  エッジ抽出 0x{LABEL_FN[0]:08x}:")
    for insn, _ in disasm_range(img, *LABEL_FN, resolve=False):
        if insn.mnemonic in ("test", "and", "cmp") and "0x1000000" in insn.op_str:
            print(f"     !! bit24 test found at 0x{insn.address:08x}")
            break
    else:
        print("     no test of bit24 anywhere in it")
    fmt = next((int(i.op_str, 16) for i, _ in disasm_range(img, *LABEL_FN, resolve=False)
                if i.mnemonic == "push" and i.op_str.startswith("0x100")
                and img.valid(int(i.op_str, 16)) and "%d" in img.cstr(int(i.op_str, 16))), 0)
    print(f"     its only format string is 0x{fmt:08x} = {img.cstr(fmt)!r}")
    third = [i for i, _ in disasm_range(img, LUMINOUS_LABEL_FN, 0x20, resolve=False)][2]
    print(f"  発光 0x{LUMINOUS_LABEL_FN:08x}: third instruction (0x{third.address:08x}) is "
          f"`{third.mnemonic} {third.op_str}`")
    print("     - the 「指定無し (元画像の色)」 branch エッジ抽出 does not have.")

    print("\n--- 4. what the default white becomes ---")
    rgb = int.from_bytes(default[:3], "little")
    r, g, b = rgb & 0xFF, (rgb >> 8) & 0xFF, (rgb >> 16) & 0xFF
    rows_q14 = {k: struct.unpack_from("<3h", img.code(va, 6)) for k, va in YC_ROWS.items()}
    y, cb, cr = (sum(rows_q14[c][i] * v for c, v in (("R", r), ("G", g), ("B", b))) * 16
                 // 16384 for i in range(3))
    print(f"  ex_data 0x{rgb:06x} -> R={r} G={g} B={b}  (COLORREF order, bit24 = "
          f"{(int.from_bytes(default, 'little') >> 24) & 1})")
    print(f"  through the Q14 BT.601 rows -> roughly Y={y} Cb={cb} Cr={cr}")
    print("  i.e. plain white at full luminance; every output pixel gets exactly this,")
    print("  and only the alpha varies. Picking a dark colour does *not* weaken the")
    print("  effect the way it does in 発光/グロー - here the colour never multiplies")
    print("  anything ([rgb_ycbcr.md](../common/rgb_ycbcr.md) section 4).")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
