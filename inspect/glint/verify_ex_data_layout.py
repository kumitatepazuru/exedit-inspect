"""Decode 閃光's 8-byte ex_data - the two buttons' state - by reading the
field table exedit keeps for it, and check the decoding against every other
filter in the binary.

閃光 has two of the three "checkboxes" as buttons (negative check_default:
-1 for 光色の設定, -2 for 前方に合成), and neither lives in fp->check[]. Both
live in ex_data, which the registration declares as 8 bytes. func_proc reads
it as two dwords - `[ebx]` for the colour and `[ebx+4]` for the composite mode
- but that alone does not say what the bytes mean or what they are called.

The names are in a table at FILTER+0x70. AviUtl's FILTER has func_is_saveframe
there; exedit overloads it, the same way it overloads +0x74 for the display
scales (tools/track_scale.py). Each entry is

    u16 kind ; u16 size ; const char *name

and the entries lay the ex_data out in order. For 閃光:

    kind 3, size 3, "color"       bytes 0..2   R, G, B (COLORREF order)
    kind 1, size 1, "no_color"    byte  3      the 0x1000000 bit func_proc tests
    kind 1, size 4, "mode"        bytes 4..7   0/1/2 = 前方/後方に合成/光成分のみ

The check is that the sizes add up to ex_data_size for every filter that has
one - if the field were something else, agreement across ~30 filters with
sizes from 4 to 260 bytes would be a coincidence.

Run via main.py:
    uv run main.py inspect/glint/verify_ex_data_layout.py
"""

from tools.filter_table import OFF_EX_DATA_DEF, walk
from tools.pe_image import PEImage

OFF_EX_DATA_NAMES = 0x70

# 閃光's 前方に合成 button cycles a 3-item list of adjacent cp932 strings that
# func_WndProc (0x1004f4ea) pushes into a combo box.
MODE_STRINGS_VA = 0x100A5C5C
MODE_COUNT = 3


def fields(img: PEImage, reg):
    """Walk the +0x70 table until the declared ex_data_size is accounted for."""
    p = img.u32(reg.struct_va + OFF_EX_DATA_NAMES)
    if not p or not img.valid(p) or not reg.ex_data_size:
        return []
    out, off = [], 0
    for i in range(32):
        kind = img.u16(p + 8 * i)
        size = img.u16(p + 8 * i + 2)
        name_ptr = img.u32(p + 8 * i + 4)
        if size == 0 and kind == 0:
            break
        name = img.cstr(name_ptr) if name_ptr and img.valid(name_ptr) else None
        out.append((off, kind, size, name))
        off += size
        if off >= reg.ex_data_size:
            break
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    regs = walk(img)

    print("1) does the table account for exactly ex_data_size bytes, everywhere?")
    print(f"   {'filter':<18}{'declared':>9}{'summed':>8}  fields")
    ok = bad = 0
    for r in regs:
        if not r.ex_data_size:
            continue
        fs = fields(img, r)
        if not fs:
            continue
        total = sum(f[2] for f in fs)
        good = total == r.ex_data_size
        ok, bad = ok + good, bad + (not good)
        desc = ", ".join(f"{n or '<unnamed>'}[{s}]" for _, _, s, n in fs)
        print(f"   {'OK ' if good else '!! '}{r.name:<15}{r.ex_data_size:>9}{total:>8}  {desc[:60]}")
    print(f"   -> {ok} filters agree, {bad} disagree")

    print("\n2) 閃光's ex_data, field by field")
    glint = next(r for r in regs if r.name == "閃光")
    default = img.code(img.u32(glint.struct_va + OFF_EX_DATA_DEF), glint.ex_data_size)
    print(f"   ex_data_size={glint.ex_data_size}  default bytes = {default.hex(' ')}")
    print(f"   {'off':>4}{'kind':>6}{'size':>6}  {'name':<10} default        meaning")
    meanings = {
        "color": "RGB, byte0=R byte1=G byte2=B (Win32 COLORREF order)",
        "no_color": "1 = use each pixel's own colour; this is bit24 of dword[0]",
        "mode": "前方に合成 button: 0/1/2",
    }
    for off, kind, size, name in fields(img, glint):
        raw = default[off:off + size]
        print(f"   {off:>4}{kind:>6}{size:>6}  {str(name):<10} {raw.hex(' '):<14} "
              f"{meanings.get(name, '')}")

    print("\n3) the two dwords func_proc reads, reconstructed from those fields")
    d0 = int.from_bytes(default[0:4], "little")
    d1 = int.from_bytes(default[4:8], "little")
    print(f"   dword[0] = 0x{d0:08x}  -> R={d0 & 0xff} G={(d0 >> 8) & 0xff} "
          f"B={(d0 >> 16) & 0xff}, no_color bit24 = {(d0 >> 24) & 1}")
    print(f"   dword[1] = 0x{d1:08x}  -> mode {d1}")
    print("   func_proc tests exactly that bit (`test eax, 0x1000000` at 0x1004e8af)")
    print("   to pick between the two workers, and branches on dword[1] at 0x1004e8d6.")

    print("\n4) what mode 0/1/2 are called, from the string table func_WndProc uses")
    for i in range(MODE_COUNT):
        va = MODE_STRINGS_VA
        for _ in range(i):
            va += len(img.cstr(va).encode("cp932")) + 1
        print(f"   mode {i} = {img.cstr(va)!r}")
    print("   func_proc: mode 0 blits the original object onto the glint with 0x11000003,")
    print("   mode 1 with 3, mode 2 skips the blit entirely (`jne` at 0x1004e8ea) and")
    print("   leaves only the light. The two blend constants are exedit-internal.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
