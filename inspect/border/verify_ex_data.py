"""縁取り's ex_data and its two buttons, checked against the tables and the
window procedure.

Five claims:

  1. **The 260-byte `ex_data` is byte-for-byte シャドー's layout**: `color`(3)
     + unnamed padding(1) + `file`(256). The two `+0x70` field tables are
     separate arrays with identical contents, down to sharing the same name
     strings - the same relationship クロマキー and カラーキー have.

  2. **The default is a black border and no pattern.** `ex_data_def`
     (0x101b1e48) is 260 zero bytes, and there is no bit24 "no colour" flag -
     the fourth byte is padding the field table does not name, exactly as in
     ライト and シャドー (rgb_ycbcr.md §1).

  3. **Two buttons share control ID `0x1e1b`, told apart by `HIWORD(wParam)`.**
     縁取り is only the second effect here to need that (シャドー §8), and the
     indices are shifted: 縁色の設定 is `check[0]` where シャドー's 影色の設定
     is `check[1]`, because シャドー has a real checkbox in front.

  4. **Colour and pattern are exclusive, and the asymmetry is the same as
     シャドー's**: picking a colour erases the path (0x100520e2), while
     setting a path only hides the colour (the colour button's label goes
     empty at 0x1005226e) and leaves the bytes in `ex_data`.

  5. **The `+0x74` block is nearly empty**: the display-scale array is two
     zeros in .data, and the grouping-marker and slider-drag pointers are all
     NULL - so both trackbars are shown raw and drag over their full range.

Run via main.py:
    uv run main.py inspect/border/verify_ex_data.py
"""

from tools.disasm import disasm_range
from tools.filter_table import find
from tools.pe_image import PEImage

STRUCT = 0x100A5CF8
FIELD_TABLE = 0x100A5CA8
EXT = 0x100A5CD8
EX_DATA_DEF = 0x101B1E48

SHADOW_STRUCT = 0x100B8560
SHADOW_FIELD_TABLE = 0x100B84B0

KINDS = {0: "unnamed padding", 1: "int", 2: "fixed-length string", 3: "colour"}


def fields(img: PEImage, table: int, limit: int = 8):
    """`{u16 kind; u16 size; char *name}[]` (filter_registration.md §5), read
    until the declared sizes add up to ex_data_size."""
    out, off = [], 0
    for i in range(limit):
        kind = img.u16(table + 8 * i)
        size = img.u16(table + 8 * i + 2)
        name = img.u32(table + 8 * i + 4)
        out.append({"kind": kind, "size": size, "offset": off,
                    "name": img.cstr(name) if name else None, "name_ptr": name})
        off += size
        if off >= 260:
            break
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)
    reg = find(img, "縁取り")[0]

    print("--- 1. the ex_data layout is シャドー's, in a separate table ---")
    mine = fields(img, FIELD_TABLE)
    theirs = fields(img, SHADOW_FIELD_TABLE)
    print(f"  {'off':>5}{'kind':>6}{'size':>6}  {'meaning':<22}{'name':<8}{'name ptr':>12}")
    for f in mine:
        print(f"  {f['offset']:>5}{f['kind']:>6}{f['size']:>6}  "
              f"{KINDS.get(f['kind'], '?'):<22}{str(f['name']):<8}0x{f['name_ptr']:08x}")
    check("the declared sizes add up to ex_data_size = 260",
          sum(f["size"] for f in mine) == reg.ex_data_size == 260,
          f"{sum(f['size'] for f in mine)} vs {reg.ex_data_size}")
    check("three fields: colour(3) + padding(1) + file(256)",
          [(f["kind"], f["size"]) for f in mine] == [(3, 3), (0, 1), (2, 256)],
          f"{[(f['kind'], f['size']) for f in mine]}")
    check("縁取り and シャドー declare identical fields ...",
          [(f["kind"], f["size"], f["name"]) for f in mine]
          == [(f["kind"], f["size"], f["name"]) for f in theirs])
    check("... reusing the very same name strings, from two different tables",
          [f["name_ptr"] for f in mine] == [f["name_ptr"] for f in theirs]
          and FIELD_TABLE != SHADOW_FIELD_TABLE,
          f"0x{FIELD_TABLE:08x} vs 0x{SHADOW_FIELD_TABLE:08x}")
    print("  Same relationship クロマキー (0x100a0dd0) and カラーキー (0x100a16a0) have:")
    print("  two tables, one layout. `file` (kind 2) is still only used by these two")
    print("  effects plus the file-backed objects.")

    print("\n--- 2. the default is a black border, no pattern ---")
    check("ex_data_def is 260 zero bytes", reg.ex_data_def == EX_DATA_DEF
          and reg.ex_data_def_bytes == b"\x00" * 260,
          f"0x{reg.ex_data_def:08x}, {len(reg.ex_data_def_bytes)} bytes")
    check("the colour field is 3 bytes, so there is no bit24 'no colour' flag",
          mine[0]["size"] == 3 and mine[1]["name"] is None)
    print("  R = byte0, G = byte1, B = byte2 (COLORREF order), so the default is")
    print("  RGB(0,0,0). 発光 / 閃光 / グロー put a 'use each pixel's own colour' flag")
    print("  in bit24; ライト, シャドー and 縁取り all leave that byte unnamed and")
    print("  always paint one colour (rgb_ycbcr.md §1).")
    print(f"  ex_data_def lives in .data at 0x{EX_DATA_DEF:08x}, just past the five")
    print("  per-frame globals - same arrangement as シャドー's 0x10231fb0.")

    print("\n--- 3. two buttons, one control ID, told apart by HIWORD ---")
    print(f"  checkboxes: {list(zip(reg.check_names, reg.check_defaults))}")
    check("both are buttons (negative check_default)",
          all(reg.is_button(i) for i in range(reg.check_n)), f"{reg.check_defaults}")
    ops = [(hex(i.address), i.mnemonic, i.op_str)
           for i, _ in disasm_range(img, 0x10052092, 0x30, resolve=False)]
    ids = [o for o in ops if o[1] == "sub"]
    check("func_WndProc accepts LOWORD 0x1e16 and 0x1e16+5 = 0x1e1b",
          [o[2] for o in ids][:2] == ["eax, 0x1e16", "eax, 5"], f"{ids[:2]}")
    hi = [o for o in ops if o[1] == "shr"]
    check("then splits on HIWORD(wParam) with `shr eax, 0x10`",
          hi and hi[0][2] == "eax, 0x10", f"{hi[:1]}")
    print("  HIWORD == 0 -> 縁色の設定 (the colour dialog at 0x100520bb)")
    print("  HIWORD != 0 -> パターン画像ファイル (the file dialog at 0x10052110)")
    # The label rebuild asks for the two button HWNDs by the same indices.
    idx = [(hex(i.address), i.op_str)
           for i, _ in disasm_range(img, 0x10052243, 0x70, resolve=False)
           if i.mnemonic == "push" and i.op_str in ("0", "1", "5")]
    check("the label rebuild fetches table[0x4c](fp+0xE4, 5, 1) then (.., 5, 0), i.e. "
          "kind 5 = button at indices 1 and 0", [o[1] for o in idx][:4] == ["1", "5", "0", "5"],
          f"{idx[:4]}")
    print("  シャドー's equivalents are indices 2 and 1, because its check[0] is the")
    print("  real checkbox 影を別オブジェクトで描画. 縁取り has no checkbox at all -")
    print("  which is also why it has no 別オブジェクトで描画 mode (README §7).")

    print("\n--- 4. colour and pattern are exclusive, asymmetrically ---")
    clear = [(hex(i.address), i.mnemonic, i.op_str)
             for i, _ in disasm_range(img, 0x100520E2, 0x10, resolve=False)][:1]
    check("confirming a colour writes a NUL over ex_data+4, erasing the path",
          clear and clear[0][2] == "byte ptr [edi + 4], 0", f"{clear}")
    blank = [(hex(i.address), i.mnemonic, i.op_str)
             for i, _ in disasm_range(img, 0x1005226E, 0x8, resolve=False)][:1]
    check("while a non-empty path only blanks the colour button's label",
          blank and blank[0][2] == "byte ptr [esp + 0x10], 0", f"{blank}")
    print("  So the two directions are not symmetric: choosing a colour destroys the")
    print("  path, choosing a path only hides the colour. Consistent with the encoders -")
    print("  the pattern worker never reads the colour globals (verify_encode.py §4).")

    print("\n--- 5. the +0x74 block is nearly empty ---")
    slots = img.u32_array(EXT, 4)
    names = ("display scale", "grouping marker", "slider drag min", "slider drag max")
    for n, s in zip(names, slots):
        vals = img.i32_array(s, reg.track_n) if s and img.valid(s, 4 * reg.track_n) else None
        print(f"  slot {names.index(n)} {n:<16} = 0x{s:08x}  {vals}")
    check("only the display-scale slot is non-NULL", [bool(s) for s in slots] == [1, 0, 0, 0],
          f"{[hex(s) for s in slots]}")
    check("and it is two zeros, i.e. both trackbars are shown raw",
          img.i32_array(slots[0], 2) == [0, 0], f"{img.i32_array(slots[0], 2)}")
    print(f"  {'track':<10}{'raw def':>9}{'raw range':>12}{'shown':>10}{'slider drag':>14}")
    for i in range(reg.track_n):
        print(f"  {str(reg.track_names[i]):<10}{reg.track_defaults[i]:>9}"
              f"{f'{reg.track_s[i]}..{reg.track_e[i]}':>12}"
              f"{reg.shown(i, reg.track_defaults[i]):>10}"
              f"{'full range':>14}")
    check("no grouping marker: サイズ and ぼかし are two independent trackbars",
          slots[1] == 0)
    print("  シャドー writes {0,0,10,0} into the same slot and NULLs the marker too")
    print("  (param_scaling.md §1); 縁取り goes one step further and leaves the drag")
    print("  ranges NULL as well, so the sliders span the whole 0..500 / 0..100.")
    print(f"  The scale array is at 0x{slots[0]:08x} - in .data, not .rdata, because it")
    print("  is all zeroes; the same reason カラーキー's track_s/track_e ended up there.")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
