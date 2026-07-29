"""The key colour: where it is stored, how it gets there, and what it shares.

Like クロマキー, カラーキー's main parameter is not a trackbar - the trackbars
only *widen* a key that has to be picked with an eyedropper first, and the key
itself lives in `ex_data`. Unlike クロマキー, all three components of that
colour are used.

Five claims, checked here:

  1. **The layout is declared in the binary.** exedit's `+0x70` field table
     (`inspect/common/filter_registration.md` §5) at `0x100a16a0` says the 12
     bytes are `color_yc` (kind 3, 6 bytes) + 2 bytes of padding + `status`
     (kind 1, 4 bytes), and the declared sizes add up to `ex_data_size`. It is
     a *different table* from クロマキー's `0x100a0dd0` with identical contents.

  2. **`status` is a tri-state, not a boolean**, with the same three values and
     the same meanings as クロマキー's - func_proc runs only for `status == 1`.

  3. **The whole eyedropper protocol is shared with クロマキー**: same control
     ids `0x1e1b` / `0x1e1d`, same `table[0x80]` / `table[0x68]` / `table[0x4c]`
     calls, same three cp932 label strings (the *same addresses*, not copies),
     and the same "arm, then cancel, and the key colour is gone" behaviour.
     The one difference is the argument to `table[0x4c]`, which is the index of
     the button in `check_name[]` - 0 here, 2 in クロマキー.

  4. **All three colour components are read by the worker.** クロマキー's
     workers read `+2` and `+4` only; カラーキー's key worker reads `+0`, `+2`
     and `+4`. Two effects with byte-identical `ex_data` layouts, one of which
     ignores a third of it.

  5. **`ex_data_def` is 12 zero bytes**, so a freshly added カラーキー has
     `status == 0` and is a no-op until the eyedropper is used.

Run via main.py:
    uv run main.py inspect/color_key/verify_ex_data.py
"""

import struct

from tools.disasm import dump_all, function_body
from tools.filter_table import find
from tools.pe_image import PEImage

EX_DATA_FIELDS = 0x100A16A0         # struct+0x70
CK_EX_DATA_FIELDS = 0x100A0DD0      # クロマキー's, for comparison
WND_PROC = (0x10016850, 0xE1)
LABEL = (0x10016940, 0x9D)
HOOK = (0x100169E0, 0x14)

KEY_WORKER = 0x10016340
WORKERS = {
    KEY_WORKER: "the key test",
    0x10016430: "境界補正 pass2 (vertical box)",
    0x100165D0: "境界補正 pass3 (horizontal + apply)",
}

ANNOTATIONS = {
    # ---- func_WndProc
    0x10016850: "uMsg",
    0x1001685A: "0x702 = AviUtl's WM_FILTER_COMMAND",
    0x1001685F: "esi = fp->ex_data_ptr, kept across every branch",
    0x1001686C: "LOWORD(wParam) = control id",
    0x10016871: "id 0x1e1b -> the キー色の取得 button was pressed",
    0x10016878: "id 0x1e1d -> exedit is delivering a picked colour",
    0x10016885: "lParam == 0 means the pick was cancelled",
    0x10016889: "PIXEL_YC y  -> ex_data+0",
    0x10016890: "PIXEL_YC cb -> ex_data+2",
    0x10016898: "PIXEL_YC cr -> ex_data+4",
    0x100168A1: "status = 1: from here on func_proc will actually run",
    0x100168BA: "cancelled: status = 0",
    0x100168DD: "button path: table[0x80](fp+0xE4, 0) first - purpose not traced",
    0x100168E9: "status == 2 -> the eyedropper is already armed",
    0x100168FA: "arm it: table[0x68](fp+0xE4, 1)",
    0x100168FD: "status = 2",
    0x1001690D: "disarm: table[0x68](0, 0)",
    0x10016910: "status = 0 - arming and then cancelling *forgets the key colour*",
    0x1001692D: "any other message: return FALSE",
    # ---- the label routine
    0x10016959: "table[0x4c](fp+0xE4, 5, 0) -> the button's HWND. The 0 is the",
    0x1001695C: "  index in check_name[]; クロマキー passes 2 for the same call",
    0x1001696B: "status == 1?",
    0x10016970: "cr ...",
    0x10016974: "... cb ...",
    0x1001697A: "... and y",
    0x10016982: "'YCbCr ( %d , %d , %d )' - the same string クロマキー uses",
    0x10016988: "wsprintfA",
    0x10016997: "SetWindowTextA",
    0x100169A5: "status == 2?",
    0x100169AE: "'マウスをクリックして色を取得してください'",
    0x100169BA: "status 0 (or anything else): '< 未取得 >'",
    # ---- FILTER+0x58
    0x100169E4: "fp->ex_data_ptr",
    0x100169E9: "the settings-window update entry: relabel and nothing else",
}


def field_table(img: PEImage, va: int, total: int) -> list:
    """Read exedit's {u16 kind; u16 size; char *name} array until it fills
    ex_data_size. The table has no terminator - the size budget is the
    terminator, which is what makes 'the declared fields add up' checkable."""
    out, used = [], 0
    while used < total:
        kind = img.u16(va + 8 * len(out))
        size = img.u16(va + 8 * len(out) + 2)
        name = img.cstr(img.u32(va + 8 * len(out) + 4))
        out.append((kind, size, name))
        used += size
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    (reg,) = find(img, "カラーキー")
    (ck,) = find(img, "クロマキー")

    print("--- 1. the ex_data layout, as the binary declares it ---")
    print(f"  struct=0x{reg.struct_va:08x}  ex_data_size={reg.ex_data_size}  "
          f"ex_data_def=0x{reg.ex_data_def:08x}  field table=0x{EX_DATA_FIELDS:08x}")
    fields = field_table(img, EX_DATA_FIELDS, reg.ex_data_size)
    off = 0
    for kind, size, name in fields:
        print(f"    +0x{off:02x}  kind={kind}  size={size}  name={name!r}")
        off += size
    print(f"  -> declared bytes = {off}, ex_data_size = {reg.ex_data_size}: "
          f"{'OK' if off == reg.ex_data_size else 'MISMATCH'}")
    print("  kind 3 = PIXEL_YC, kind 1 = int, kind 0 = unnamed padding to align it.")
    print("  In C:  struct { short y, cb, cr; short pad; int status; }")

    ck_fields = field_table(img, CK_EX_DATA_FIELDS, ck.ex_data_size)
    print(f"  クロマキー's own table 0x{CK_EX_DATA_FIELDS:08x} declares {ck_fields}")
    print(f"  -> identical contents, separate tables: "
          f"{'OK' if ck_fields == fields else 'they differ'}")

    print("\n--- 5. what a newly added カラーキー starts with ---")
    words = struct.unpack("<3hhi", reg.ex_data_def_bytes)
    print(f"  ex_data_def bytes = {reg.ex_data_def_bytes.hex(' ')}  (0x{reg.ex_data_def:08x})")
    print(f"  -> y={words[0]} cb={words[1]} cr={words[2]} pad={words[3]} status={words[4]}")
    print("  status = 0, so func_proc's first test fails and the effect is a no-op")
    print("  until the eyedropper is used. The trackbar defaults are 0/0/0 as well")
    print(f"  ({reg.track_defaults}), so even after picking a colour the effect starts")
    print("  out keying only pixels that match it exactly - see verify_key_box.py.")

    print("\n--- 3. what the two eyedropper effects share ---")
    print(f"  {'':<26}{'カラーキー':<14}{'クロマキー':<14}")
    rows = [
        ("func_WndProc", reg.func_wndproc, ck.func_wndproc),
        ("FILTER+0x58", img.u32(reg.struct_va + 0x58), img.u32(ck.struct_va + 0x58)),
        ("+0x70 field table", EX_DATA_FIELDS, CK_EX_DATA_FIELDS),
        ("+0x74 ext block (both NULL)", reg.ext_va, ck.ext_va),
        ("'キー色の取得'", img.u32(img.u32(reg.struct_va + 0x28)),
         img.u32(img.u32(ck.struct_va + 0x28) + 8)),
        ("'境界補正'", img.u32(img.u32(reg.struct_va + 0x14) + 8),
         img.u32(img.u32(ck.struct_va + 0x14) + 8)),
    ]
    for label, a, b in rows:
        same = "  <- same address" if a == b and a else ""
        print(f"  {label:<28}0x{a:08x}    0x{b:08x}{same}")
    for va in (0x100A0FBC, 0x100A0FC8, 0x100A0FF4):
        print(f"  label string 0x{va:08x} = {img.cstr(va, 80)!r}   (used by both)")
    print("  The button and the two UI strings are literally shared symbols, not")
    print("  duplicated text: MSVC pooled them because the two effects were written")
    print("  from the same source. The code is a copy, the data is not.")

    print("\n--- 4. which worker can see the key colour at all? ---")
    print(f"  {'worker':>12}  {'role':<34} reads fp->ex_data_ptr?")
    for addr, role in WORKERS.items():
        has = any(insn.op_str.endswith("+ 0x4c]")
                  for insn in function_body(img, addr, 0x400))
        print(f"  0x{addr:08x}  {role:<34} {'yes' if has else 'no'}")
    print("  Only the key worker. The two border passes take everything from the two")
    print("  globals and fpip - they never see the key colour, only the alpha it left")
    print("  behind. That is why カラーキー needs two globals where クロマキー needs")
    print("  five: there is no matte to point at.")

    print("\n  and which components of it does that worker read?")
    # ex_data reaches the worker in ecx (0x10016364); the three field reads are
    # the movsx that follow, at +0 (no displacement), +2 and +4. Report them
    # with their addresses rather than as a set of displacements, because a
    # bare `[ecx]` is indistinguishable from a pixel read when summarised.
    for insn in function_body(img, KEY_WORKER, 0x400):
        if insn.mnemonic == "movsx" and 0x10016360 <= insn.address <= 0x10016390:
            print(f"    0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    print("    -> [ecx] = y, [ecx+2] = cb, [ecx+4] = cr, where ecx is ex_data_ptr")
    print("       (loaded at 0x10016364, before the pixel loop is entered).")
    print("  All three. クロマキー's seven workers read +2 and +4 and never +0 - its")
    print("  key colour's luminance is written, displayed, saved and ignored. Here the")
    print("  same 12-byte ex_data is fully used, so two key colours with the same")
    print("  chroma and different brightness are NOT interchangeable.")

    dump_all(img, {
        "func_WndProc 0x10016850": WND_PROC,
        "settings-window label 0x10016940": LABEL,
        "FILTER+0x58 hook 0x100169e0": HOOK,
    }, annotations=ANNOTATIONS)

    print(
        "\n"
        "--- 2. status is a tri-state ---\n"
        "   0  '< 未取得 >'                                   func_proc returns immediately\n"
        "   1  'YCbCr ( y , cb , cr )'                        the only value that filters\n"
        "   2  'マウスをクリックして色を取得してください'      also returns immediately\n"
        "\n"
        "So the effect is disabled while the eyedropper is armed, and pressing the\n"
        "button a second time to disarm it sets status back to 0 - it does not restore\n"
        "the colour that was there before (0x10016910), exactly as in クロマキー.\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
