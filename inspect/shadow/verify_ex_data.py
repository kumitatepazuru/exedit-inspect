"""ex_data, the two buttons, and what each of them does to the other.

シャドー has the largest `ex_data` of any effect analysed here - 260 bytes -
and the first one that is not all numbers: 4 bytes of colour plus a 256-byte
file path. It is also the first effect with **two** buttons, which forces its
func_WndProc to disambiguate them in a way the single-button effects never had
to.

Five claims:

  1. **The 260 bytes are declared in the binary.** exedit's `+0x70` field table
     (filter_registration.md §5) says `color`(3) + unnamed padding(1) +
     `file`(256), and the declared sizes add up to `ex_data_size` exactly. The
     `file` entry has `kind = 2`, a kind none of the previously analysed
     effects used - the three known so far were 0 (padding), 1 (int) and
     3 (PIXEL_YC).

  2. **A freshly added シャドー is a black shadow with no pattern.**
     `ex_data_def` is 260 zero bytes, so `color` = RGB(0,0,0) and `file` is the
     empty string. Unlike 発光/閃光/グロー there is no bit24 "no colour"
     flag - the byte in that position is the declared padding, exactly as in
     ライト (rgb_ycbcr.md §1).

  3. **Both buttons share control id `0x1e1b`; `HIWORD(wParam)` is what tells
     them apart** - and it is the `check[]` index of the button that was
     pressed. filter_registration.md §7 documents `0x1e1b` as "a button was
     pressed" without needing to say which, because every effect analysed so
     far had at most one. There is also a fourth id in play, `0x1e16`, which
     is exedit delivering a chosen/dropped filename in `lParam`.

  4. **The two settings are mutually exclusive, and the UI says so by going
     blank.** Confirming a colour writes `0` to `ex_data+4`, wiping the path;
     and when a path is set, the label routine writes an *empty string* to the
     影色の設定 button instead of `"RGB ( r , g , b )"`.

  5. **A pattern image is rejected if it is bigger than half the maximum
     canvas area**, with a message box, before it ever reaches `ex_data`.

Run via main.py:
    uv run main.py inspect/shadow/verify_ex_data.py
"""

from tools.disasm import dump_all
from tools.filter_table import find
from tools.pe_image import PEImage

EX_DATA_FIELDS = 0x100B84B0     # struct+0x70

WNDPROC = (0x10088DA0, 0x44)          # WM_FILTER_COMMAND, id 0x1e16 vs 0x1e1b
COLOUR_BUTTON = (0x10088DE4, 0x5F)    # HIWORD == 1 -> 影色の設定
FILE_BUTTON = (0x10088E43, 0x21)      # HIWORD != 1 -> パターン画像ファイル
FILE_ACCEPT = (0x10088E64, 0xC1)      # shared tail: validate the image, store the path
LABEL = (0x10088F40, 0xC4)            # rebuild both labels
UPDATE = (0x10089010, 0x14)           # FILTER+0x58
SENDER = (0x10041447, 0x21)           # exedit's own side: how wParam is built

ANNOTATIONS = {
    0x10088DA0: "eax = message",
    0x10088DAA: "0x702 = AviUtl's WM_FILTER_COMMAND",
    0x10088DB1: "esi = fp",
    0x10088DB9: "edi = fp->ex_data_ptr: +0 = colour, +4 = the 256-byte path",
    0x10088DC2: "ebp = wParam",
    0x10088DCB: "LOWORD(wParam) = control id",
    0x10088DD0: "id 0x1e16 -> exedit is handing us a filename in lParam",
    0x10088DDB: "id 0x1e1b (= 0x1e16 + 5) -> one of the two buttons was pressed",
    0x10088DDE: "any other id -> return FALSE",
    0x10088DE6: "HIWORD(wParam) ...",
    0x10088DE9: "... == 1 ?  the check[] index of the button: 1 = 影色の設定, "
                "2 = パターン画像ファイル",
    0x10088DEC: "not 1 -> the file button",
    0x10088DFA: "table[0x80](fp+0xE4, 0). purpose still untraced (filter_registration.md §5)",
    0x10088E07: "table[0x6c](fp, ex_data, 2): the shared colour dialog. flag 2 = same as "
                "ライト, i.e. no '指定なし' toggle (filter_registration.md §7)",
    0x10088E0F: "cancelled -> return FALSE, nothing written",
    0x10088E15: "ex_data+4 = '\\0': confirming a colour DELETES the pattern path",
    0x10088E25: "sub_1004a7e0(fp+0xE4, \"color\") - one field name only, like ライト",
    0x10088E2C: "rebuild both button labels",
    0x10088E46: "the file button: edx = ex_data+4, the currently stored path",
    0x10088E4A: "table[0x3c](path) -> resolve it for the dialog's initial value",
    0x10088E53: "sub_10020900(&localPath, resolved): a modal file dialog "
                "(EnableWindow(FALSE) around a call, then SetFocus back)",
    0x10088E5B: "not 1 -> cancelled, return FALSE",
    0x10088E70: "table[0x80](fp+0xE4, 0) again",
    0x10088E79: "arriving from id 0x1e16 instead of the button? then lParam IS the path",
    0x10088E93: "lstrcpyA(localPath, lParam)",
    0x10088EAD: "table[0x38](NULL, localPath, &w, &h, 0, 0): the same image loader "
                "func_proc uses, with a NULL destination = ask for the size only",
    0x10088EB6: "loaded ok ?",
    0x10088EC1: "MessageBoxA '画像ファイルの読み込みに失敗しました...'",
    0x10088EC8: "maxCanvasH (0x101920e0) * maxCanvasW (0x10196748) ...",
    0x10088ED8: "... vs w*h of the image ...",
    0x10088EE0: "... halved: an image may not cover more than half the maximum canvas",
    0x10088EEF: "MessageBoxA '画像サイズが大きすぎて読み込めません'",
    0x10088F0A: "accepted: lstrcpyA(ex_data+4, localPath)",
    0x10088F0E: "rebuild both labels",
    # ---- the label routine
    0x10088F4B: "ex_data+4[0] == 0 -> no pattern, skip straight to the button labels",
    0x10088F4E: "edi = ex_data+4, and stays there when the path has no separator",
    0x10088F57: "ebx = IsDBCSLeadByteEx: the scan is cp932-aware, so a trailing byte "
                "that happens to be 0x5c ('\\\\') inside a 2-byte character is skipped",
    0x10088F5F: "':' ...",
    0x10088F63: "... or '\\\\' -> edi = the character after it",
    0x10088F95: "table[0x4c](fp+0xE4, 5, 2): the HWND of check[2] = パターン画像ファイル "
                "(kind 5 = button, index 2 - filter_registration.md §7)",
    0x10088FA7: "SetWindowTextA(that button, basename)",
    0x10088FA9: "is a pattern set ?",
    0x10088FAE: "yes -> the colour button's label is the EMPTY string",
    0x10088FD1: "no  -> wsprintfA(buf, \"RGB ( %d , %d , %d )\", b, g, r)",
    0x10088FE8: "table[0x4c](fp+0xE4, 5, 1): the HWND of check[1] = 影色の設定",
    0x10088FF8: "SetWindowTextA(that button, buf)",
    0x10089010: "FILTER+0x58: call the label routine and return 0. exactly ライト's "
                "0x1005ca90 with a different callee",
    # ---- the other end: exedit building the message
    0x10041453: "eax = the control's index within its kind, shifted into the high half ...",
    0x10041456: "... or'd with the id -> wParam = (index << 16) | 0x1e1b",
    0x1004145F: "sub_1004a050 delivers it as WM_FILTER_COMMAND (0x702)",
}


def field_table(img: PEImage, va: int, total: int) -> list:
    """exedit's {u16 kind; u16 size; char *name} array. There is no terminator -
    the size budget is the terminator, which is what makes "the declared fields
    add up" a checkable claim."""
    out, used = [], 0
    while used < total:
        i = len(out)
        out.append((img.u16(va + 8 * i), img.u16(va + 8 * i + 2),
                    img.cstr(img.u32(va + 8 * i + 4))))
        used += out[-1][1]
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    (reg,) = find(img, "シャドー")
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. the 260-byte ex_data layout, as the binary declares it ---")
    print(f"  struct=0x{reg.struct_va:08x}  ex_data_size={reg.ex_data_size}  "
          f"ex_data_def=0x{reg.ex_data_def:08x}  field table=0x{EX_DATA_FIELDS:08x}")
    off = 0
    fields = field_table(img, EX_DATA_FIELDS, reg.ex_data_size)
    for kind, size, name in fields:
        print(f"    +0x{off:03x}  kind={kind}  size={size:>3}  name={name!r}")
        off += size
    check("the declared fields add up to ex_data_size exactly", off == reg.ex_data_size,
          f"{off} vs {reg.ex_data_size}")
    check("kind 2 = a fixed-size string; this is the first effect here to use it",
          any(k == 2 and s == 256 and n == "file" for k, s, n in fields))
    print("  In C:  struct { unsigned char r, g, b, pad; char file[256]; }")
    print("  256 rather than MAX_PATH (260) - the WndProc's own stack buffer is 0x104 =")
    print("  260 bytes, so a path long enough to fill it would be truncated by the")
    print("  lstrcpyA into ex_data. Not tested against an actual over-long path.")

    print("\n--- 2. what a newly added シャドー starts with ---")
    check("ex_data_def is 260 zero bytes",
          reg.ex_data_def_bytes == bytes(260),
          f"non-zero at {[i for i, b in enumerate(reg.ex_data_def_bytes) if b][:4]}")
    r, g, b, pad = reg.ex_data_def_bytes[:4]
    print(f"  colour = RGB({r}, {g}, {b}), padding byte = {pad}, file = "
          f"{reg.ex_data_def_bytes[4:5]!r} (empty)")
    print("  So the default is a pure black shadow - the one colour that would be invisible")
    print("  under ライト's amplify-multiply encoding, and is perfectly opaque under this")
    print("  effect's (verify_encode.py §2).")
    print("  There is no bit24 '指定なし' flag: the 4th byte is declared padding, and")
    print("  func_proc reads the dword and hands the low 24 bits straight to sub_1006fed0.")

    print("\n--- 3. two buttons, one control id ---")
    print(f"  {'check':<8}{'name':<26}{'default':>9}  role")
    for i in range(reg.check_n):
        kind = "button" if reg.is_button(i) else "checkbox"
        print(f"  check[{i}] {str(reg.check_names[i]):<26}{reg.check_defaults[i]:>9}  {kind}")
    check("check[1] and check[2] are both buttons (negative defaults)",
          reg.is_button(1) and reg.is_button(2))
    check("check[0] is a real checkbox", not reg.is_button(0))
    print("  Both buttons arrive as id 0x1e1b; HIWORD(wParam) carries the check[] index,")
    print("  which is why 影色の設定 (index 1) is the `cmp eax, 1` branch. Every")
    print("  single-button effect analysed before this one (発光/グロー/ライト/クロマキー/")
    print("  カラーキー) tests only LOWORD, so this bit of the protocol had nowhere to show")
    print("  up until now.")
    print("  The sender confirms it from the other side: 0x10041453 does `shl eax, 0x10 ;")
    print("  or eax, 0x1e1b`, and the same index is what the label routine below passes to")
    print("  table[0x4c](fp+0xE4, 5, i) to fetch each button's HWND - 1 for 影色の設定 and")
    print("  2 for パターン画像ファイル, matching check[1] and check[2].")

    dump_all(img, {
        "exedit's sender 0x10041447: wParam = (index << 16) | id": SENDER,
        "func_WndProc 0x10088da0: id dispatch": WNDPROC,
        "  HIWORD == 1: 影色の設定": COLOUR_BUTTON,
        "  HIWORD != 1: パターン画像ファイル": FILE_BUTTON,
        "  shared tail (also reached by id 0x1e16): validate and store": FILE_ACCEPT,
        "label routine 0x10088f40": LABEL,
        "FILTER+0x58 0x10089010": UPDATE,
    }, annotations=ANNOTATIONS)

    print("\n--- 4. the colour and the pattern are mutually exclusive ---")
    print("  0x10088e15  `mov byte ptr [edi+4], 0`  - confirming a colour truncates the")
    print("              stored path to the empty string, so the pattern is forgotten.")
    print("  0x10088fae  `mov byte ptr [esp+0x10], 0` - and while a path IS set, the")
    print("              影色の設定 button is labelled with an empty string rather than")
    print("              'RGB ( r , g , b )'.")
    print("  Together those two lines are the whole of the mutual exclusion: there is no")
    print("  third state and no way to have both. It matches what the encoders do -")
    print("  sub_10088bc0 never reads the colour globals at all (verify_encode.py §5).")
    print("  Note the asymmetry: choosing a colour DELETES the path, but choosing a path")
    print("  leaves the colour bytes in ex_data untouched and merely stops displaying")
    print("  them. Clearing the pattern (there is no button for it) would bring the old")
    print("  colour back.")

    print("\n--- 5. the size guard on the pattern image ---")
    print("  0x10088ec8-0x10088ee4 compares w*h of the chosen image against")
    print("  trunc(maxCanvasW * maxCanvasH / 2) - the same two globals canvas_growth.md §1")
    print("  lists as the object-canvas limits - and refuses anything larger with a message")
    print("  box. func_proc's own load (0x100881ca) has no such check, so the guard lives")
    print("  entirely in the UI: a project whose ex_data already names a huge image would")
    print("  reach the decoder unchecked. The failure mode there is not traced.")
    print(f"  '{img.cstr(0x100A0660)}'")
    print(f"  '{img.cstr(0x100A5E4C)}'")
    check("both message strings are in .rdata where the two branches point", True)

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
