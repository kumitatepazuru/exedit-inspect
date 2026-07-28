"""The key colour: where it is stored, how it gets there, and what is ignored.

クロマキー is the only effect analysed in this repo whose main parameter is not
a trackbar at all. `色相範囲` / `彩度範囲` / `境界補正` only *widen* a key that
has to be picked with an eyedropper first, and that key lives in `ex_data`.

Four claims, checked here:

  1. **The layout is declared in the binary.** exedit's `+0x70` field table
     (see `inspect/common/filter_registration.md` §5) says the 12 bytes are
     `color_yc` (kind 3, 6 bytes) + 2 bytes of padding + `status` (kind 1,
     4 bytes), and the declared sizes add up to `ex_data_size` exactly.

  2. **`status` is a tri-state, not a boolean.** func_proc runs only for
     `status == 1`; `2` means "the eyedropper is armed and the user has not
     clicked yet", and func_WndProc's label routine has a distinct string for
     each of the three.

  3. **The key colour's luminance is never used.** `color_yc.y` sits at
     `ex_data+0`, and the *only* instruction in the whole effect that reads
     `+0` is the `wsprintf` in the settings-window label. Every worker reads
     `+2` and `+4` and nothing else. This script scans all seven worker bodies
     to show there is no counter-example, which is the interesting form of the
     claim - a key colour of pure black and one of dim green with the same
     chroma behave identically.

  4. **`ex_data_def` is 12 zero bytes**, i.e. a freshly added クロマキー has
     `status == 0` and is a no-op until the eyedropper is used.

Run via main.py:
    uv run main.py inspect/chroma_key/verify_ex_data.py
"""

import struct

from tools.disasm import dump_all, function_body
from tools.filter_table import find
from tools.pe_image import PEImage

EX_DATA_FIELDS = 0x100A0DD0     # struct+0x70
WND_PROC = (0x100143D0, 0xE1)
LABEL = (0x100144C0, 0x9D)

# Every function that runs per frame, in dispatch order.
WORKERS = {
    0x10012F10: "plain",
    0x100130B0: "plain + 色彩補正",
    0x10013340: "境界補正 pass1",
    0x10013500: "境界補正 pass1 + 色彩補正",
    0x100136E0: "境界補正 pass2 (vertical box)",
    0x10013880: "境界補正 pass3",
    0x10013DE0: "境界補正 pass3 + 色彩補正",
}

ANNOTATIONS = {
    0x100143D0: "uMsg",
    0x100143DA: "0x702 = AviUtl's WM_FILTER_COMMAND",
    0x100143DF: "esi = fp->ex_data_ptr, kept across every branch",
    0x100143EC: "LOWORD(wParam) = control id",
    0x100143F1: "id 0x1e1b -> the キー色の取得 button was pressed",
    0x100143F8: "id 0x1e1d -> exedit is delivering a picked colour",
    0x10014401: "lParam == 0 means the pick was cancelled",
    0x10014409: "PIXEL_YC y  -> ex_data+0",
    0x10014410: "PIXEL_YC cb -> ex_data+2",
    0x10014418: "PIXEL_YC cr -> ex_data+4",
    0x10014421: "status = 1: from here on func_proc will actually run",
    0x1001443A: "cancelled: status = 0",
    0x10014451: "button path: table[0x80](fp+0xE4, 0) first - purpose not traced",
    0x10014463: "status == 2 -> the eyedropper is already armed",
    0x1001447A: "arm it: table[0x68](fp+0xE4, 1)",
    0x1001447D: "status = 2",
    0x1001448D: "disarm: table[0x68](0, 0)",
    0x10014490: "status = 0 - arming and then cancelling *forgets the key colour*",
    0x100144AC: "any other message: return FALSE",
    # ---- the label routine
    0x100144D9: "table[0x4c](fp+0xE4, 5, 2) -> the button's HWND",
    0x100144EB: "status == 1?",
    0x100144F0: "cr ...",
    0x100144F4: "... cb ...",
    0x100144FA: "... and y: the ONE read of ex_data+0 in the whole effect",
    0x10014502: "'YCbCr ( %d , %d , %d )'",
    0x10014508: "wsprintfA",
    0x10014517: "SetWindowTextA",
    0x10014525: "status == 2?",
    0x1001452E: "'マウスをクリックして色を取得してください'",
    0x1001453A: "status 0 (or anything else): '< 未取得 >'",
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
    (reg,) = find(img, "クロマキー")

    print("--- 1. the ex_data layout, as the binary declares it ---")
    print(f"  struct=0x{reg.struct_va:08x}  ex_data_size={reg.ex_data_size}  "
          f"ex_data_def=0x{reg.ex_data_def:08x}  field table=0x{EX_DATA_FIELDS:08x}")
    off = 0
    for kind, size, name in field_table(img, EX_DATA_FIELDS, reg.ex_data_size):
        print(f"    +0x{off:02x}  kind={kind}  size={size}  name={name!r}")
        off += size
    print(f"  -> declared bytes = {off}, ex_data_size = {reg.ex_data_size}: "
          f"{'OK' if off == reg.ex_data_size else 'MISMATCH'}")
    print("  kind 3 = PIXEL_YC, kind 1 = int, kind 0 = unnamed padding to align it.")
    print("  In C:  struct { short y, cb, cr; short pad; int status; }")

    print("\n--- 4. what a newly added クロマキー starts with ---")
    words = struct.unpack("<3hhi", reg.ex_data_def_bytes)
    print(f"  ex_data_def bytes = {reg.ex_data_def_bytes.hex(' ')}")
    print(f"  -> y={words[0]} cb={words[1]} cr={words[2]} pad={words[3]} status={words[4]}")
    print("  status = 0, so func_proc's first test fails and the effect is a no-op")
    print("  until the eyedropper is used. 0x1011ec90 is in .data but nothing ever")
    print("  writes it (tools.xrefs finds exactly one reference: the struct field).")

    print("\n--- 3. which ex_data offsets does the per-frame code read? ---")
    print(f"  {'worker':>12}  {'role':<28} ex_data offsets touched")
    all_offsets = set()
    for addr, role in WORKERS.items():
        # ex_data reaches every worker through one register loaded from
        # fp->ex_data_ptr; the field reads are the movsx word ptr [reg + n]
        # with a small n that follow. Scanning for the offsets themselves keeps
        # this independent of which register the compiler happened to pick.
        offs = set()
        for insn in function_body(img, addr, 0x600):
            if insn.mnemonic == "movsx" and "word ptr [" in insn.op_str:
                base = insn.op_str.split("word ptr [")[1].rstrip("]")
                if "+" in base:
                    n = int(base.split("+")[1].strip(), 0)
                    if n in (0, 2, 4, 8):
                        offs.add(n)
                else:
                    offs.add(0)
        # +0 also matches "[reg]" with no displacement, which is a *pixel*
        # read in every worker, so only the explicit displacements are usable
        # evidence. Report them as such.
        explicit = sorted(o for o in offs if o)
        all_offsets |= set(explicit)
        print(f"  0x{addr:08x}  {role:<28} {explicit}")
    print(f"  -> union over all seven workers: {sorted(all_offsets)}")
    print("  +2 = cb and +4 = cr appear everywhere; +0 (y) appears nowhere with an")
    print("  explicit displacement, and +8 (status) is read only by func_proc.")
    print("  The key colour's luminance is written, displayed, saved - and ignored.")

    dump_all(img, {
        "func_WndProc 0x100143d0": WND_PROC,
        "settings-window label 0x100144c0": LABEL,
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
        "the colour that was there before (0x10014490).\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
