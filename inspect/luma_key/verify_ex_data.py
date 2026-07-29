"""`ex_data`, the combobox, and the two UI entry points - all of them shared.

ルミナンスキー has no eyedropper, no colour picker and no per-effect dialog
code. Its entire UI is one 4-byte `ex_data` holding a combobox index, and both
routines that touch it are shared verbatim with other effects. Claims checked:

  1. **`ex_data` is one `int`.** exedit's own `+0x70` field table
     (0x100a7d10, filter_registration.md §5) declares a single field named
     `type`, kind 1, size 4 - and 4 is `ex_data_size`. `ex_data_def`
     (0x101bacdc) is zero, so a freshly added effect starts on item 0,
     暗い部分を透過.

  2. **The checkbox is a 4-item combobox.** `check_default[0] = -2` is exedit's
     marker for a dropdown, and the items are four consecutive cp932 strings
     starting at `check_name[0]`. The addresses are printed so the packing can
     be checked rather than assumed.

  3. **`func_WndProc` (0x10018080) is generic and shared by five
     registrations.** It handles exactly one message - `WM_FILTER_COMMAND`
     (0x702) with control id 0x1e1c - and its whole body is
     `ex_data[0] = lParam`. It never reads `fp->track[]`, and it contains no
     mention of ルミナンスキー.

  4. **`FILTER+0x58` (0x10065270) is shared with インターレース解除.** It
     pushes `CB_SETCURSEL` and calls `SendMessageA`, i.e. it pushes the stored
     index back into the dropdown when the settings window is rebuilt.

  5. **`table[0x4c](fp+0xE4, kind, index)` selects a control by KIND and
     index.** クロマキー / カラーキー passed 5 and this repository recorded the
     meaning of that argument as untracked. Reading every call site in the
     image settles three of the values: **5 = checkbox/button, 6 = combobox,
     7 = static text**, cross-checked against グロー, which is the one effect
     that uses two of them in the same function.

  6. **The `+0x74` block leaves 基準輝度's negative half unreachable by
     dragging.** Both trackbars have display scale 1, and the drag range is
     0..4096 while 基準輝度's typed range is -4096..8192.

Run via main.py:
    uv run main.py inspect/luma_key/verify_ex_data.py
"""

import re

from tools.disasm import disasm_range, dump_range
from tools.filter_table import walk
from tools.pe_image import PEImage
from tools.xrefs import scan

FIELD_TABLE = 0x100A7D10
WND_PROC = 0x10018080
UPDATE_ENTRY = 0x10065270

# Call sites of `table[0x4c]`, each with the control it is known to fetch from
# the effect it belongs to. The kind argument is read out of the binary below,
# not written here.
KIND_ANCHORS = [
    (0x100144D9, "クロマキー", "the キー色の取得 button, check_name[2]"),
    (0x10016959, "カラーキー", "the キー色の取得 button, check_name[0]"),
    (0x1006528F, "ルミナンスキー", "the 暗い部分を透過 combobox, check_name[0]"),
    (0x10059002, "グロー", "the 通常 combobox, check_name[0]"),
    (0x10059022, "グロー", "the static text 形状 (0x100a67d4), not a control at all"),
    (0x100180F0, "色ずれ", "its combobox (shares this WndProc)"),
]

WND_ANNOTATIONS = {
    0x10018089: "WM_FILTER_COMMAND",
    0x10018094: "control id 0x1e1c - the combobox. Buttons are 0x1e1b",
    0x100180A9: "table[0x80](fp+0xE4, 0). Return value unused",
    0x100180AF: "lParam = the new item index",
    0x100180B6: "ex_data[0] = it. That is the entire handler",
    0x100180B8: "TRUE -> exedit re-renders the object",
}

UPDATE_ANNOTATIONS = {
    0x10065285: "CB_SETCURSEL",
    0x1006528C: "control kind 6",
    0x1006528F: "table[0x4c](fp+0xE4, 6, 0)",
    0x10065296: "SendMessageA(combo, CB_SETCURSEL, ex_data.type, 0)",
}


def _pushes_before(img, call_va: int, n: int = 3, back: int = 0x40):
    """The last `n` push operands before an instruction, in program order.

    Decoding starts `back` bytes earlier and is resynchronised by discarding
    anything that does not end exactly on `call_va`, so a misaligned start
    cannot invent a `push`.
    """
    for start in range(call_va - back, call_va):
        seq = [i for i, _ in disasm_range(img, start, call_va - start, resolve=False)]
        if seq and seq[-1].address + seq[-1].size == call_va:
            return [i.op_str for i in seq if i.mnemonic == "push"][-n:]
    return []


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    regs = walk(img)
    (reg,) = [r for r in regs if r.name == "ルミナンスキー"]

    print("--- 1. the ex_data layout, as exedit itself declares it ---")
    print(f"  ex_data_size = {reg.ex_data_size}, ex_data_def = 0x{reg.ex_data_def:08x}"
          f" = {reg.ex_data_def_bytes.hex(' ')}")
    print(f"  +0x70 field table = 0x{FIELD_TABLE:08x}")
    print(f"    {'offset':>7}{'kind':>6}{'size':>6}  name")
    off, total, p = 0, 0, FIELD_TABLE
    while total < reg.ex_data_size:
        kind, size, namep = img.u16(p), img.u16(p + 2), img.u32(p + 4)
        name = img.cstr(namep) if namep and img.valid(namep) else "(unnamed)"
        print(f"    {off:>7}{kind:>6}{size:>6}  {name!r}")
        off, total, p = off + size, total + size, p + 8
    print(f"  -> declared total {total} == ex_data_size {reg.ex_data_size}: "
          f"{total == reg.ex_data_size}")
    print("  One field. `struct { int type; };` - the combobox index and nothing else.")
    print("  クロマキー and カラーキー carry 12 bytes here (a PIXEL_YC plus an eyedropper")
    print("  state machine); ルミナンスキー keys on a field that is already in the pixel,")
    print("  so it needs no picked colour at all.")
    print(f"  ex_data_def is all zero -> a new ルミナンスキー starts on item 0.")

    print("\n--- 2. the combobox items ---")
    print(f"  check_n = {reg.check_n}, check_default[0] = {reg.check_defaults[0]}"
          f"  ({'combobox' if reg.check_defaults[0] == -2 else 'other'})")
    p = img.u32(img.u32(reg.struct_va + 0x28))
    for i in range(4):
        s = img.cstr(p)
        print(f"    item {i}  0x{p:08x}  {s!r}  ({len(s.encode('cp932'))} bytes + NUL)")
        p += len(s.encode("cp932")) + 1
    pad = 0
    while img.code(p, 1) == b"\x00":     # alignment padding after the run
        p, pad = p + 1, pad + 1
    print(f"  then {pad} NUL byte(s) of padding and {img.cstr(p)!r} = track_name[0]"
          f" (0x{p:08x}), so the run of four is exactly the item list:"
          f" {img.cstr(p) == reg.track_names[0]}")

    print("\n--- 3. func_WndProc 0x10018080 is not this effect's code ---")
    sharers = [r for r in regs if r.func_wndproc == WND_PROC]
    print(f"  registrations using it: {len(sharers)}")
    for r in sharers:
        print(f"    [{r.index:>3}] {r.name:<20} ex_data_size={r.ex_data_size}"
              f"  check_n={r.check_n}  +0x58=0x{img.u32(r.struct_va + 0x58) or 0:08x}")
    print(f"  raw-dword occurrences of 0x{WND_PROC:08x} in the image: {len(scan(img, WND_PROC))}"
          f"  (one per registration struct, all in .data)")
    dump_range(img, WND_PROC, 0x43, label="func_WndProc 0x10018080",
               annotations=WND_ANNOTATIONS)
    print("  Every effect in this list has a 4-byte ex_data and a combobox at")
    print("  check_name[0] (ミラー's second checkbox is a real checkbox, and this")
    print("  handler ignores it - checkboxes go to fp->check[], not to ex_data).")
    print("  The handler is generic over all of them: it writes lParam into ex_data[0]")
    print("  without knowing which effect it belongs to. This is why ルミナンスキー's")
    print("  func_WndProc lives 300 KB away from its func_proc.")

    print("\n--- 4. FILTER+0x58 0x10065270 ---")
    owners = [r for r in regs if (img.u32(r.struct_va + 0x58) or 0) == UPDATE_ENTRY]
    print(f"  registrations pointing at it: {[r.name for r in owners]}")
    dump_range(img, UPDATE_ENTRY, 0x2F, label="the settings-window update entry",
               annotations=UPDATE_ANNOTATIONS)
    print("  Note the argument trick: lParam, wParam and CB_SETCURSEL are pushed before")
    print("  the table[0x4c] call and left on the stack, so `add esp, 0xc` cleans only")
    print("  the three table arguments and the HWND is pushed on top. Six pushes, one")
    print("  cleanup, two calls.")

    print("\n--- 5. what the second argument of table[0x4c] means ---")
    print(f"  {'call site':<12}{'effect':<16}{'kind':>5}{'index':>7}   control")
    kinds = {}
    for va, effect, what in KIND_ANCHORS:
        ps = _pushes_before(img, va)
        if len(ps) < 3:
            print(f"  0x{va:08x}  {effect:<16}  <could not resynchronise>")
            continue
        index, kind, _handle = ps
        kinds.setdefault(kind, []).append(f"{effect} / {what}")
        print(f"  0x{va:08x}  {effect:<16}{kind:>5}{index:>7}   {what}")
    print("  (arguments are cdecl, so the three pushes read handle, kind, index"
          " backwards)")
    print("\n  grouped by kind:")
    for k in sorted(kinds, key=lambda s: int(s, 0)):
        print(f"    {k} -> {'; '.join(kinds[k])}")
    print("  グロー is the deciding case: one function fetches its dropdown with 6 and")
    print("  the 形状 label with 7, four instructions apart, and calls SendMessageA on")
    print("  the first and SetWindowTextA on the second. So:")
    print("      5 = checkbox / button row      (クロマキー, カラーキー)")
    print("      6 = combobox                   (ルミナンスキー, グロー, 色ずれ, ...)")
    print("      7 = static text                (グロー's 形状)")
    print("  The third argument is the index within that kind - which for 5 and 6 is the")
    print("  index into check_name[], matching what filter_registration.md §5 already")
    print("  recorded from the クロマキー(2) / カラーキー(0) difference.")
    print("  Kinds 0..4 also occur elsewhere in exedit's dialog code and are still")
    print("  unidentified; nothing in the effects analysed here uses them.")

    print("\n--- 6. the +0x74 block ---")
    print(f"  ext = 0x{reg.ext_va:08x}")
    print(f"    scale     = {reg.scale}")
    print(f"    group     = {reg.slot1}")
    print(f"    drag_min  = {reg.drag_min}")
    print(f"    drag_max  = {reg.drag_max}")
    print(f"  {'trackbar':<12}{'raw range':>16}{'default':>9}{'scale':>7}{'drag':>14}")
    for i in range(reg.track_n):
        print(f"  {str(reg.track_names[i]):<12}"
              f"{f'{reg.track_s[i]}..{reg.track_e[i]}':>16}{reg.track_defaults[i]:>9}"
              f"{reg.track_scale(i):>7}"
              f"{f'{reg.drag_min[i]}..{reg.drag_max[i]}':>14}")
    print("  Scale 1 on both, so the numbers in the UI are the raw values and the raw")
    print("  values are PIXEL_YC luminance units directly - 4096 is full white, exactly")
    print("  as for カラーキー's 輝度範囲. No /1000 conversion exists anywhere in the")
    print("  effect (verify_dispatch.py §7).")
    print("  基準輝度 accepts -4096..8192 but the slider only spans 0..4096: the ends")
    print("  are reachable by typing only. Both extremes are degenerate anyway - see")
    print("  verify_alpha_curve.py §5 for which (基準輝度, ぼかし) pairs are no-ops and")
    print("  which erase the object outright.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
