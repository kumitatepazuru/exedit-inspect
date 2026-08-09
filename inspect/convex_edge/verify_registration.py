"""What 凸エッジ (convex edge) is made of, and - mostly - what it is not.

Five claims, each checked against the image rather than paraphrased from it:

  1. **One registration, three trackbars, and nothing else.** No checkbox, no
     ex_data, no func_init/exit/update/WndProc, no FILTER+0x58. ルミナンスキー
     was previously the "no UI code of its own" record holder, but it still has
     a 4-byte ex_data and borrows two shared UI functions; 凸エッジ has no UI
     surface at all beyond the three sliders.

  2. **846 bytes, two functions, contiguous.** 0x10007a80 func_proc and
     0x10007b90 worker, back to back, ending at 0x10007dcd. That is smaller
     than ルミナンスキー's 959 bytes, which makes 凸エッジ the smallest effect
     analysed in this repository. The worker is pushed exactly once in the
     whole image.

  3. **Four globals, all private.** Every literal occurrence of each of the
     four addresses lands inside those 846 bytes, so nothing else can read or
     write them (the same byte-scan argument 縁取り §2 uses).

  4. **It calls almost nothing and touches almost nothing.** The only direct
     call is CRT `_ftol`; the only indirect call is
     `exfunc->exec_multi_thread_func`. No `table[0x44]`/`table[0x48]`, so no
     canvas growth; no `0x10624dd3`, so no /1000 conversion; the only
     FILTER_PROC_INFO fields read are +0x00, +0xAC, +0xB0, +0xB4, +0xB8, +0xEC
     - and none of them is ever written.

  5. **The output is a full-frame copy through the pair buffer.** Every pixel
     of the band gets all four 16-bit fields written, alpha verbatim, and
     func_proc swaps +0xAC/+0xB0 at the end.

Run via main.py:
    uv run main.py inspect/convex_edge/verify_registration.py
"""

from tools.disasm import disasm_range, function_body
from tools.filter_table import find, walk
from tools.pe_image import PEImage
from tools.xrefs import function_owners, instruction_containing, owner_of, scan

FUNC_PROC = 0x10007A80
WORKER = 0x10007B90
CODE_END = 0x10007DCE          # one past the worker's `ret`
STRUCT_VA = 0x1009ECB0
EXT_VA = 0x1009EC9C

GLOBALS = {
    0x100D7588: "scale = 高さ / (200 * steps)   [double, 8 bytes]",
    0x100D7590: "steps",
    0x100D7594: "dy = trunc( cos(角度) * 65536)",
    0x100D7598: "dx = trunc(-sin(角度) * 65536)",
}

# FILTER_PROC_INFO / FILTER fields the effect is allowed to touch.
EXPECTED_FIELDS = {
    0x00: "fpip->flag (only bit 9 is tested)",
    0x44: "fp->track[]",
    0x60: "fp->exfunc            (filter_registration.md §4)",
    0xAC: "*(fpip+0xAC) source object buffer",
    0xB0: "*(fpip+0xB0) pair buffer",
    0xB4: "*(fpip+0xB4) w",
    0xB8: "*(fpip+0xB8) h",
    0xCC: "exfunc->exec_multi_thread_func",
    0xEC: "*(fpip+0xEC) stride [pixels]",
}


def effect_instructions(img):
    return list(function_body(img, FUNC_PROC, 0x200)) + list(function_body(img, WORKER, 0x400))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)
    owners = function_owners(img)
    regs = walk(img)
    hits = find(img, "凸エッジ")

    print("--- 1. one registration, three trackbars, and no UI surface at all ---")
    check("exactly one registration named 凸エッジ", len(hits) == 1, f"{len(hits)} found")
    r = hits[0]
    check(f"it is table entry [{r.index}] at 0x{r.struct_va:08x}",
          (r.index, r.struct_va) == (36, STRUCT_VA))
    check("flag = 0x20 -> object effect only, no frame-filter twin",
          r.flag == 0x20, f"flag=0x{r.flag:08x}")
    check("func_proc = 0x10007a80", r.func_proc == FUNC_PROC, f"0x{r.func_proc:08x}")
    check("func_init / func_exit / func_update / func_WndProc are all NULL",
          not (r.func_init or r.func_exit or r.func_update or r.func_wndproc))
    check("FILTER+0x58 (settings-window update) is NULL too",
          img.u32(r.struct_va + 0x58) == 0, f"0x{img.u32(r.struct_va + 0x58):08x}")
    check("ex_data_size = 0 and ex_data_def = NULL",
          r.ex_data_size == 0 and r.ex_data_def == 0)
    check("+0x70 (the ex_data field table) is NULL as well",
          img.u32(r.struct_va + 0x70) == 0)
    check("track_n = 3, check_n = 0 -> not one checkbox, button or combo box",
          (r.track_n, r.check_n) == (3, 0))

    print(f"\n  {'trackbar':<8}{'raw def':>9}{'raw range':>14}{'scale':>7}{'shown def':>11}"
          f"{'shown range':>18}")
    for i in range(r.track_n):
        print(f"  {str(r.track_names[i]):<8}{r.track_defaults[i]:>9}"
              f"{f'{r.track_s[i]}..{r.track_e[i]}':>14}{r.track_scale(i):>7}"
              f"{r.shown(i, r.track_defaults[i]):>11}"
              f"{f'{r.shown(i, r.track_s[i])}..{r.shown(i, r.track_e[i])}':>18}")
    check("names are 幅 / 高さ / 角度",
          [str(n) for n in r.track_names] == ["幅", "高さ", "角度"])
    check("raw defaults are 4 / 100 / -450 = 4 px, 1.00, -45.0 deg",
          r.track_defaults == [4, 100, -450])
    check("raw ranges are 0..100 / 0..300 / -3600..3600",
          list(zip(r.track_s, r.track_e)) == [(0, 100), (0, 300), (-3600, 3600)])

    slots = img.u32_array(EXT_VA, 4)
    check(f"+0x74 block 0x{EXT_VA:08x}: display scales {{1,100,10}}, other three slots NULL",
          r.ext_va == EXT_VA and r.scale == [1, 100, 10]
          and slots[1] == 0 and slots[2] == 0 and slots[3] == 0,
          f"slots {[hex(s) for s in slots]} scale {r.scale}")
    print("  No drag range, so every slider spans its raw range; no grouping marker, so")
    print("  the three trackbars are independent (param_scaling.md §1).")

    bare = [x for x in regs
            if x.track_n and not x.check_n and not x.ex_data_size
            and not (x.func_init or x.func_exit or x.func_update or x.func_wndproc)]
    print(f"\n  {len(bare)} of {len(regs)} registrations expose trackbars and nothing else:")
    print("   ", ", ".join(sorted({x.name for x in bare})))
    check("凸エッジ is one of them", any(x.name == "凸エッジ" for x in bare))
    print("  Of the effects analysed so far every one had at least a checkbox (サイズ固定,")
    print("  タイル風, ...) or an ex_data (colour button, combo box). 凸エッジ is the")
    print("  first with neither, which is why it has no UI code to read.")

    print("\n--- 2. 846 bytes in two functions, contiguous ---")
    fp_body = function_body(img, FUNC_PROC, 0x200)
    wk_body = function_body(img, WORKER, 0x400)
    fp_end = fp_body[-1].address + fp_body[-1].size
    wk_end = wk_body[-1].address + wk_body[-1].size
    print(f"  func_proc 0x{FUNC_PROC:08x}..0x{fp_end - 1:08x}  "
          f"{fp_end - FUNC_PROC:>4} bytes, {len(fp_body):>3} instructions")
    print(f"  worker    0x{WORKER:08x}..0x{wk_end - 1:08x}  "
          f"{wk_end - WORKER:>4} bytes, {len(wk_body):>3} instructions")
    check("func_proc ends at 0x10007b8c, the worker starts 3 nops later",
          fp_end == 0x10007B8D and WORKER == 0x10007B90)
    check("the worker ends at 0x10007dcd, so the effect spans exactly 846 bytes",
          wk_end == CODE_END and CODE_END - FUNC_PROC == 846,
          f"{wk_end - FUNC_PROC} bytes")
    check("that is smaller than ルミナンスキー's 959 bytes - the smallest effect analysed",
          CODE_END - FUNC_PROC < 959)

    before = [x for x in regs if x.func_proc < FUNC_PROC]
    check("the function immediately before belongs to 直前オブジェクト (0x10007a70)",
          max(x.func_proc for x in before) == 0x10007A70,
          f"0x{max(x.func_proc for x in before):08x}")
    stub = list(disasm_range(img, CODE_END + 2, 8, resolve=False))
    check("the 16-byte slot after it is a shared `mov eax,1 ; ret` stub, not 凸エッジ code",
          [i.mnemonic for i, _ in stub][:2] == ["mov", "ret"],
          f"{[(i.mnemonic, i.op_str) for i, _ in stub][:2]}")

    wk_hits = scan(img, WORKER)
    check("the worker address occurs exactly once in the whole image (the push at 0x10007b3e)",
          len(wk_hits) == 1 and 0x10007B3E <= wk_hits[0] <= 0x10007B43,
          f"{[hex(v) for v in wk_hits]}")

    print("\n--- 3. four globals, every reference inside those 846 bytes ---")
    for va, what in sorted(GLOBALS.items()):
        refs = scan(img, va)
        inside = [v for v in refs if FUNC_PROC <= v < CODE_END]
        insns = [instruction_containing(img, v, va, anchor=(owner_of(owners, v) or (None,))[0])
                 for v in inside]
        check(f"0x{va:08x} {what}", len(refs) == len(inside) and refs,
              f"{len(refs)} refs, {len(inside)} inside")
        for v, ins in zip(inside, insns):
            print(f"        0x{ins.address:08x}: {ins.mnemonic} {ins.op_str}")
    print("  A byte scan, not a disassembly: on 32-bit x86 with no position independence")
    print("  every reference to a global is that literal dword somewhere in the file, so")
    print("  'all occurrences are in this range' settles it for the whole binary.")

    print("\n--- 4. what the effect never does ---")
    insns = effect_instructions(img)
    direct = sorted({int(i.op_str, 16) for i in insns
                     if i.mnemonic == "call" and i.op_str.startswith("0x")})
    check("the only direct call target is CRT _ftol (0x10091ad8)",
          direct == [0x10091AD8], f"{[hex(a) for a in direct]}")
    indirect = sorted({i.op_str for i in insns
                       if i.mnemonic == "call" and not i.op_str.startswith("0x")})
    check("the only indirect call is exfunc->exec_multi_thread_func (`call [edx+0xcc]`)",
          indirect == ["dword ptr [edx + 0xcc]"], f"{indirect}")
    print("  No table[0x44] / table[0x48] (rect blit / rect clear), which is the shape")
    print("  every canvas-growing effect has (canvas_growth.md §3). No 0x1006fed0 either,")
    print("  because there is no colour to convert.")

    check("`0x10624dd3` (the shared /1000 magic divide) does not appear",
          not any("0x10624dd3" in i.op_str for i in insns))
    check("no `pow` / no shared LUT / no exedit helper of any kind is reached",
          all(t == 0x10091AD8 for t in direct))

    import re
    disp = {}
    for i in insns:
        for base, off in re.findall(r"\[(e[a-z]{2}) \+ (0x[0-9a-f]+)\]", i.op_str):
            if base == "esp":
                continue          # stack frame, named in disasm_params.py
            v = int(off, 16)
            if v >= 0x40:
                disp.setdefault(v, []).append(i.address)
    # `mov eax, dword ptr [edi]` reads fpip->flag with no displacement at all.
    flag_reads = [i.address for i in insns if i.op_str.endswith("dword ptr [edi]")]
    if flag_reads:
        disp[0x00] = flag_reads
    check("the only struct fields touched are the nine expected ones",
          set(disp) == set(EXPECTED_FIELDS), f"{sorted(hex(d) for d in disp)}")
    for v in sorted(disp):
        print(f"        +0x{v:02x}  {EXPECTED_FIELDS.get(v, '?'):<48}"
              f"{len(disp[v])} access(es)")
    check("+0x00 is read once and only bit 9 of it is tested (`test ah, 2`)",
          len(flag_reads) == 1
          and any(i.mnemonic == "test" and i.op_str == "ah, 2" for i in insns))
    print("  Not present: +0x04/+0x08 (ycp_edit/ycp_temp - there is no frame-filter")
    print("  version), +0x14/+0x18 (max_w/max_h), +0x1C (frame - so the output is")
    print("  deterministic), +0xD4/+0xD8 (centre correction), +0xF0 (allocated rows -")
    print("  the only analysed effect that clamps against w/h alone).")

    def stores(body):
        """Every memory destination in a function body: `... ptr [x], src` for
        the integer stores plus `fstp ... ptr [x]`, which has no comma."""
        out = set()
        for i in body:
            m = re.match(r"((?:[a-z]*word|byte) ptr \[[^\]]+\])(,|$)", i.op_str)
            if m and not m.group(1).endswith("ptr [esp]") \
                    and not m.group(1).startswith("dword ptr [esp +"):
                if i.mnemonic == "fstp" or m.group(2) == ",":
                    out.add(m.group(1))
        return out

    check("func_proc's only memory writes are the four globals and the buffer swap",
          stores(fp_body) == {"dword ptr [0x100d7590]", "dword ptr [0x100d7594]",
                              "dword ptr [0x100d7598]", "qword ptr [0x100d7588]",
                              "dword ptr [edi + 0xac]", "dword ptr [edi + 0xb0]"},
          f"{sorted(stores(fp_body))}")
    check("the worker writes exactly the four 16-bit fields y / cb / cr / a of dst",
          stores(wk_body) == {"word ptr [ebp]", "word ptr [ebp + 2]",
                              "word ptr [ebp + 4]", "word ptr [ebp + 6]"},
          f"{sorted(stores(wk_body))}")
    print(f"        {sorted(stores(wk_body))}")
    print("  So the source buffer is read-only and the pair buffer is written in full:")
    print("  no in-place hazard, and every neighbour sample sees the original alpha.")

    print("\n--- 5. output goes to the pair buffer, then the buffers are swapped ---")
    swap = [i for i, _ in disasm_range(img, 0x10007B68, 0x1B, resolve=False)]
    for i in swap:
        print(f"        0x{i.address:08x}: {i.mnemonic} {i.op_str}")
    check("func_proc reads both pointers, then stores them crossed over",
          [i.op_str for i in swap] == ["eax, dword ptr [edi + 0xb0]",
                                       "ecx, dword ptr [edi + 0xac]",
                                       "esp, 0xc",
                                       "dword ptr [edi + 0xb0], ecx",
                                       "dword ptr [edi + 0xac], eax"])
    print("  Every pixel of every row band is written (the x loop has no `continue`),")
    print("  so the pair buffer needs no clearing first - which is why there is no")
    print("  table[0x48] call anywhere in the effect.")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
