"""Pin down which of func_proc's branches is the object-effect path and which
is the frame(video)-filter path, and recover the full worker table by reading
the dispatch sites out of the binary instead of trusting a hand-transcription.

Getting the object/frame mapping backwards would silently mislabel half of the
analysis, because every downstream choice (worker, buffer, edge handling,
whether the canvas may grow) hangs off `fp->flag & 0x20`. So this script does
two things:

  * dumps the branch itself, annotated, showing that the two sides read
    different struct fields:

        flag & 0x20 SET   -> image = *(fpip+0xAC), pair buffer = *(fpip+0xB0),
                             w/h = *(fpip+0xB4)/*(fpip+0xB8),
                             row stride = *(fpip+0xEC), 8 bytes/pixel
                             (PIXEL_YCA: y, cb, cr at +0/+2/+4, alpha at +6)
        flag & 0x20 CLEAR -> image = fpip->ycp_edit (+4), pair = ycp_temp (+8),
                             w/h = fpip->w (+0xC)/fpip->h (+0x10),
                             row stride = fpip->max_w (+0x14) pixels, 6 bytes/pixel

    Note the stride: the workers multiply *(fpip+0x14) by 6 to get the byte
    pitch of a row, so it is the pixel count max_w, not the byte count
    line_size (which sits at +0x44 and exedit never reads).

    An 8-byte pixel with an alpha channel is exedit's own object image;
    ycp_edit/ycp_temp are AviUtl's frame buffers. The flag&0x20 side is also
    the only registration that owns the サイズ固定 checkbox - and only an
    object's canvas can grow when the blur spills past its bounding box - so
    flag&0x20 is the object-effect path.

  * walks every `push <worker>` / `call [reg+0xCC]` pair inside func_proc
    (0xCC is EXFUNC::exec_multi_thread_func) and prints, for each, the
    guard that selects it and what func_proc does immediately afterwards.
    The "+= 2*radius" lines are what prove which workers enlarge the canvas.

Run via main.py:
    uv run main.py inspect/blur/verify_mode_mapping.py
"""

from tools.disasm import disasm_range, dump_range
from tools.pe_image import PEImage

FUNC_PROC = (0x1000E2F0, 0x7E4)
MODE_BRANCH = (0x1000E355, 0x1F0)

ANNOTATIONS = {
    0x1000E355: "eax = fp->flag",
    0x1000E35B: "and eax, 0x20",
    0x1000E362: "je -> 0x1000e3a3 (skip the object-only max-canvas clamp)",
    0x1000E364: "edx = fp->check   (FILTER+0x48)",
    0x1000E367: "ecx = *(fpip+0xB4) = object canvas width",
    0x1000E36D: "eax = check[0] = サイズ固定, stashed for the worker choice",
    0x1000E376: "0x10196748 = max object canvas width",
    0x1000E388: "ecx = *(fpip+0xB8) = object canvas height",
    0x1000E38E: "0x101920e0 = max object canvas height",
    0x1000E3C9: "je -> 0x1000e4e4: flag&0x20 CLEAR = FRAME path",
    0x1000E3CF: "--- object path: サイズ固定 on? -> skip expansion AND clamping ---",
    0x1000E3E5: "expand the canvas if 2*rx_hi >= w ...",
    0x1000E3F2: "... or 2*ry_hi >= h ...",
    0x1000E403: "... or 2*rx_lo >= w ...",
    0x1000E410: "... or 2*ry_lo >= h; otherwise skip to 0x1000e535",
    0x1000E418: "--- canvas pre-expansion (verify_canvas_growth.py) ---",
    0x1000E464: "call exedit_table[0x48]: clear buffer B over (w+2rx, h+2ry)",
    0x1000E4A0: "call exedit_table[0x44]: blit A into B at (rx, ry)",
    0x1000E4B3: "swap *(fpip+0xAC) <-> *(fpip+0xB0), then w += 2rx, h += 2ry",
    0x1000E45C: "サイズ固定 := 1, so the passes below use the non-growing workers",
    0x1000E4E4: "--- frame path: clamp each of the 4 radii to dim/2 ---",
    0x1000E4E7: "eax = fpip->w (+0xC) vs 2*rx_hi",
    0x1000E4F6: "eax = fpip->h (+0x10) vs 2*ry_hi",
    0x1000E535: "eax = 光の強さ; <= 0 -> 0x1000e840 (the integer-pixel pass set)",
    0x1000E541: "光の強さ > 0: run the forward curve over the whole image first",
    0x1000E55E: "call 0x10070220 (object, 8-byte buffer)",
    0x1000E571: "call 0x10070550 (frame, 6-byte buffer)",
}

# EXFUNC::exec_multi_thread_func lives at exfunc+0xCC (see data/filter.h);
# fp->exfunc is FILTER+0x60.
MT_CALL = "dword ptr [ecx + 0xcc]", "dword ptr [edx + 0xcc]", "dword ptr [eax + 0xcc]"


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_range(img, *MODE_BRANCH,
               label="func_proc: the flag&0x20 branch and what it selects",
               resolve=False, annotations=ANNOTATIONS)

    # --- recover the worker dispatch table straight out of func_proc ---
    insns = [i for i, _ in disasm_range(img, *FUNC_PROC, resolve=False)]
    index_of = {ins.address: k for k, ins in enumerate(insns)}

    # Every `test .. / je T` in this function guards exactly one dispatch pair:
    # a call site at an address >= T is on the je-taken (condition false) side,
    # a site below T is on the fall-through (condition true) side. That is
    # enough to label each site without a full CFG.
    guards = []           # (test_addr, kind, je_target)
    for i, insn in enumerate(insns[:-1]):
        nxt = insns[i + 1] if insns[i + 1].mnemonic == "je" else None
        if nxt is None and i + 2 < len(insns) and insns[i + 2].mnemonic == "je":
            nxt = insns[i + 2]      # one instruction scheduled into the delay slot
        if insn.mnemonic != "test" or nxt is None:
            continue
        a, _, b = (x.strip() for x in insn.op_str.partition(","))
        if (a, b) == ("al", "0x20"):
            guards.append((insn.address, "flag&0x20", int(nxt.op_str, 16)))
        elif a == b:
            guards.append((insn.address, "サイズ固定", int(nxt.op_str, 16)))

    def label(site):
        mode_guards = [g for g in guards if g[1] == "flag&0x20" and g[0] < site]
        if not mode_guards:
            return "?"
        is_object = site < mode_guards[-1][2]
        if not is_object:
            # the frame path never reads fp->check, so no second label
            return "frame"
        fixed = [g for g in guards if g[1] == "サイズ固定" and g[0] < site]
        if not fixed:
            return "object"
        return "object / " + ("固定on" if site < fixed[-1][2] else "固定off")

    print("\n--- every exec_multi_thread_func dispatch inside func_proc ---")
    print("    site        worker      selected when       after the call")
    rows = []
    for i, insn in enumerate(insns):
        if insn.mnemonic != "call" or insn.op_str not in MT_CALL:
            continue
        worker = None
        for j in range(i - 1, max(i - 6, -1), -1):
            if insns[j].mnemonic == "push" and insns[j].op_str.startswith(("0x1000", "0x1001")):
                worker = int(insns[j].op_str, 16)
                break
        # What happens right after. An unconditional jmp is followed (the
        # size-fixed branch joins a common tail) rather than fallen through, so
        # the scan cannot leak into the sibling branch's code.
        after = "?"
        j, budget = i + 1, 24
        while 0 <= j < len(insns) and budget > 0:
            budget -= 1
            op, mnem = insns[j].op_str, insns[j].mnemonic
            if mnem == "jmp":
                j = index_of.get(int(op, 16), -1) if op.startswith("0x") else -1
                continue
            if mnem == "mov" and op.startswith("dword ptr [esi + 0xac],"):
                after = "swap *(fpip+0xAC) <-> *(fpip+0xB0)"
                break
            if mnem == "mov" and op.startswith("dword ptr [esi + 0xb8],"):
                after = "*(fpip+0xB8) += 2*radius, then swap A/B  (canvas grew vertically)"
                break
            if mnem == "mov" and op.startswith("dword ptr [esi + 0xb4],"):
                after = "*(fpip+0xB4) += 2*radius, then swap A/B  (canvas grew horizontally)"
                break
            if mnem == "mov" and op.startswith("dword ptr [esi + 8],"):
                after = "swap fpip->ycp_edit <-> ycp_temp"
                break
            j += 1
        rows.append((insn.address, worker, label(insn.address), after))
        print(f"    0x{insn.address:08x}  0x{worker:08x}  {label(insn.address):19s} {after}")

    workers = sorted({w for _, w, _, _ in rows})
    print(f"\n  {len(rows)} dispatch sites, {len(workers)} distinct workers: "
          + ", ".join(f"0x{w:08x}" for w in workers))

    print(
        "\n"
        "Verdict:\n"
        "\n"
        "  flag & 0x20 SET  -> OBJECT EFFECT (the registration with サイズ固定)\n"
        "      image : *(fpip+0xAC)  pair: *(fpip+0xB0)   8 bytes/pixel (y,cb,cr,a)\n"
        "      w / h : *(fpip+0xB4)  *(fpip+0xB8)         stride: *(fpip+0xEC) px\n"
        "      サイズ固定 off -> 0x1000eae0/0x1000eef0 (int)  0x10010190/0x100105e0 (curve)\n"
        "                       and the canvas grows by 2*radius on each pass\n"
        "      サイズ固定 on  -> 0x1000f310/0x1000f7e0 (int)  0x10010a30/0x10010f20 (curve)\n"
        "      curve : 0x10070220 forward / 0x100703f0 inverse\n"
        "\n"
        "  flag & 0x20 CLEAR -> FRAME (VIDEO) FILTER\n"
        "      image : fpip->ycp_edit (+4)  pair: ycp_temp (+8)   6 bytes/pixel\n"
        "      w / h : fpip->w (+0xC)  fpip->h (+0x10)   stride: fpip->max_w (+0x14) px\n"
        "      workers: 0x1000fcb0/0x1000ff40 (int)  0x10011400/0x100116d0 (curve)\n"
        "      the frame size never changes; radii are clamped to dim/2 instead\n"
        "      curve : 0x10070550 forward / 0x10070700 inverse (shared with 発光)\n"
        "\n"
        "  Each pass ping-pongs: it reads the current image, writes the pair buffer,\n"
        "  and func_proc then swaps the two pointers - so a pass with radius 0, which\n"
        "  is skipped, also skips its swap and the chain stays consistent.\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
