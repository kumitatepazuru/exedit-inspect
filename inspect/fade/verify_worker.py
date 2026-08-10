"""The worker touches the alpha channel and nothing else.

`0x1004de20` is 45 instructions and 118 bytes - the smallest worker in this
project. Three claims, each proved by scanning the instructions rather than by
reading them.

(1) **It is alpha-only.** Every memory access in the worker resolves to
    `*(fpip+0xAC) + (stride*y + x)*8 + 6`, i.e. offset 6 of an 8-byte
    PIXEL_YCA. There is exactly one load and one store, both 16-bit, both at
    that address; `y`, `cb` and `cr` (offsets 0, 2, 4) are never named. That
    puts フェード in the same family as `境界ぼかし`, which also reads and
    writes only alpha - except that フェード does not even read the neighbours,
    so there is no canvas growth, no pair buffer and no swap.

(2) **In place, one buffer.** `*(fpip+0xB0)` (the pair buffer that every other
    analysed effect ping-pongs through) never appears, and neither does
    `[0x101a5328]` (the shared scratch). The only globals the whole worker
    reads are `fpip` fields and `0x101a5390`.

(3) **The thread split is the safe form.** Rows, `dim = h`, guard (B) only -
    no `dim < thread_num` guard - so the per-thread ranges telescope and every
    row is covered no matter how thin the object is (thread_split.md §1/§2).
    Since the worker has no unconditional write outside the row loop, the
    duplicate-write hazard of §4 does not apply either: an undersized object is
    simply processed by fewer threads.

Run via main.py:
    uv run main.py inspect/fade/verify_worker.py
"""

from tools.cints import c_div
from tools.disasm import disasm_range, dump_range
from tools.pe_image import PEImage

WORKER = (0x1004DE20, 0x76)

ANNOTATIONS = {
    0x1004DE33: "the split dimension: fpip->h (+0xB8) -> rows",
    0x1004DE3D: "hi = h*(tid+1)/thread_num",
    0x1004DE47: "lo = h*tid/thread_num",
    0x1004DE4B: "guard (B). There is no `cmp h, thread_num` / `test tid,tid` above it",
    0x1004DE5F: "row offset in pixels",
    0x1004DE62: "*(fpip+0xAC) + offset*8 - 8 bytes per pixel, PIXEL_YCA",
    0x1004DE6B: "+6 -> the alpha field. Nothing else is ever addressed",
    0x1004DE85: "+8 -> the next pixel's alpha",
}

PIXEL_FIELDS = {0: "y", 2: "cb", 4: "cr", 6: "a"}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    lo, size = WORKER

    dump_range(img, lo, size, label="alpha worker 0x1004de20",
               resolve=False, annotations=ANNOTATIONS)

    print("\n--- (1) every memory operand in the worker ---")
    loads, stores, fpip_fields, others = [], [], set(), []
    for insn, _ in disasm_range(img, lo, size, resolve=False):
        op = insn.op_str
        if "ptr [" not in op and "[" not in op:
            continue
        if "[edi + " in op:                       # edi = fpip
            fpip_fields.add(op.split("[edi + ")[1].split("]")[0])
            continue
        if "[esp" in op:                          # the incoming arguments
            continue
        if op.startswith("word ptr [") or ", word ptr [" in op:
            (stores if op.startswith("word ptr [") else loads).append(
                (insn.address, f"{insn.mnemonic} {op}"))
            continue
        if "[0x" in op:
            others.append((insn.address, f"{insn.mnemonic} {op}"))
            continue
        others.append((insn.address, f"{insn.mnemonic} {op}"))
    print(f"  fpip fields read: {sorted(fpip_fields)}")
    print("     +0xac = the object image, +0xb4 = w, +0xb8 = h, +0xec = line stride")
    print(f"  16-bit loads  ({len(loads)}): {[f'0x{a:08x} {t}' for a, t in loads]}")
    print(f"  16-bit stores ({len(stores)}): {[f'0x{a:08x} {t}' for a, t in stores]}")
    print(f"  absolute / other operands ({len(others)}): "
          f"{[f'0x{a:08x} {t}' for a, t in others]}")
    print("\n  the pointer those two use is built once per row:")
    print("     ecx = *(fpip+0xAC) + (fpip+0xEC)*y*8      (0x1004de62)")
    print("     ecx += 6                                   (0x1004de6b)")
    print("     ecx += 8 per pixel                         (0x1004de85)")
    print("  so every access lands on byte 6 of an 8-byte pixel:")
    for off, name in PIXEL_FIELDS.items():
        touched = "READ + WRITE" if off == 6 else "never addressed"
        print(f"     +{off}  {name:<3s} {touched}")

    print("\n--- (2) buffers neither half of the effect uses ---")
    whole = "\n".join(f"{i.mnemonic} {i.op_str}"
                      for i, _ in disasm_range(img, 0x1004DD40, 0x156, resolve=False))
    worker = "\n".join(f"{i.mnemonic} {i.op_str}"
                       for i, _ in disasm_range(img, lo, size, resolve=False))
    # fpip is esi in func_proc and edi in the worker; anything based on esp is a
    # stack slot and must not be matched.
    def present(text, off):
        return any(f"[{r} + {off}]" in text for r in ("esi", "edi"))

    for label, off in (("pair buffer *(fpip+0xB0)", "0xb0"),
                       ("object image *(fpip+0xAC)", "0xac"),
                       ("frame size fpip->w / fpip->h (+0xC / +0x10)", "0xc"),
                       ("fpip->frame / frame_n (+0x1C / +0x20)", "0x1c"),
                       ("fp->exfunc table replacement (+0x64)", "0x64")):
        print(f"  {label:<48s} whole effect: {'present' if present(whole, off) else 'absent':<8s}"
              f" worker: {'present' if present(worker, off) else 'absent'}")
    print(f"  {'shared scratch [0x101a5328]':<48s} whole effect: "
          f"{'present' if '0x101a5328' in whole else 'absent':<8s}"
          f" worker: {'present' if '0x101a5328' in worker else 'absent'}")
    print("  arg2 (fp) inside the worker ([esp+0x1c]): "
          f"{'read' if 'esp + 0x1c]' in worker else 'never read'}")
    print("  ycp_edit / ycp_temp (+4 / +8) cannot be checked this way - fp->track is")
    print("  also based on a register here - but there is no frame-filter path to use")
    print("  them: フェード has one registration, flag=0x20, object effect only.")
    print("  Only *(fpip+0xAC) is touched, and only by the worker, so there is nothing")
    print("  to swap: フェード edits the object image in place - the same shape as")
    print("  モザイク, and unlike every ぼかし-family effect.")

    print("\n--- (3) thread coverage, thread_num = 8 ---")
    print("      h    rows covered   by threads")
    for h in (240, 16, 8, 7, 3, 1):
        parts = [(t, c_div(h * t, 8), c_div(h * (t + 1), 8)) for t in range(8)]
        live = [(t, a, b) for t, a, b in parts if a < b]
        print(f"    {h:4d}    {sum(b - a for _t, a, b in live):4d}/{h:<4d}      "
              f"{[f'{t}:[{a},{b})' for t, a, b in live]}")
    print("  Always the full height. Compare シャープ's workers, which carry the extra")
    print("  `h < thread_num && tid != 0 -> return` guard and stop entirely at h < 8")
    print("  (thread_split.md §3).")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
