"""Who runs, in what order, and on which globals.

func_proc fires `exec_multi_thread_func` either once or four times. Four, not
three: with `境界補正 != 0` the key worker `0x10016340` is dispatched a **second
time** before the two box passes. That is not a decompiler artifact - the dword
`0x10016340` occurs exactly twice in the whole image and both occurrences are a
`push` inside func_proc, which this script shows by byte scan.

Claims checked here:

  1. **The dispatch order**, read out of func_proc as raw `push imm32` /
     `call [reg+0xCC]` pairs rather than from decompiled text.
  2. **The repeat is idempotent.** The key worker's only write is
     `alpha = 0`, and its decision depends on y/cb/cr, which it never modifies.
     Running it twice therefore produces the first run's output exactly - the
     cost is one wasted full-image pass, not a different picture. (The pixel
     scan for that single store is in verify_key_box.py; here the point is the
     dispatch shape.)
  3. **Only two globals exist**, `0x1011ed38` = r and `0x1011ed34` = 2r+1, and
     every reference to either is inside this effect. カラーキー needs no
     matte buffers because its matte is the alpha channel itself.
  4. **The three workers read a disjoint set of inputs.** The key worker reads
     `fp->ex_data_ptr` and `fp->track[]`; the two box passes read neither - they
     take everything from the globals and `fpip`. `fp->check[]` is never read by
     anything, which is consistent with `キー色の取得` being a button.
  5. **The split axis differs per pass**: rows for the key worker and pass 3,
     **columns** for the vertical pass 2, which is what makes a barrier between
     passes necessary and is why they are separate dispatches.

Run via main.py:
    uv run main.py inspect/color_key/verify_dispatch.py
"""

from tools.disasm import disasm_range, function_body
from tools.pe_image import PEImage
from tools.xrefs import function_owners, nearest_owner, scan

FUNC_PROC = 0x100162C0
FUNC_PROC_END = 0x10016339
WORKERS = {
    0x10016340: "the key test           (alpha = 0 inside the box)",
    0x10016430: "境界補正 pass2         (vertical box average of alpha)",
    0x100165D0: "境界補正 pass3         (horizontal box average + stretch + apply)",
}
GLOBALS = {0x1011ED38: "r = 境界補正", 0x1011ED34: "kernel width 2r+1"}

# fp field offsets, from data/filter.h
FP_FIELDS = {0x44: "fp->track", 0x48: "fp->check", 0x4C: "fp->ex_data_ptr",
             0x60: "fp->exfunc", 0x64: "exedit's table"}
# fpip fields exedit adds past the SDK struct (inspect/common/filter_registration.md §3)
FPIP_FIELDS = {0xAC: "object buffer", 0xB0: "pair buffer", 0xB4: "w", 0xB8: "h",
               0xEC: "row stride [px]"}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    owners = function_owners(img)

    print("--- 1. the dispatch sequence, as func_proc pushes it ---")
    pending = None
    order = []
    for insn, _ in disasm_range(img, FUNC_PROC, FUNC_PROC_END - FUNC_PROC, resolve=False):
        if insn.mnemonic == "push" and insn.op_str.startswith("0x1001"):
            pending = int(insn.op_str, 16)
        elif insn.mnemonic == "call" and "0xcc" in insn.op_str and pending:
            order.append((insn.address, pending))
            pending = None
    for i, (at, target) in enumerate(order, 1):
        print(f"  {i}. 0x{at:08x}  exec_multi_thread_func(0x{target:08x})   "
              f"{WORKERS.get(target, '?')}")
    print(f"  -> {len(order)} dispatches, {len(set(t for _, t in order))} distinct workers")
    print("  Dispatch 1 always runs. Dispatches 2-4 are inside `if (track[2] != 0)`.")

    print("\n--- 2. is 0x10016340 really pushed twice? ---")
    for va in scan(img, 0x10016340):
        print(f"  the dword 0x10016340 occurs at 0x{va:08x}  ({nearest_owner(owners, va)})")
    print("  Two occurrences, both operands of a `push` in func_proc, and none in")
    print("  .data - so nothing else in exedit can reach this worker and the repeat")
    print("  is real. The worker's decision is a function of y/cb/cr, which it never")
    print("  writes, and its output is a constant 0 into alpha - so the second run")
    print("  recomputes the first run's answer and stores the same zeros.")
    print("  境界補正 > 0 therefore costs one extra full pass over the image for")
    print("  nothing. Most likely two identical source functions that MSVC folded")
    print("  (/OPT:ICF); either way the observable behaviour is unaffected.")

    print("\n--- 3. the globals ---")
    for va, meaning in GLOBALS.items():
        hits = scan(img, va)
        outside = [h for h in hits if not FUNC_PROC <= h < 0x100169F4]
        print(f"  0x{va:08x}  {meaning:<20} {len(hits)} reference(s), "
              f"{len(outside)} outside 0x100162c0..0x100169f3")
        for h in hits:
            print(f"      0x{h:08x}  ({nearest_owner(owners, h)})")
    print("  Both are private to カラーキー. Compare クロマキー, which needs five")
    print("  (two 16-bit matte pointers, a third for 色彩補正, and the same r / 2r+1):")
    print("  カラーキー has no matte to point at - the key worker has already written")
    print("  its answer into the alpha of *(fpip+0xAC), and the box passes read it")
    print("  back from there.")

    print("\n--- 4/5. what each worker reads ---")
    for addr, role in WORKERS.items():
        fp_hits, fpip_hits = set(), set()
        for insn in function_body(img, addr, 0x400):
            for off, name in FP_FIELDS.items():
                if f"+ 0x{off:x}]" in insn.op_str:
                    fp_hits.add(name)
            for off, name in FPIP_FIELDS.items():
                if f"+ 0x{off:x}]" in insn.op_str:
                    fpip_hits.add(name)
        # Every pixel store is a 16-bit `mov` into the buffer. Report the
        # destination operands verbatim rather than a parsed displacement:
        # pass 3's last phase folds the +6 into the pointer with an earlier
        # `lea esi, [ecx + 6]` (0x100167b9), so a displacement-only summary
        # would hide a store instead of explaining it.
        stores = sorted({insn.op_str.split(",")[0].strip()
                         for insn in function_body(img, addr, 0x400)
                         if insn.mnemonic == "mov" and insn.op_str.startswith("word ptr")})
        print(f"\n  0x{addr:08x}  {role}")
        print(f"      fp fields   : {sorted(fp_hits) or ['none']}")
        print(f"      fpip fields : {sorted(fpip_hits)}")
        print(f"      16-bit stores : {stores}")
    print("\n  Every 16-bit store in all three workers lands on +6 of an 8-byte pixel -")
    print("  directly, or through a pointer that had the 6 added by `lea` first. So")
    print("  カラーキー writes the alpha channel and nothing else: y, cb and cr come")
    print("  out of the effect bit-for-bit unchanged, which is what separates it from")
    print("  クロマキー (whose 色彩補正 / 境界補正 paths rewrite the chroma).")
    print("\n  The vertical pass splits by COLUMN and the other two by ROW; the")
    print("  dimension each one divides by thread_num is visible in disasm_params.py")
    print("  (0x100163a2, h) and in verify_border_chain.py (0x1001646a, w).")
    print("  `fp->check` appears nowhere: キー色の取得 is a button, and there is no")
    print("  checkbox in this effect for a worker to branch on.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
