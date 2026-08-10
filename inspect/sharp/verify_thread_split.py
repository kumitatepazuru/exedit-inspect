"""How シャープ divides work between threads, and what happens when the object
is smaller than the thread count.

All three workers open with the same shape:

    lo = dim * tid       / thread_num
    hi = dim * (tid + 1) / thread_num
    if (dim < thread_num && tid != 0) return;      // (A)
    if (lo >= hi) return;                          // (B)

with `dim` = the object's width for the vertical box pass and its height for
the horizontal box pass and for the combine worker.

Guard (B) alone is harmless: the per-thread ranges telescope, so even when
`dim < thread_num` every row still belongs to exactly one thread - that is how
`シャドー`, `エッジ抽出` and `ライト` behave, and why `エッジ抽出`'s duplicate
border writes are the worst that happens there.

Guard (A) changes that. It silences every thread except 0 - and thread 0's own
range is `[0, dim/thread_num)`, which is **empty** whenever `dim <
thread_num`. So the pass does not run at all.

`ぼかし`'s two integer `サイズ固定` **off** workers (`0x1000eae0`, `0x1000eef0`)
have the same guard and do not have the problem: they write `thread_num = 1` in
the slot the `jge` skips and compute `lo`/`hi` **afterwards**, so thread 0 ends
up owning the whole extent. シャープ computes `lo`/`hi` first and has no
substitution at all - which is not surprising once verify_blur_chain.py §5 is
taken into account: シャープ's two box workers are `ぼかし`'s `サイズ固定`
**on** workers, instruction for instruction, and those do not have it either.

The script

  1. dumps the three prologues with the two guards marked,
  2. reproduces the range arithmetic and shows the coverage collapsing,
  3. scans the whole image for the `jge / test r,r / jne` guard and separates
     the sites that do write `n = 1` in the skipped slot from the ones that do
     not,
  4. spells out what each of the three "too small" cases does to the output.

Run via main.py:
    uv run main.py inspect/sharp/verify_thread_split.py
"""

import re

from tools.cints import c_div
from tools.disasm import dump_range, make_md
from tools.filter_table import walk
from tools.pe_image import PEImage

PROLOGUES = {
    "vertical box 0x100891c0 (splits COLUMNS, guards on w)": (0x100891C0, 0x5C),
    "horizontal box 0x10089690 (splits ROWS, guards on h)": (0x10089690, 0x4C),
    "combine 0x10089b60 (splits ROWS, guards on h)": (0x10089B60, 0x78),
}

ANNOTATIONS = {
    0x100891E9: "lo = w * tid / thread_num",
    0x100891F4: "hi = w * (tid+1) / thread_num   <- computed BEFORE the guard",
    0x100891F6: "(A) w < thread_num ?",
    0x10089200: "     ... then only thread 0 survives",
    0x10089216: "(B) lo >= hi -> return. For thread 0 with w < thread_num, hi == 0",
    0x100896B8: "lo = h * tid / thread_num",
    0x100896C4: "hi = h * (tid+1) / thread_num",
    0x100896C6: "(A) h < thread_num ?",
    0x100896CC: "     ... only thread 0 survives",
    0x100896DA: "(B) lo >= hi -> return",
    0x10089B88: "lo = h * tid / thread_num",
    0x10089B94: "hi = h * (tid+1) / thread_num",
    0x10089B96: "(A) h < thread_num ?",
    0x10089BA2: "     ... only thread 0 survives",
    0x10089BD1: "(B) lo >= hi -> return, before a single pixel is combined",
}

# ぼかし 0x1000eae0, for contrast: same guard, but the range is computed after
# it and the skipped slot writes thread_num = 1.
BLUR_PROLOGUE = (0x1000EAFF, 0x40)
BLUR_ANNOTATIONS = {
    0x1000EAFF: "(A) w < thread_num ?",
    0x1000EB09: "     ... only thread 0 survives ...",
    0x1000EB0F: "     ... and it gets thread_num = 1   <- シャープ has no equivalent",
    0x1000EB1B: "hi = w * (tid+1) / thread_num, with the substituted thread_num",
    0x1000EB2F: "lo = w * tid / thread_num",
}

GUARD = re.compile(rb"(?:\x7d.|\x0f\x8d....)\x85[\xc0-\xff](?:\x75.|\x0f\x85....)", re.S)


def ranges(dim, n, guard_a):
    """Which indices each thread claims, under (A)+(B) or (B) alone."""
    out = []
    for tid in range(n):
        lo, hi = c_div(dim * tid, n), c_div(dim * (tid + 1), n)
        if guard_a and dim < n and tid != 0:
            continue
        if lo >= hi:
            continue
        out.append((tid, lo, hi))
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("--- (1) the three prologues ---")
    for label, (addr, size) in PROLOGUES.items():
        dump_range(img, addr, size, label=label, resolve=False, annotations=ANNOTATIONS)
    dump_range(img, *BLUR_PROLOGUE, label="ぼかし 0x1000eae0, for contrast",
               resolve=False, annotations=BLUR_ANNOTATIONS)

    print("\n--- (2) coverage, thread_num = 8 ---")
    print("    dim   with (A)+(B) [シャープ]                with (B) only [シャドー/エッジ抽出]")
    for dim in (32, 9, 8, 7, 5, 3, 1):
        a = ranges(dim, 8, True)
        b = ranges(dim, 8, False)
        cov_a = sum(hi - lo for _t, lo, hi in a)
        cov_b = sum(hi - lo for _t, lo, hi in b)
        print(f"    {dim:4d}   {cov_a:2d}/{dim} covered by {len(a)} thread(s)"
              f"{'  <- NOTHING RUNS' if cov_a == 0 else '':<20s}"
              f"   {cov_b:2d}/{dim} by {len(b)}")
    print("  The (B)-only column always covers the whole extent; the two guards")
    print("  together cover none of it as soon as dim < thread_num.")

    print("\n--- (3) every jge / test r,r / jne guard in the image ---")
    md = make_md()
    table = sorted(set((r.func_proc, r.name) for r in walk(img)))

    def owner(va):
        best = None
        for a, n in table:
            if a <= va and (best is None or a > best[0]):
                best = (a, n)
        return f"{best[1]}+0x{va - best[0]:x}" if best else "?"

    for sec in img.pe.sections:
        if sec.Name.rstrip(b"\x00") != b".text":
            continue
        base = img.image_base + sec.VirtualAddress
        blob = img.code(base, sec.Misc_VirtualSize)

    with_sub, without = [], []
    for m in GUARD.finditer(blob):
        va = base + m.start()
        ins = list(md.disasm(img.code(va, 32), va))[:4]
        if len(ins) < 4 or ins[0].mnemonic != "jge":
            continue
        jge, test, _jne, nxt = ins
        ops = [o.strip() for o in test.op_str.split(",")]
        if ops[0] != ops[1]:
            continue
        sub = (nxt.mnemonic == "mov" and nxt.op_str.endswith(", 1")
               and int(jge.op_str, 16) == nxt.address + nxt.size)
        (with_sub if sub else without).append(va)

    print(f"  with a `mov r32, 1` in the slot the jge skips: {len(with_sub)}")
    for va in with_sub:
        print(f"    0x{va:08x}  {owner(va)}")
    print("    (attribution is 'nearest preceding registered func_proc', so a large")
    print("     +0x... means an unregistered helper somewhere after that entry -")
    print("     tools/xrefs.py makes the same reservation)")
    print(f"  without it: {len(without)}, including "
          f"{[hex(v) for v in without if 0x10089030 <= v < 0x10089D9A]}")
    print("""  (the pattern needs jge/test/jne adjacent, so it finds two of シャープ's three
  guards - the combine's has a `mov` wedged between the jge and the test, and
  is shown in full in section 1 instead.)

  So the bare form is by far the common one, and the substitution is the
  exception - even inside `ぼかし`, where only the two integer サイズ固定-off
  workers carry it and the サイズ固定-on and curve workers do not.

  **Not checked here**: what the other sites do with an undersized object.
  Several sit in workers with a different loop shape, and the consequence
  depends on guard (B) covering the whole body the way シャープ's does. The
  claim proved above is about these three workers only.""")

    print("\n--- (4) what that does to the output ---")
    print("  func_proc swaps *(fpip+0xAC) and *(fpip+0xB0) after every blur pass,")
    print("  whether or not the pass wrote anything, so the bookkeeping has to be")
    print("  played out rather than guessed. X = the buffer that starts as the object,")
    print("  Y = the pair buffer and STALE its unknown prior contents.\n")
    print("      w    h   範囲   *(fpip+0xAC) after the 4 passes   final output")
    for w, h, rng in ((32, 32, 5), (5, 32, 5), (32, 5, 5), (5, 5, 5),
                      (5, 32, 1), (32, 5, 1)):
        n = 8
        ac, b0 = {"buf": "X", "holds": "orig"}, {"buf": "Y", "holds": "STALE"}
        r_lo = c_div(rng, 2)
        for radius in (rng - r_lo, r_lo):
            if radius == 0:
                continue
            for vertical in (True, False):
                dim = w if vertical else h
                if dim >= n:                      # the pass actually runs
                    b0 = {"buf": b0["buf"],
                          "holds": f"blur({ac['holds']})"}
                ac, b0 = b0, ac                   # unconditional swap
        combine_runs = h >= n
        out = (f"orig + S*(orig - {ac['holds']})" if combine_runs
               else ac["holds"])
        print(f"    {w:4d} {h:4d} {rng:5d}   {ac['buf']} = {ac['holds']:<26s} {out}")
    print("""
  Reading the rows:

    w <  N   the vertical passes write nothing, so the horizontal ones read the
             pair buffer's stale contents as if they were pass 1's output. The
             blur becomes that, and the combine subtracts it from the original.
             **Undetermined**: what the pair buffer holds - this analysis has
             never pinned it down (box_blur.md §4 makes the same reservation).

    h <  N   the horizontal passes AND the combine all write nothing. Each
             vertical result is then undone by the next (skipped) pass's swap,
             so *(fpip+0xAC) ends up back on the untouched original: a complete
             no-op, not a vertical blur.

    both     nothing runs at all; same no-op.

  All of these need an object thinner than the thread count, so they are
  reachable with thin lines and small text, not with ordinary footage. Nothing
  crashes; the effect just silently stops being シャープ.""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
