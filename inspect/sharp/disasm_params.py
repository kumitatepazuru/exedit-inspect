"""func_proc and the unsharp combine worker, annotated instruction by
instruction.

シャープ's func_proc is a dispatcher with no pixel loop. In order:

  1. return 1 immediately if `強さ == 0` or `範囲 == 0`,
  2. copy the whole object image into the shared scratch buffer `[0x101a5328]`
     with `table[0x44]`, mode word `0x13000003` = plain copy, 8-byte pixels on
     both sides (blend_modes.md §2/§3). That copy is the *original*, and it is
     the only reason the effect can subtract a blur from it later,
  3. split `範囲` into `r_hi = 範囲 - 範囲/2` and `r_lo = 範囲/2` and run
     V(r_hi), H(r_hi), V(r_lo), H(r_lo) - the same four-pass schedule as
     `ぼかし` and `シャドー` (box_blur.md §2), swapping `*(fpip+0xAC)` with
     `*(fpip+0xB0)` after each pass,
  4. run the combine worker once, **without** a final swap, so the sharpened
     image stays in `*(fpip+0xAC)`.

`強さ` is never read here. It is read - and divided by 1000 - inside the
combine worker, once per thread.

The combine worker is the interesting half, so it is annotated in full too.
One warning about reading it with angr instead: the decompiler renders

    node += a0 * (node * a1 - iter1[3] * iter1[0]) / v23 >> 12

which reads as "multiply by 強さ, then divide". The instructions say the
opposite - `idiv` first, `imul 強さ` second, `sar 12` third - and that order is
what verify_unsharp.py reproduces.

The annotations are the claims; the instructions beside them are the evidence.

Run via main.py:
    uv run main.py inspect/sharp/disasm_params.py
    uv run main.py inspect/sharp/disasm_params.py --only combine
"""

import argparse

from tools.disasm import dump_all
from tools.pe_image import PEImage

FUNC_PROC = (0x10089030, 0x186)
COMBINE = (0x10089B60, 0x23A)

ANNOTATIONS = {
    # ---------------------------------------------------------- func_proc
    0x10089032: "edi = fp",
    0x10089036: "eax = fp->track (+0x44)",
    0x10089039: "track[0] = 強さ",
    0x1008903C: "  == 0 -> return 1. Nothing is touched, not even the scratch copy",
    0x10089042: "ebx = track[1] = 範囲",
    0x10089047: "  == 0 -> return 1 as well. Two independent early returns",
    0x10089051: "esi = fpip",
    0x10089055: "cdq + sub eax,edx + sar 1 = trunc(範囲/2), i.e. c_div not floor",
    0x10089056: "ecx = fpip->h (+0xB8)",
    0x1008905E: "edx = fpip->w (+0xB4)",
    0x10089064: "mode word: 0x13 = plain copy, low byte 3 = 8-byte pixels src+dst",
    0x1008906C: "ecx = *(fpip+0xAC), the object image",
    0x10089073: "edx = [0x101a5328], the scratch shared with 発光/グロー/ライト/シャドー/縁取り",
    0x10089080: "eax = fp->exfunc table replacement (+0x64)",
    0x10089088: "ebp = r_lo = trunc(範囲/2)",
    0x1008908A: "table[0x44](scratch, 0,0, image, 0,0, w, h, 0, copy) - the untouched original",
    0x10089092: "eax = r_hi = 範囲 - trunc(範囲/2) = ceil(範囲/2)",
    0x10089096: "g_102320c0 = radius of the horizontal pass",
    0x1008909B: "g_102320bc = radius of the vertical pass (same value this round)",
    0x100890A1: "r_hi == 0 is unreachable: 範囲 >= 1 here, so ceil(範囲/2) >= 1",
    0x100890A3: "kernel width 2*r_hi+1",
    0x100890A8: "g_102320c4 = vertical kernel width",
    0x100890AD: "ecx = fp->exfunc (+0x60)",
    0x100890B1: "worker 0x100891c0 = vertical box average",
    0x100890B6: "EXFUNC::exec_multi_thread_func(worker, fp, fpip)",
    0x100890C8: "swap *(fpip+0xAC) <-> *(fpip+0xB0): the pass output becomes the input",
    0x100890D4: "reload r_hi for the horizontal pass",
    0x100890E5: "g_102320c8 = horizontal kernel width",
    0x100890EE: "worker 0x10089690 = horizontal box average",
    0x10089116: "round 2: both radii become r_lo = trunc(範囲/2)",
    0x10089122: "r_lo == 0 (i.e. 範囲 == 1) -> skip passes 3 and 4 entirely",
    0x10089137: "vertical again, this time with r_lo",
    0x10089175: "horizontal again, with r_lo",
    0x1008919B: "worker 0x10089b60 = the unsharp combine ...",
    0x100891A0: "... and no swap after it: the result is written in place into *(fpip+0xAC)",
    0x100891AC: "return 1",

    # ------------------------------------------------------------ combine
    0x10089B6A: "eax = fpip->w",
    0x10089B70: "ecx = fpip->h",
    0x10089B84: "y0 = h*tid/n - this worker splits by ROWS (the vertical one splits by columns)",
    0x10089B96: "h < thread_num and tid != 0 -> nothing to do",
    0x10089BA8: "ecx = fp (3rd arg)",
    0x10089BAC: "0x10624dd3: the /1000 magic (param_scaling.md §2) ...",
    0x10089BB1: "edx = fp->track",
    0x10089BB4: "ecx = track[0] = 強さ, raw",
    0x10089BB6: "強さ * 4096 ...",
    0x10089BBB: "... sar 6 + sign fixup -> S = trunc(強さ*4096/1000). raw 1000 (UI 100.0) = 4096",
    0x10089BC5: "eax = fpip->line stride (+0xEC) [pixels]",
    0x10089BCD: "S parked in the caller's arg slot; every thread recomputes it",
    0x10089BF4: "eax = the scratch base: the ORIGINAL image copied by func_proc",
    0x10089BF9: "esi = *(fpip+0xAC) = the four-times-blurred image, and the write target",
    0x10089C01: "edx = scratch + same row offset. Both use fpip+0xEC as the stride",
    0x10089C18: "eax = orig.a",
    0x10089C1C: "edi = blur.a",
    0x10089C20: "edi = (blur.a * orig.a) >> 12 -- the divisor of the general path",
    0x10089C31: "== 4096 exactly? that happens only when both alphas are 4096",
    0x10089C3F: "  no -> the general, alpha-weighted path at 0x10089caa",
    0x10089C41: "fast path: both opaque. eax = blur.y",
    0x10089C46: "edi = orig.y - blur.y",
    0x10089C48: "* S ...",
    0x10089C51: "... sar 12 (floor, not trunc - the difference is signed)",
    0x10089C54: "y' = orig.y + S*(orig.y - blur.y)/4096  <- the unsharp mask, in one line",
    0x10089C66: "cb' likewise",
    0x10089C74: "cr' likewise",
    0x10089C76: "y' >= 0 -> write as is. There is NO upper clamp anywhere",
    0x10089C7E: "y' <= -1024 -> the pixel becomes flat black (below)",
    0x10089C86: "-1024 < y' < 0: fade the chroma out linearly and pin y' to 0 ...",
    0x10089C92: "... cb' = cb'*(y'+1024)/1024, same for cr'. Shared idiom, see verify_luma_undershoot.py",
    0x10089C98: "y' = 0",
    0x10089C9F: "the y' <= -1024 arm: y = cb = cr = 0",
    0x10089CAA: "general path. (blur.a*orig.a)>>12 <= 0 -> leave the pixel at its ORIGINAL value",
    0x10089CB2: "edx = blur.y",
    0x10089CB9: "edx = blur.y * blur.a",
    0x10089CC4: "eax = orig.y * orig.a",
    0x10089CC7: "eax = orig.y*orig.a - blur.y*blur.a  (a difference of premultiplied values)",
    0x10089CCA: "idiv by (blur.a*orig.a)>>12 -- truncating, and it happens BEFORE the 強さ scale",
    0x10089CD0: "* S ...",
    0x10089CD3: "... >> 12",
    0x10089CD6: "y' = orig.y + that",
    0x10089CEB: "cb: same shape",
    0x10089D0E: "cr: same shape",
    0x10089D1A: "the same three-way negative-luma cleanup as the fast path",
    0x10089D40: "restore edx = scratch pointer (clobbered by the idivs)",
    0x10089D44: "ax = orig.a ...",
    0x10089D49: "out.y",
    0x10089D4C: "... out.a = orig.a. The blur passes' alpha is thrown away; シャープ never",
    0x10089D50: "    changes the alpha channel",
    0x10089D54: "out.cb",
    0x10089D58: "out.cr - written into *(fpip+0xAC), on top of the blurred pixel",
    0x10089D5C: "advance both pointers by one 8-byte pixel",
    0x10089D81: "next row: += stride*8, for the scratch and the image alike",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="disasm_params")
    parser.add_argument("--only", choices=("func_proc", "combine"),
                        help="dump just one of the two functions")
    args = parser.parse_args(argv or [])

    targets = {
        "func_proc 0x10089030": FUNC_PROC,
        "combine worker 0x10089b60": COMBINE,
    }
    if args.only == "func_proc":
        targets.pop("combine worker 0x10089b60")
    elif args.only == "combine":
        targets.pop("func_proc 0x10089030")

    dump_all(PEImage(dll_path), targets, annotations=ANNOTATIONS, mnemonic_width=9)

    print("""
Reading the two paths together:

    p = (blur.a * orig.a) >> 12

    p == 4096   ->  c' = orig.c + (S * (orig.c - blur.c)) >> 12
    p >  0      ->  c' = orig.c + (S * trunc((orig.c*orig.a - blur.c*blur.a)/p)) >> 12
    p <= 0      ->  c' = orig.c                    (untouched)

    then, for the luma only:
      y' <  -1024        -> (y,cb,cr) = (0,0,0)
      -1024 <= y' < 0    -> cb,cr *= (y'+1024)/1024 ; y' = 0
      y' >= 0            -> unchanged, with no upper bound

    out.a = orig.a, always.

The first two lines agree where they meet: at orig.a = blur.a = 4096 the divide
is exact and the general form collapses onto the fast one. verify_unsharp.py
checks that over the whole alpha grid, and works out what the divisor does to
半透明 pixels.""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
