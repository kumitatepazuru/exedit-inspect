"""Annotated raw disassembly of every instruction 凸エッジ (convex edge) owns.

The whole effect is 846 bytes in two functions that sit back to back:

    0x10007a80 func_proc   269 bytes,  87 instructions
    0x10007b90 worker      574 bytes, 174 instructions

which is small enough that "the annotated listing" and "the analysis" can be
the same artefact - there is no third function, no UI code, no ex_data. What
the listing has to supply on top of the decompiler (decompile_convex_edge.py)
is:

  * the x87 block that turns 角度 into a Q16 direction vector. angr renders
    all seven of those instructions as `/* unsupported instruction */`, and
    the two shared constants (-pi/1800 at 0x1009a3f8, 65536.0 at 0x1009a3e8)
    are what identify the convention - see inspect/common/angle_vector.md.
  * names for the worker's `esp+0x..` slots. The worker keeps 14 live values
    in a 0x44-byte frame and reuses two of the *caller's* argument slots
    (esp+0x48 = thread_id, esp+0x4c = thread_num) as the source cursor and the
    running sum once their original contents are dead, which reads as noise
    without the mapping below.
  * that the sampling loop's four bounds tests are real - every sample is
    range-checked against the object rectangle before it is read, so 凸エッジ
    has none of the sliding-window overruns collected in
    inspect/common/box_blur.md §4.

Run via main.py:
    uv run main.py inspect/convex_edge/disasm_params.py
    uv run main.py inspect/convex_edge/disasm_params.py --only sampling
"""

import argparse

from tools.disasm import dump_all
from tools.pe_image import PEImage

FUNC_PROC = 0x10007A80
WORKER = 0x10007B90

# {label: (start, size)} - the whole effect, cut where the shape changes.
RANGES = {
    "func_proc / parameters: 幅 clamp, 角度 -> Q16 direction, 描画品質 cap":
        (0x10007A80, 0xB3),
    "func_proc / dispatch: 高さ -> scale, exec_multi_thread_func, buffer swap":
        (0x10007B33, 0x5D),
    "worker / prologue: row band, cursors, globals pulled into the frame":
        (0x10007B90, 0xB5),
    "worker / sampling loop: sum += a(p + o_k) - a(p - o_k), k = 1..steps":
        (0x10007C45, 0xAE),
    "worker / encode: d = trunc(sum * scale), two output paths, alpha copied":
        (0x10007CF3, 0xA9),
    "worker / loop tails: x++, y++, row advance, return":
        (0x10007D9C, 0x32),
}

# esp+0x.. slots in the worker, after `sub esp,0x34` + 4 pushes (frame 0x44).
# Two of these live in the caller's argument area on purpose: by the time they
# are written, thread_id and thread_num have both been consumed.
SLOTS = {
    0x10: "dst cursor (fpip+0xB0 + (y*stride + x)*8)",
    0x14: "x",
    0x18: "w      = *(fpip+0xB4)",
    0x1C: "y",
    0x20: "stride = *(fpip+0xEC)   [pixels per row]",
    0x24: "h      = *(fpip+0xB8)",
    0x28: "src base = *(fpip+0xAC)",
    0x2C: "k counter (counts down from steps)",
    0x30: "steps  = g_100d7590",
    0x34: "row byte offset = y*stride*8",
    0x38: "dx     = g_100d7598  [Q16]",
    0x3C: "dy     = g_100d7594  [Q16]",
    0x40: "y_end",
    0x48: "src cursor  (reuses the thread_id argument slot)",
    0x4C: "sum         (reuses the thread_num argument slot)",
}

NOTES = {
    # ---- func_proc: parameters -------------------------------------------
    0x10007A88: "ecx = fp->track[]",
    0x10007A8B: "esi = track[0] = 幅",
    0x10007A8F: "幅 == 0 -> return 1. THE ONLY early-out; 高さ=0 and 角度 never stop it",
    0x10007A95: "edi = fpip",
    0x10007A99: "eax = *(fpip+0xB4) = w",
    0x10007AA2: "cdq/sub/sar = c_div(w, 2), truncating",
    0x10007AA8: "幅 = min(幅, w/2)",
    0x10007AAA: "eax = *(fpip+0xB8) = h",
    0x10007AB9: "幅 = min(幅, h/2)   <- the only clamp in the effect",
    0x10007ABB: "st0 = track[2] = 角度 raw [1/10 degree]",
    0x10007ABE: "* -pi/1800  ->  t = -radians(角度).  angle_vector.md §1",
    0x10007AC6: "sin(t) = -sin(角度)",
    0x10007AC8: "* 65536 -> Q16",
    0x10007ACE: "_ftol: truncate toward zero",
    0x10007AD3: "cos(t) = cos(角度)  (st0 still holds t)",
    0x10007AD7: "g_100d7598 = dx = trunc(-sin(角度) * 65536)",
    0x10007ADD: "* 65536 -> Q16",
    0x10007AEA: "g_100d7594 = dy = trunc( cos(角度) * 65536)",
    0x10007AF0: "eax = fpip->flag",
    0x10007AF2: "test ah,2 = flag & 0x200 = 'draft quality is allowed'",
    0x10007AF7: "... and only when 幅 > 16",
    0x10007AFE: "dx * 幅",
    0x10007B07: "cdq/and 0xf/add/sar 4 = c_div(dx*幅, 16): stretch the step 幅/16x",
    0x10007B18: "steps = 16 (same total reach, 16 samples instead of 幅)",
    0x10007B22: "g_100d7594 = c_div(dy*幅, 16)",
    0x10007B2B: "幅 <= 0 after the clamp -> return 1 (w or h below 2 px)",
    0x10007B2D: "g_100d7590 = steps",
    # ---- func_proc: dispatch ---------------------------------------------
    0x10007B38: "st0 = track[1] = 高さ raw (display scale 100 -> 0.00..3.00)",
    0x10007B3E: "push the worker",
    0x10007B43: "* 0.5",
    0x10007B4C: "ecx = 5*5*4*steps = 100 * steps",
    0x10007B57: "g_100d7588 = 高さ / (200 * steps)   [double]",
    0x10007B5F: "edx = fp->exfunc  (filter_registration.md §4)",
    0x10007B62: "exfunc->exec_multi_thread_func(worker, fp, fpip)",
    0x10007B77: "swap *(fpip+0xAC) <-> *(fpip+0xB0): the pair buffer becomes the object",
    0x10007B86: "return 1. w/h/+0xD4/+0xD8 are never written - the canvas does not move",
    # ---- worker: prologue -------------------------------------------------
    0x10007BB6: "y_end   = (thread_id+1) * h / thread_num",
    0x10007BC0: "esi = steps",
    0x10007BCA: "edx = dx",
    0x10007BE8: "eax = dy",
    0x10007BF7: "y_start =  thread_id    * h / thread_num   <- split by ROWS",
    0x10007C07: "empty band -> return",
    0x10007C12: "row byte offset = y_start * stride * 8",
    0x10007C19: "src = *(fpip+0xAC) + offset   (top of the y loop)",
    0x10007C1F: "dst = *(fpip+0xB0) + offset",
    0x10007C3F: "w <= 0 -> skip straight to the row advance",
    # ---- worker: sampling loop -------------------------------------------
    0x10007C45: "accX = 0  (top of the x loop)",
    0x10007C47: "accY = 0",
    0x10007C4B: "sum = 0",
    0x10007C55: "k counter = steps",
    0x10007C61: "accX += dx      (top of the k loop)",
    0x10007C67: "accY += dy",
    0x10007C6F: "ox = accX >> 16   <- sar, i.e. floor(k*dx / 65536)",
    0x10007C72: "sx = x + ox",
    0x10007C77: "oy = accY >> 16",
    0x10007C7A: "sy = y + oy",
    0x10007C7E: "forward sample: sx < 0  -> contribute nothing",
    0x10007C84: "                sx >= w -> contribute nothing",
    0x10007C88: "                sy < 0  -> contribute nothing",
    0x10007C94: "                sy >= h -> contribute nothing",
    0x10007CA1: "a(x+ox, y+oy)  <- +6 only: the colour of the neighbour is never read",
    0x10007CA6: "sum += a",
    0x10007CB4: "backward sample sits at -(ox, oy) exactly, not at floor(-k*dx/65536)",
    0x10007CDB: "a(x-ox, y-oy)",
    0x10007CE0: "sum -= a",
    0x10007CED: "next k",
    # ---- worker: encode ---------------------------------------------------
    0x10007CF3: "st0 = sum",
    0x10007CF7: "* g_100d7588",
    0x10007CFD: "d = trunc(sum * 高さ / (200*steps))",
    0x10007D0A: "y0 = src.y",
    0x10007D0D: "d >= 0 -> additive path (highlight)",
    0x10007D11: "y0 <= 0 -> additive path as well, even though d < 0",
    0x10007D13: "ny = d + y0",
    0x10007D15: "ny >= 0 ?",
    0x10007D17: "ny < 0 -> ny = 0 and scale = 0 (the only clamp on the output)",
    0x10007D1F: "ny << 12",
    0x10007D23: "scale = (ny << 12) / y0   [Q12], idiv = truncate",
    0x10007D25: "dst.y = ny",
    0x10007D34: "dst.cb = (cb * scale) >> 12   <- sar, floor, and cb is signed",
    0x10007D45: "dst.cr = (cr * scale) >> 12",
    0x10007D49: "ax = src.a",
    0x10007D55: "dst.y = y0 + d   <- NO clamp: may exceed 4096, or go negative if y0 < 0",
    0x10007D59: "dst.cb = cb, unchanged",
    0x10007D69: "dst.cr = cr, unchanged",
    0x10007D6D: "ax = src.a",
    0x10007D71: "restore esi = steps (it was scratch for sx inside the k loop)",
    0x10007D75: "dst.a = src.a - alpha is copied verbatim on both paths",
    0x10007D7D: "src cursor += 8",
    0x10007D89: "dst cursor += 8",
    0x10007D96: "next x",
    # ---- worker: tails ----------------------------------------------------
    0x10007DB1: "stride * 8",
    0x10007DC0: "next y",
    0x10007DCD: "return",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="disasm_params")
    parser.add_argument("--only", help="substring of a range label")
    args = parser.parse_args(argv or [])

    ranges = RANGES
    if args.only:
        ranges = {k: v for k, v in RANGES.items() if args.only in k}
        if not ranges:
            print(f"no range label contains {args.only!r}; known: {list(RANGES)}")
            return

    print(__doc__)
    print("worker stack frame (esp+0x.. after the prologue):")
    for off, what in sorted(SLOTS.items()):
        print(f"  esp+0x{off:02x}  {what}")

    img = PEImage(dll_path)
    dump_all(img, ranges, annotations=NOTES, mnemonic_width=8)

    lo, hi = FUNC_PROC, 0x10007DCE
    print(f"\n--- the whole effect is 0x{lo:08x}..0x{hi - 1:08x} = {hi - lo} bytes ---")
    print("  0x10007a70 just before it is 直前オブジェクト's 5-instruction func_proc,")
    print("  0x10007dd0 just after it is a shared `return 1` stub. Nothing else in the")
    print("  image belongs to 凸エッジ (verify_registration.py §2).")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
