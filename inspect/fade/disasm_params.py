"""func_proc and the alpha worker, annotated instruction by instruction.

フェード is the smallest effect analysed in this project: two functions,
`0x1004dd40`-`0x1004de95`, 342 bytes including the padding between them. It has
no checkbox, no `ex_data`, no `func_WndProc`, no canvas growth and no pair
buffer - the entire effect is "work out one Q12 number, then multiply every
pixel's alpha by it".

`func_proc` in order:

  1. `g_101a5390 = 4096` (fully opaque),
  2. convert `イン` and `アウト` from hundredths of a second to **frames**,
     using the frame rate in `*(fpip+0xFC)` / `*(fpip+0x100)` and the shared
     constant `100.0` at `0x1009a538` (object_time.md §4). The whole conversion
     is x87 plus two `_ftol` calls; there is no `/1000` magic divide anywhere
     in this effect,
  3. fade-in ramp on `t = *(fpip+0xA8) - fp[0x118] - *(fpip+0x118)`, i.e.
     frames since this object's timeline started (object_time.md §2/§5),
  4. fade-out ramp on `u = fp[0x11C] - *(fpip+0xA8)`, frames left before it
     ends, and keep the smaller of the two,
  5. three exits: `>= 4096` -> `return 1` having touched nothing, `<= 0` ->
     `return 0` (the object is not drawn at all), otherwise one
     `exec_multi_thread_func`.

The x87 stack is worth following, because the two `fmul st(2)` / `fdiv st(1)`
pairs reuse operands left on the stack across a `_ftol` call:

    fild [fpip+0xFC]     st0 = R                       (frame rate numerator)
    fild [fpip+0x100]    st0 = S,      st1 = R
    fmul [0x1009a538]    st0 = S*100,  st1 = R
    fild [track+0]       st0 = イン,   st1 = S*100, st2 = R
    fmul st(2)           st0 = イン*R                  (d8 ca = FMUL ST(0),ST(2))
    fdiv st(1)           st0 = イン*R/(S*100)          (d8 f1 = FDIV ST(0),ST(1))
    call _ftol           pops -> eax; st0 = S*100, st1 = R again
    ... same four for アウト ...
    fstp st(0) x2        drop S*100 and R

so both `fmul`/`fdiv` write into ST(0) and the two divisors survive the first
`_ftol`. verify_seconds_to_frames.py §1 re-reads those opcode bytes rather than
trusting capstone's one-operand rendering.

The annotations are the claims; the instructions beside them are the evidence.

Run via main.py:
    uv run main.py inspect/fade/disasm_params.py
    uv run main.py inspect/fade/disasm_params.py --only worker
"""

import argparse

from tools.disasm import dump_all
from tools.pe_image import PEImage

FUNC_PROC = (0x1004DD40, 0xD3)
WORKER = (0x1004DE20, 0x76)

ANNOTATIONS = {
    # ---------------------------------------------------------- func_proc
    0x1004DD42: "ebp = fp",
    0x1004DD47: "esi = fpip",
    0x1004DD4B: "g_101a5390 = 4096. The effect's ONLY global, and the only thing",
    0x1004DD55: "    the worker will read. Set before anything can fail",
    0x1004DD56: "edi = fp->track (+0x44)",
    0x1004DD59: "st0 = *(fpip+0xFC) = frame rate numerator (object_time.md §4)",
    0x1004DD5F: "st0 = *(fpip+0x100) = frame rate denominator, st1 = numerator",
    0x1004DD65: "x100.0 - because the trackbars are in 1/100 s, not seconds",
    0x1004DD6B: "st0 = track[0] = イン, raw (0..1000 = 0.00..10.00 s)",
    0x1004DD6D: "d8 ca = FMUL ST(0),ST(2): イン * rate",
    0x1004DD6F: "d8 f1 = FDIV ST(0),ST(1): / (scale*100)  -> イン in frames",
    0x1004DD71: "_ftol: truncation toward zero (integer_semantics.md §3), NOT rounding",
    0x1004DD76: "st0 = track[1] = アウト. The divisors are still on the stack",
    0x1004DD79: "ebx = in_frames",
    0x1004DD84: "edx = fp[0x118] = first frame of this object's whole timeline,",
    0x1004DD8A: "    edi = *(fpip+0x118) = this sub-object's own delay [frames].",
    0x1004DD90: "    ecx = out_frames",
    0x1004DD92: "eax = *(fpip+0xA8) = the current frame, absolute",
    0x1004DD98: "t = frame - object start ...",
    0x1004DD9A: "    ... - own delay. Only テキストの文字毎に個別オブジェクト makes",
    0x1004DD9C: "    that last term non-zero (object_time.md §5)",
    0x1004DD9E: "t < in_frames ? (signed)",
    0x1004DDA2: "  no -> no fade-in at all; イン=0 lands here on every frame",
    0x1004DDA4: "(t+1) ...",
    0x1004DDA5: "    ... << 12 ...",
    0x1004DDAA: "    ... / (in_frames+1), truncating. Both +1 are what keep the ramp",
    0x1004DDAC: "    off both endpoints: it starts at 4096/(N+1), never at 0",
    0x1004DDB1: "  the >= 4096 guard is unreachable while t < in_frames",
    0x1004DDB3: "g_101a5390 = the fade-in alpha",
    0x1004DDB8: "eax = fp[0x11C] = last frame of the whole timeline",
    0x1004DDC4: "u = end - frame. NOTE: *(fpip+0x118) is NOT subtracted here",
    0x1004DDC6: "u < out_frames ?",
    0x1004DDCA: "same ramp: ((u+1) << 12) / (out_frames+1)",
    0x1004DDD2: "keep the smaller of the two ramps ...",
    0x1004DDD8: "    ... so an object shorter than イン+アウト never reaches 4096",
    0x1004DDDF: "eax = the alpha that came out of all that",
    0x1004DDE4: ">= 4096 -> return 1 without touching a single pixel",
    0x1004DDEB: "> 0 -> run the worker",
    0x1004DDF2: "<= 0 -> return 0. exedit stops the effect chain for this object",
    0x1004DDF5: "    (verify_alpha_curve.py §4); nothing gets drawn",
    0x1004DDF6: "eax = fp->exfunc (+0x60, filter_registration.md §4)",
    0x1004DDF9: "param2 = fpip",
    0x1004DDFA: "param1 = fp (the worker ignores it)",
    0x1004DDFB: "worker 0x1004de20",
    0x1004DE00: "EXFUNC::exec_multi_thread_func(worker, fp, fpip)",
    0x1004DE0C: "return 1",

    # ------------------------------------------------------------- worker
    0x1004DE23: "esi = tid",
    0x1004DE28: "edi = param2 = fpip",
    0x1004DE2C: "tid + 1",
    0x1004DE2F: "ebx = thread_num",
    0x1004DE33: "ecx = fpip->h (+0xB8) - this worker splits by ROWS",
    0x1004DE3D: "y_end = h*(tid+1)/thread_num",
    0x1004DE47: "y_begin = h*tid/thread_num",
    0x1004DE4B: "guard (B) only - no `dim < thread_num` guard, so the row ranges",
    0x1004DE4D: "    telescope and every row is covered (thread_split.md §1)",
    0x1004DE53: "row loop head. ecx = fpip->line stride (+0xEC) [pixels]",
    0x1004DE59: "esi = *(fpip+0xAC), the object image. There is no pair buffer,",
    0x1004DE62: "    no swap, no scratch: フェード edits in place",
    0x1004DE65: "x = 0",
    0x1004DE6B: "+6 = the alpha field of the 8-byte PIXEL_YCA. The ONLY offset",
    0x1004DE6E: "    this effect ever touches: movsx = signed 16-bit read ...",
    0x1004DE71: "    ... x the Q12 alpha ...",
    0x1004DE78: "    ... sar 12 = floor, not truncate (integer_semantics.md §1).",
    0x1004DE7B: "    a' = floor(a * g / 4096) <= a: フェード can only reduce alpha",
    0x1004DE7E: "w is re-read from fpip every single pixel",
    0x1004DE85: "advance one 8-byte pixel",
    0x1004DE8D: "next row",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="disasm_params")
    parser.add_argument("--only", choices=("func_proc", "worker"),
                        help="dump just one of the two functions")
    args = parser.parse_args(argv or [])

    targets = {
        "func_proc 0x1004dd40": FUNC_PROC,
        "alpha worker 0x1004de20": WORKER,
    }
    if args.only == "func_proc":
        targets.pop("alpha worker 0x1004de20")
    elif args.only == "worker":
        targets.pop("func_proc 0x1004dd40")

    dump_all(PEImage(dll_path), targets, annotations=ANNOTATIONS, mnemonic_width=9)

    print("""
The whole effect, in the order the instructions run:

    R = *(fpip+0xFC)                      // frame rate numerator
    S = *(fpip+0x100)                     // frame rate denominator
    in  = trunc(イン   * R / (S * 100))    // _ftol, toward zero
    out = trunc(アウト * R / (S * 100))

    g = 4096
    t = *(fpip+0xA8) - fp[0x118] - *(fpip+0x118)
    if (t < in)   { a = ((t+1) << 12) / (in  + 1);  if (a < 4096) g = a; }
    u = fp[0x11C] - *(fpip+0xA8)
    if (u < out)  { a = ((u+1) << 12) / (out + 1);  if (g > a)    g = a; }

    if (g >= 4096) return 1;              // no-op
    if (g <= 0)    return 0;              // object dropped
    for every pixel: a = (a * g) >> 12    // alpha only, in place
    return 1;

Both `<< 12 / (n+1)` divides are `shl` + `cdq` + `idiv`, so they truncate
toward zero and go negative for negative `t`/`u` - which is exactly how a text
character that has not appeared yet ends up on the `return 0` exit.""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
