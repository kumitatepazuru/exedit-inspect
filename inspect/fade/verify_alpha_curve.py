"""The ramp itself: what alpha フェード produces, and its three exits.

    g = 4096
    if (t < in)  { a = ((t+1) << 12) / (in  + 1);  if (a < 4096) g = a; }
    if (u < out) { a = ((u+1) << 12) / (out + 1);  if (g > a)    g = a; }

Five claims.

(1) The ramp never touches either endpoint. `+1` on both the numerator and the
    divisor means the first faded frame is `4096/(N+1)`, not 0, and the last
    one is `N*4096/(N+1)`, not 4096 - the full-opacity value is only reached by
    *leaving* the branch. So a fade-in of N frames occupies N frames and none
    of them is invisible.

(2) The `if (a < 4096)` guard on the fade-in arm is dead code. Inside the
    branch `t <= in - 1`, so `(t+1)*4096 <= in*4096 < (in+1)*4096` and the
    quotient is always below 4096. Brute-forced over the whole reachable
    parameter space rather than argued.

(3) The two arms compose as a minimum, so an object shorter than `イン+アウト`
    never becomes fully opaque - and both ramps are computed from the *whole*
    object timeline, so the peak is a property of the object's length, not of
    where the playhead is.

(4) The three exits. `>= 4096` returns 1 without dispatching anything; `<= 0`
    returns **0**, which is rare - 20 of the 81 distinct `func_proc` in the
    table can do it at all. At the dispatch sites `0x1004993e` and `0x10049fab`
    exedit compares the result against 1 and breaks out of the per-object
    effect loop when it differs; the first of the two then returns from the
    whole routine.

    But `<= 0` needs `t <= -1` or `u <= -1`, and for an ordinary object
    `t = frame - chain_start` and `u = chain_end - frame` are both >= 0 on
    every frame exedit draws it (verify_timeline.py §1: the chain spans every
    segment, and the 時間制御 remap clamps into the segment). So **the drop
    exit is unreachable without `*(fpip+0x118)`** - it exists for テキスト
    characters whose 表示速度 delay has not elapsed. That is checked by brute
    force below, not by inspection. Making `イン` longer than the object does
    *not* drop it; it only caps how bright it ever gets.

(5) `sar 12` in the worker, not `idiv 4096`: the alpha multiply floors. For the
    non-negative values that reach it the two agree, which is checked here
    rather than assumed.

Run via main.py:
    uv run main.py inspect/fade/verify_alpha_curve.py
"""

from tools.cints import c_div, sar
from tools.disasm import function_body
from tools.filter_table import walk
from tools.pe_image import PEImage

FULL = 4096


def ramp(k: int, n: int) -> int:
    """0x1004dda4-0x1004ddaa / 0x1004ddca-0x1004ddd0: ((k+1) << 12) / (n+1)."""
    return c_div((k + 1) << 12, n + 1)


def alpha(frame: int, start: int, end: int, in_f: int, out_f: int, delay: int = 0) -> int:
    """func_proc 0x1004dd4b-0x1004dddf, verbatim."""
    g = FULL
    t = frame - start - delay
    if t < in_f:
        a = ramp(t, in_f)
        if a < FULL:
            g = a
    u = end - frame
    if u < out_f:
        a = ramp(u, out_f)
        if g > a:
            g = a
    return g


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("--- (1) the ramp never reaches 0 or 4096 ---")
    print("    N    frame 0      frame 1    ...    frame N-1     frame N")
    for n in (1, 2, 5, 15, 30, 300):
        head = ", ".join(str(ramp(k, n)) for k in range(min(2, n)))
        print(f"  {n:4d}    {head:<22s}        {ramp(n - 1, n):8d}  {FULL:8d} (branch not taken)")
    print("  first faded frame  = 4096/(N+1) > 0     -> never fully transparent")
    print("  last faded frame   = N*4096/(N+1) < 4096 -> the ramp ends one step short,")
    print("                                              and 4096 comes from the else arm")
    print("  N = 0 (イン below one frame) skips the branch on every frame: no fade.")

    print("\n--- (2) the `a < 4096` guard on the fade-in arm ---")
    worst = 0
    for n in range(0, 601):          # 0..600 frames = 0..10 s at 60 fps
        for t in range(-4096, n):
            worst = max(worst, ramp(t, n))
    print(f"  max over every (in_frames 0..600, t -4096..in_frames-1): {worst}")
    print(f"  4096 is never reached, so `jge 0x1004ddb8` at 0x1004ddb1 never fires.")
    print("  (the fade-out arm has no such guard - it uses `if (g > a)` instead,")
    print("   which is a genuine minimum and does fire.)")

    print("\n--- (3) two ramps at once ---")
    print("  object of 30 frames (frames 0..29), 30 fps")
    for in_s, out_s in ((0.5, 0.5), (1.0, 0.0), (0.6, 0.6), (2.0, 2.0)):
        in_f, out_f = int(in_s * 30), int(out_s * 30)
        vals = [alpha(f, 0, 29, in_f, out_f) for f in range(30)]
        peak = max(vals)
        print(f"    イン={in_s:.2f}s ({in_f:2d}f) アウト={out_s:.2f}s ({out_f:2d}f)  "
              f"peak={peak:4d} ({peak / FULL * 100:5.1f}%)  "
              f"zero-alpha frames={sum(1 for v in vals if v <= 0)}")
        print(f"      {vals}")
    print("  With イン+アウト >= the object length the object never reaches 100%.")
    print("  Note the peak is the same on every frame of an object: both ramps read")
    print("  the object's whole timeline, so it is a property of its length.")

    print("\n--- (4) the three exits ---")

    def which(g):
        return ("return 1 (no-op)" if g >= FULL
                else "return 0 (DROPPED)" if g <= 0 else "worker")

    print("  object of 30 frames, イン=2.00s (60f) at 30 fps - longer than the object")
    for f in (0, 5, 20, 29):
        print(f"    frame {f:2d}: alpha={alpha(f, 0, 29, 60, 0):5d}  -> {which(alpha(f, 0, 29, 60, 0))}")
    print("    -> still never dropped: t stays >= 0, so the ramp stays > 0")

    print("\n  exhaustive: is `return 0` reachable at all with delay = 0?")
    hits = 0
    for length in range(1, 61):
        for in_f in range(0, 601):
            for f in (0, length - 1):
                if alpha(f, 0, length - 1, in_f, in_f) <= 0:
                    hits += 1
    print(f"    lengths 1..60 x イン=アウト 0..600 frames, at both ends: {hits} drop(s)")
    print("    (both ramps are monotone in the frame index, so the two ends bound them)")

    print("\n  テキスト's per-character delay, 30-frame object, イン=0.50s (15f), delay 40f:")
    for f in (0, 20, 29):
        g = alpha(f, 0, 29, 15, 0, delay=40)
        print(f"    frame {f:2d}: t={f - 40:4d} alpha={g:7d}  -> {which(g)}")
    print("    t < 0 makes (t+1)<<12 negative and idiv truncates toward zero, so the")
    print("    character is dropped for its whole delay - which is what makes the")
    print("    `return 0` exit exist in the first place.")

    print("\n  how unusual `return 0` is, across the whole effect table:")
    seen, zeroed = {}, []
    for r in walk(img):
        if not r.func_proc or r.func_proc in seen:
            continue
        body = function_body(img, r.func_proc, 0x2000)
        found = False
        for i, insn in enumerate(body):
            if insn.mnemonic == "xor" and insn.op_str == "eax, eax":
                for j in range(i + 1, min(i + 8, len(body))):
                    if body[j].mnemonic == "ret":
                        found = True
                        break
                    if body[j].mnemonic not in ("pop", "add", "mov", "nop", "leave"):
                        break
        seen[r.func_proc] = found
        if found:
            zeroed.append(r.name)
    print(f"    {sum(seen.values())} of {len(seen)} distinct func_proc have an `xor eax,eax; ret`")
    print(f"    including: {', '.join(zeroed)}")
    print("    (a linear scan for `xor eax,eax` followed by `ret` past the register")
    print("     restores; a func_proc that zeroes eax some other way would be missed)")

    print("\n--- (5) sar vs idiv in the worker ---")
    bad = 0
    for a in range(0, FULL + 1):
        for g in range(1, FULL):
            if g % 337:            # sample the grid; the full product is 16M pairs
                continue
            if sar(a * g, 12) != c_div(a * g, FULL):
                bad += 1
    print(f"  sar(a*g, 12) vs trunc(a*g/4096) over a=0..4096, g in a sample of 1..4095:"
          f" {bad} mismatch(es)")
    print("  They agree because both operands are non-negative here: `a` is a PIXEL_YCA")
    print("  alpha and `g` is > 0 on the only path that reaches the worker. `movsx`")
    print("  would read a negative alpha as negative, and there `sar` would floor")
    print("  while `idiv` truncates - but nothing in exedit writes one.")

    print("\n--- reference table: alpha over a 0.50 s fade ---")
    print("    fps      in_frames   frame 0   frame 1   ...   last faded   then")
    for label, rate, scale in (("30 fps", 30, 1), ("29.97 fps", 30000, 1001),
                               ("60 fps", 60, 1), ("24 fps", 24, 1)):
        n = int(50 * rate / (scale * 100.0))
        print(f"    {label:<10s} {n:6d}     {ramp(0, n):7d}   {ramp(1, n):7d}         "
              f"{ramp(n - 1, n):7d}   4096")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
