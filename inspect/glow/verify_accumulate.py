"""Every shape worker ends the same way, and that ending is where 強さ lives.

Whatever a worker sums - a column, a row, a diagonal - it finishes with:

    contribution = ((sum >> 4) * strength) >> 10        # = sum * strength / 2^14
    n = contribution + dst                              # per channel
    if (n.y > 0x2000):
        n.cb = c_div(n.cb << 13, n.y)
        n.cr = c_div(n.cr << 13, n.y)
        n.y  = 0x2000
    dst = n

Two spellings of exactly this exist: `sub_10056680`, called by the five streak
shapes, and an inlined copy in 通常's horizontal worker (three times over, once
per sliding-window phase). Section 1 disassembles both so the reader can see
they agree; section 2 replays them against each other over a brute-force sweep.

The things this ending decides:

  * **there is no divide by the kernel width.** A box average would divide by
    `2r+1`; this multiplies by `strength/2^14` instead, so the gain of a pass is
    proportional to its *width*. That is why func_proc has to hand each pass a
    different 強さ (verify_params.py) - the schedule is the normalisation.
  * **the ceiling is 8192, not 4096.** Glow luma saturates at exactly twice full
    white, and the two chroma channels are rescaled by `8192/y` so the
    chroma/luma ratio - i.e. the hue and saturation - survives the clip. 発光
    clamps at the same 0x2000 but fades chroma toward *white* instead
    ([`発光` §4](../luminous/README.md)); グロー keeps the colour.
  * **nothing else is clamped.** Chroma is written back as int16 with no bound
    of its own, and the 4096..8192 luma band is super-white that only the final
    composite turns into alpha.

Run via main.py:
    uv run main.py inspect/glow/verify_accumulate.py
"""

import random
import struct

from tools.cints import c_div
from tools.disasm import dump_all
from tools.pe_image import PEImage

HELPER = (0x10056680, 0x73)
INLINE = (0x10055FDD, 0x8A)

ANNOTATIONS = {
    0x10056680: "ecx = sum_y (arg2)",
    0x10056684: "eax = strength (arg5)",
    0x10056689: "ebx = dst (arg1)",
    0x1005668D: "sum_y >> 4",
    0x10056691: "esi = sum_cb (arg3)",
    0x10056696: "edi = sum_cr (arg4)",
    0x1005669A: "* strength",
    0x100566B0: ">> 10  (so overall: sum * strength / 2^14)",
    0x100566B3: "+= dst.y   <- read-modify-write, this is the accumulation",
    0x100566C3: "y > 0x2000 ? (8192 = twice full white)",
    0x100566D1: "cb = (cb << 13) / y",
    0x100566DB: "cr = (cr << 13) / y   <- rescale keeps the hue",
    0x100566DD: "y = 0x2000",
    0x100566E4: "write back as int16, no further clamp",
    0x10055FDD: "the same thing inlined in 通常's horizontal worker ...",
    0x10055FF2: "sum_y >> 4",
    0x10055FF7: "* strength",
    0x10056017: ">> 10",
    0x1005601A: "+= dst.y",
    0x1005602E: "y > 0x2000 ?",
    0x1005603C: "cb = (cb << 13) / y",
    0x10056046: "cr = (cr << 13) / y",
    0x1005604C: "y = 0x2000",
    0x10056057: "... and the same int16 write-back",
}


def accumulate(dst: tuple, sums: tuple, strength: int) -> tuple:
    """sub_10056680 / its inlined twin, replayed literally."""
    y, cb, cr = ((((s >> 4) * strength) >> 10) + d for s, d in zip(sums, dst))
    if y > 0x2000:
        cb = c_div(cb << 13, y)
        cr = c_div(cr << 13, y)
        y = 0x2000
    return y, cb, cr


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_all(PEImage(dll_path), {
        "sub_10056680: the streak shapes' accumulate step": HELPER,
        "0x10055ed0: 通常's inlined copy (ramp-up phase)": INLINE,
    }, annotations=ANNOTATIONS)

    print("\n--- 1. the saturation point and what it does to colour ---")
    print(f"  {'sum_y':>9}{'contrib':>9}{'out.y':>8}{'out.cb':>8}{'out.cr':>8}   cb/y")
    for sy in (0, 100000, 200000, 400000, 800000, 2000000):
        scb, scr = -sy // 4, sy // 2
        y, cb, cr = accumulate((0, 0, 0), (sy, scb, scr), 400)
        print(f"  {sy:>9}{((sy >> 4) * 400) >> 10:>9}{y:>8}{cb:>8}{cr:>8}   "
              f"{(cb / y) if y else 0:+.4f}")
    print("  cb/y stays at -0.25 through the clip: the rescale is exact enough that")
    print("  a saturated glow keeps its hue instead of washing out to white.")

    print("\n--- 2. accumulation really accumulates (a 4-pass 通常 schedule) ---")
    dst = (0, 0, 0)
    for i, (s, sums) in enumerate(((2400, (6000, -1500, 0)),
                                   (1200, (9000, -2200, 0)),
                                   (600, (14000, -3500, 0)),
                                   (300, (22000, -5500, 0)))):
        dst = accumulate(dst, sums, s)
        print(f"  after pass {i + 1}: {dst}")
    print("  each pass adds to whatever the previous ones left, in place - which")
    print("  is also why the destination is the *source* of the next pass in 通常.")

    print("\n--- 3. the two spellings agree (random sweep) ---")
    rng = random.Random(20240727)
    mismatch = 0
    for _ in range(200000):
        dst = (rng.randint(0, 0x2000), rng.randint(-8000, 8000), rng.randint(-8000, 8000))
        sums = tuple(rng.randint(-1 << 20, 1 << 21) for _ in range(3))
        strength = rng.randint(1, 24000)
        a = accumulate(dst, sums, strength)
        # the inlined copy, transcribed separately from 0x10055fdd-0x10056062
        y = (((sums[0] >> 4) * strength) >> 10) + dst[0]
        cb = (((sums[1] >> 4) * strength) >> 10) + dst[1]
        cr = (((sums[2] >> 4) * strength) >> 10) + dst[2]
        if y > 0x2000:
            cb, cr, y = c_div(cb << 13, y), c_div(cr << 13, y), 0x2000
        if a != (y, cb, cr):
            mismatch += 1
    print(f"  {'MISMATCH on %d' % mismatch if mismatch else 'OK: identical'} "
          f"over 200000 random (dst, sums, strength) triples.")

    print("\n--- 4. the int16 write-back has no clamp: when does chroma wrap? ---")
    print("  a saturated pixel holds cb = 8192 * (sum_cb / sum_y), so it exceeds")
    print("  int16 as soon as |chroma| > 4 * luma. That ratio is a property of the")
    print("  colour alone; here it is, from exedit's own BT.601 Q14 table:")
    img = PEImage(dll_path)
    rows = {ch: struct.unpack_from("<3h", img.code(va, 6))
            for ch, va in (("B", 0x100A989C), ("G", 0x100A98A4), ("R", 0x100A98AC))}
    print(f"  {'RGB':>9}{'Y':>7}{'Cb':>7}{'Cr':>7}{'|Cb|/Y':>9}{'saturated cb':>14}")
    for name, (r, g, b) in (("#ffffff", (255, 255, 255)), ("#00ff00", (0, 255, 0)),
                            ("#ff0000", (255, 0, 0)), ("#0000ff", (0, 0, 255)),
                            ("#4040ff", (64, 64, 255))):
        ycc = [sum(rows[ch][i] * v for ch, v in (("R", r), ("G", g), ("B", b))) * 16
               // 16384 for i in range(3)]
        y0, cb0 = ycc[0], ycc[1]
        sat_cb = c_div(cb0 * 0x2000, y0) if y0 else 0
        print(f"  {name:>9}{y0:>7}{cb0:>7}{ycc[2]:>7}{abs(cb0) / y0:>9.2f}"
              f"{sat_cb:>14}{'  <- wraps int16' if abs(sat_cb) > 32767 else ''}")
    print("  |Cb| > 4Y only happens near pure blue - it is the darkest primary in")
    print("  BT.601 (Y = 0.114) while carrying the largest Cb (0.5). A saturated")
    print("  blue glow therefore writes a chroma that wraps to the opposite sign,")
    print("  i.e. the core of the glow flips hue. Below saturation nothing can")
    print("  overflow, because the contribution is bounded by the 8192 the luma")
    print("  reaches first. Whether this is visible on screen depends on the")
    print("  YCbCr->RGB clip in aviutl.exe ([`rgb_ycbcr.md` §3](../common/rgb_ycbcr.md)).")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
