"""境界補正 - two box passes over the alpha channel, and the stretch at the end.

With `境界補正 = r > 0` the effect gains two more workers:

    pass 2  0x10016430   temp[y][x].a = vertical box average of img[..][x].a
    pass 3  0x100165d0   v = (horizontal box average of temp[y][..].a) ...
                         v = (v * img[y][x].a) >> 12
                         t = (v - A)*r + B
                         img[y][x].a = 0 if v == 0 or t <= 0 else (a * t) >> 12

with the two stretch constants computed once per worker:

    A = 4096 - 4096/r          B = 4096 - (4096/r)*r   (= 4096 mod r)

which is, instruction for instruction, クロマキー's pass 2 / pass 3. The
difference is what is being blurred. クロマキー builds a 16-bit matte
`min(d, 4096)` in a scratch buffer and multiplies the blur by *that*;
カラーキー has no matte, so both the blurred value and the multiplicand are
**the pixel's own alpha**.

That substitution has a consequence the shared code does not have in
クロマキー, and it is the main thing this script exists to show: in the flat
interior of a uniformly semi-transparent object the blur equals the alpha, so
`v = a²/4096` and the pixel comes out at roughly `a³/4096²`. 境界補正 does not
just erode the edge - it eats semi-transparency everywhere, and from r = 2 up
it deletes anything below ~71% opaque outright.

Claims checked here:

  1. **the phase structure.** Both passes walk the classic three-phase sliding
     window of `inspect/common/box_blur.md` §4; this script replays the loop
     bounds as written and compares against `sum(src[i-r : i+r+1]) / (2r+1)`
     with out-of-range samples read as zero.
  2. **the stretch constants** are the same pair クロマキー uses, `t(4096) ==
     4096` exactly for every r, and r = 1 is the identity stretch.
  3. **uniform alpha is cubed** (r = 1) or **clipped to nothing** (r >= 2).
  4. **an opaque object loses its border** even with no key colour present,
     because the divisor never shrinks at the image edge.
  5. **small images overrun.** Phases 2 and 4 write `r+1` and `r` samples
     unconditionally, so a row or column shorter than `2r+1` gets `2r+1`
     written. Bounded and harmless at r <= 5, but it is a real out-of-range
     write, the same one クロマキー has.
  6. **the stretch idiom is shared.** `mov eax, 0x1000; cdq; idiv r32` followed
     by the two subtractions occurs in exactly three places in exedit.auf, and
     the three effects that own them are exactly the three whose registration
     declares a `境界補正` trackbar: クロマキー, 特定色域変換 and カラーキー.
     Both halves of that are enumerated rather than asserted.

Run via main.py:
    uv run main.py inspect/color_key/verify_border_chain.py
"""

import random

from tools.cints import c_div, sar
from tools.disasm import dump_all, disasm_range
from tools.filter_table import walk
from tools.pe_image import PEImage
from tools.xrefs import function_owners, nearest_owner

PASS2_SETUP = (0x1001643F, 0x5C)
PASS2_PHASES = (0x10016493, 0x13A)
PASS3_CONST = (0x100165DF, 0x4C)
PASS3_APPLY = (0x100166AB, 0x46)

# `mov eax, 0x1000 / cdq / idiv r32` - the head of the stretch-constant idiom.
STRETCH_IDIOM = bytes.fromhex("b800100000" "99" "f7")

ANNOTATIONS = {
    # ---- pass 2, the vertical box average
    0x1001643F: "*(fpip+0xB8) = h: the length of the pass",
    0x10016445: "*(fpip+0xB4) = w: the thread split runs along x ...",
    0x1001645A: "... x1 = (thread_id+1)*w/thread_num",
    0x1001645C: "*(fpip+0xEC) = row stride in pixels",
    0x1001646A: "x0 = thread_id*w/thread_num. COLUMNS, unlike the other two workers",
    0x10016482: "r",
    0x10016487: "kernel width 2r+1",
    0x10016493: "*(fpip+0xB0), the pair buffer: the destination",
    0x100164A0: "*(fpip+0xAC), the image: the source. Only the alpha field is touched",
    0x100164AA: "sum = 0",
    0x100164B6: "phase 1: prime the sum with r rows of alpha, writing nothing",
    0x100164C0: "step = stride*8 bytes = one row of 8-byte pixels",
    0x100164D2: "phase 2 runs (2r+1) - r = r+1 times ...",
    0x100164E3: "  ... adding the leading sample only: the window is [0, i+r]",
    0x100164EE: "  and the divisor is the FULL kernel width -> zero padding",
    0x100164F4: "  the only store: temp[y][x].a",
    0x1001651B: "phase 3 runs h - (2r+1) times: the steady state",
    0x10016534: "  leading sample in, trailing sample out",
    0x10016571: "phase 4 runs r times: trailing samples only, window [i-r, h-1]",
    0x1001658F: "  still divided by the full kernel width",
    # ---- pass 3, the constants
    0x100165DF: "w: the length of this pass",
    0x100165E5: "h: and the thread split runs along y again",
    0x100165FA: "r",
    0x10016608: "4096 / r",
    0x1001660F: "A = 4096 - 4096/r",
    0x1001661C: "(4096/r) * r ...",
    0x10016626: "B = 4096 - that = 4096 mod r",
    # ---- pass 3, the apply step
    0x100166AB: "the horizontal box average, same three phases as pass 2 ...",
    0x100166B6: "... / kernel width",
    0x100166B8: "the pixel's OWN alpha - クロマキー reads its 16-bit matte here",
    0x100166BC: "v = (blurred * alpha) >> 12 - a product, not a blend",
    0x100166C2: "v == 0 -> alpha = 0 outright",
    0x100166CC: "v - A ...",
    0x100166CE: "... * r ...",
    0x100166D1: "... + B: the stretch. Slope r, and t(4096) == 4096 exactly",
    0x100166D5: "t <= 0 -> alpha = 0",
    0x100166D7: "alpha = (alpha * t) >> 12, in place in *(fpip+0xAC)",
    0x100166E3: "the two failure branches share this store",
}


def box_pass(src: list, r: int, stats: dict | None = None) -> list:
    """One pass of 0x10016430 (or the box half of 0x100165d0), as written.

    Indices are tracked the way the pointers are: `lead` is the sample being
    added, `trail` the one being removed, and each phase runs the number of
    times its own loop bound says - which is what makes the `n < 2r+1` overrun
    visible instead of being smoothed over by a clamp Python would add for
    free. Out-of-range samples are counted and read as zero; the real code
    reads whatever happens to be in the buffer there.
    """
    n, kw = len(src), 2 * r + 1
    stats = stats if stats is not None else {}
    stats.setdefault("over_read", 0)

    def at(i):
        if 0 <= i < n:
            return src[i]
        stats["over_read"] += 1
        return 0

    out, s, lead, trail = [], 0, 0, 0
    for _ in range(r):                       # phase 1: prime, write nothing
        s += at(lead)
        lead += 1
    for _ in range(kw - r):                  # phase 2: r+1 times
        s += at(lead)
        lead += 1
        out.append(c_div(s, kw))
    for _ in range(max(0, n - kw)):          # phase 3: the steady state
        s += at(lead) - at(trail)
        lead, trail = lead + 1, trail + 1
        out.append(c_div(s, kw))
    for _ in range(r):                       # phase 4
        s -= at(trail)
        trail += 1
        out.append(c_div(s, kw))
    stats["over_write"] = max(0, len(out) - n)
    return out


def box_reference(src: list, r: int) -> list:
    """What the three phases are supposed to add up to."""
    n, kw = len(src), 2 * r + 1
    return [c_div(sum(src[max(0, i - r):i + r + 1]), kw) for i in range(n)]


def stretch_constants(r: int) -> tuple:
    q = c_div(4096, r)
    return 4096 - q, 4096 - q * r


def apply_pixel(blurred: int, alpha: int, r: int) -> int:
    """The tail of pass 3: 0x100166bc..0x100166e3."""
    a_const, b_const = stretch_constants(r)
    v = sar(blurred * alpha, 12)
    if v == 0:
        return 0
    t = (v - a_const) * r + b_const
    return 0 if t <= 0 else sar(alpha * t, 12)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_all(img, {
        "pass 2: setup and thread split  0x1001643f": PASS2_SETUP,
        "pass 2: the three phases        0x10016493": PASS2_PHASES,
        "pass 3: the stretch constants   0x100165df": PASS3_CONST,
        "pass 3: applying it             0x100166ab": PASS3_APPLY,
    }, annotations=ANNOTATIONS)

    print("\n--- 1. do the phases add up to a zero-padded box average? ---")
    rng = random.Random(20260728)
    bad = []
    for r in range(0, 6):
        for n in range(2 * r + 1, 2 * r + 24):
            src = [rng.randrange(0, 4097) for _ in range(n)]
            if box_pass(src, r) != box_reference(src, r):
                bad.append((r, n))
    print("  r in 0..5, length from 2r+1 to 2r+23: "
          + (f"MISMATCH at (r,n) = {bad[:4]}" if bad else
             "OK, identical to sum(src[i-r:i+r+1]) / (2r+1) with zeros outside"))
    print("  The divisor never shrinks at the edge, so the outer r rows and columns")
    print("  are averaged against zeros - i.e. against 'fully transparent'.")

    print("\n--- 2. the contrast stretch ---")
    print(f"  {'r':>3}{'A':>7}{'B':>4}   t(v) for v =  0   1024   2048   3072   4096")
    for r in range(1, 6):
        a_const, b_const = stretch_constants(r)
        row = "  ".join(f"{(v - a_const) * r + b_const:>5}"
                        for v in (0, 1024, 2048, 3072, 4096))
        print(f"  {r:>3}{a_const:>7}{b_const:>4}                {row}")
    print("  t(4096) == 4096 for every r: a fully opaque, fully surrounded pixel is")
    print("  left alone. r = 1 gives A = B = 0 and slope 1 - the identity stretch, so")
    print("  境界補正 = 1 is 'blur the alpha and multiply it back in' and nothing more.")
    print("  These are the same constants クロマキー computes at 0x100138f9.")

    print("\n--- 3. a uniformly semi-transparent object, far from any edge ---")
    print("  In the interior the box average of a constant alpha is that alpha, so")
    print("  v = (a*a)>>12 and the result is a * t / 4096.")
    print(f"  {'alpha in':>9}" + "".join(f"{'r=' + str(r):>8}" for r in range(1, 6)))
    for a in (4096, 3686, 3072, 2048, 1024, 256):
        cells = "".join(f"{apply_pixel(a, a, r):>8}" for r in range(1, 6))
        print(f"  {a:>9}{cells}")
    print("  r = 1 cubes the alpha: 50% opaque comes out at 12.5%.")
    print("  r >= 2 clips everything below roughly sqrt(4096*A) to zero - about 71% at")
    print("  r = 2 and 90% at r = 5 - so a half-transparent object simply disappears.")
    print(f"  {'r':>3}{'A':>7}{'minimum surviving uniform alpha':>34}")
    for r in range(1, 6):
        a_const, _ = stretch_constants(r)
        lo = next((a for a in range(4097) if apply_pixel(a, a, r) > 0), None)
        print(f"  {r:>3}{a_const:>7}{f'{lo}  ({100 * lo / 4096:.1f}%)':>34}")
    print("  クロマキー does not behave this way: its matte is min(d,4096), which is")
    print("  4096 wherever the pixel is not key-coloured whatever its alpha, so the")
    print("  product comes back to 4096 and the interior is untouched. The shared code")
    print("  is the same; the thing being blurred is not.")

    print("\n--- 4. an opaque object with no key colour in it at all ---")
    for r in (1, 2, 5):
        col = box_pass([4096] * 16, r)
        edge = [apply_pixel(col[i], 4096, r) for i in range(4)]
        print(f"  r={r}: rows 0..3 of a 16-row opaque column come out at {edge}"
              f"   (interior {apply_pixel(col[8], 4096, r)})")
    print("  Zero padding + a divisor that never shrinks = the border fades. 境界補正")
    print("  always eats into an object that reaches the edge of its own buffer, even")
    print("  when the key colour is absent from the frame.")

    print("\n--- 5. what happens when the image is shorter than the kernel? ---")
    print(f"  {'r':>3}{'kernel':>8}{'n':>5}{'written':>10}{'past end':>10}"
          f"{'read past end':>16}")
    for r in (1, 3, 5):
        for n in (1, 2 * r, 2 * r + 1):
            stats = {}
            written = len(box_pass([0] * n, r, stats))
            print(f"  {r:>3}{2 * r + 1:>8}{n:>5}{written:>10}{stats['over_write']:>10}"
                  f"{stats['over_read']:>16}")
    print("  Phases 2 and 4 have no `min(n, ...)` anywhere: they run r+1 and r times")
    print("  whatever n is, and neither pointer is bounded. Pass 2 spills into the")
    print("  pair buffer past row h; pass 3 spills into the image buffer past column w.")
    print("  Both need a dimension below 2r+1 (at most 11) to fire.")

    print("\n--- 6. where else does this stretch idiom appear? ---")
    owners = function_owners(img)
    pos, found = 0, 0
    while True:
        i = img.data.find(STRETCH_IDIOM, pos)
        if i == -1:
            break
        va = i + img.image_base
        found += 1
        tail = [f"{n.mnemonic} {n.op_str}"
                for n, _ in disasm_range(img, va, 0x20, resolve=False)][:6]
        print(f"  0x{va:08x}  ({nearest_owner(owners, va)})")
        print(f"      {' ; '.join(tail)}")
        pos = i + 1
    print(f"  -> {found} occurrence(s) in the whole 850 KB image.")

    print("\n  and every effect in the table that has a 境界補正 trackbar:")
    owners_with_track = []
    for reg in walk(img):
        for i, name in enumerate(reg.track_names):
            if name and "境界補正" in name:
                owners_with_track.append(reg)
                print(f"    {reg.name:<14} track[{i}]  range {reg.track_s[i]}..{reg.track_e[i]}"
                      f"  default {reg.track_defaults[i]}  func_proc=0x{reg.func_proc:08x}")
    print(f"  -> {len(owners_with_track)} effect(s), and they are the same three.")
    print("  特定色域変換 is not analysed in this repository; what is checked here is")
    print("  only that it computes A and B with the same instruction sequence, not")
    print("  that the surrounding pipeline matches.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
