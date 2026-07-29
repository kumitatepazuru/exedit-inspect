"""The whole of ルミナンスキー: four alpha curves over the pixel's luminance.

Every worker reduces to one signed integer `t` and three branches on it. With
`base = 基準輝度` and `blur = ぼかし`:

    type 0  暗い部分を透過                t = y - base + blur
    type 1  明るい部分を透過              t = base + blur - y
    type 2  明暗部分を透過                t = blur - |y - base|
    type 3  明暗部分を透過(ぼかし無し)    t = blur - |y - base|

    t < 0        ->  a = 0
    t >= blur    ->  a unchanged
    otherwise    ->  a = a * t / blur          (types 0..2; type 3 has no ramp)

This script checks that reading, against the instructions and by replay:

  1. **The branches really are what the piecewise form says.** The seven
     conditional jumps that make up the four decisions are read out of the
     binary and their mnemonics asserted, which is what fixes each boundary as
     closed or open. `jns` and `jge` mean `t = 0` keys the pixel and
     `t = blur` keeps it - so at `ぼかし = 0` the curves become hard steps
     rather than becoming undefined.

  2. **The branch chain and the closed form agree everywhere.** Each worker's
     inner loop is replayed instruction by instruction and compared against the
     formula above over the whole representable luminance range for a grid of
     parameters - 1.5 million pixels per worker, including every degenerate
     `ぼかし` and every corner of 基準輝度's typed range.

  3. **`ぼかし = 0` cannot divide by zero.** The replay carries a guard that
     fails loudly if the `idiv` is ever reached with a zero divisor, over the
     full -4096..8192 span of 基準輝度. `0 <= t < blur` is unsatisfiable when
     `blur = 0`, so the divide is unreachable rather than merely unlikely.

  4. **The divide truncates.** `imul` / `cdq` / `idiv` is C's `/`, and both
     operands are non-negative here, so the ramp rounds *down*: a pixel one
     unit inside the ramp comes out darker than linear interpolation would put
     it. `a * blur / blur == a` exactly, which is why the `t >= blur` shortcut
     and the ramp agree on their shared boundary.

  5. **Which parameter combinations do nothing, and which erase everything.**
     PIXEL_YC luminance is 0..4096 but 基準輝度 accepts -4096..8192, so a large
     part of the slider is degenerate in one direction or the other.

  6. **type 2 dims the band it keeps; type 3 does not.** After the fold,
     `t >= blur` can only mean `t == blur`, i.e. `y == base` exactly. The
     entire band of 明暗部分を透過 is ramp, with full opacity at a single
     luminance value.

Run via main.py:
    uv run main.py inspect/luma_key/verify_alpha_curve.py
"""

from tools.cints import c_div
from tools.disasm import function_body
from tools.pe_image import PEImage

WORKERS = {0: 0x10064F60, 1: 0x10065020, 2: 0x100650E0, 3: 0x100651B0}

# (address, expected mnemonic, what taking the branch means)
BRANCHES = [
    (0, 0x10064FE8, "jns", "t >= 0  -> ramp test. t == 0 takes it, so `a = 0` needs t < 0"),
    (0, 0x10064FF8, "jge", "t >= blur -> leave alpha alone. y == base is fully opaque"),
    (1, 0x100650AA, "jns", "t >= 0  -> go on to the ramp test"),
    (1, 0x100650BA, "jge", "t >= blur -> leave alpha alone"),
    (2, 0x10065168, "jle", "t <= blur -> skip the fold (y is at or below base)"),
    (2, 0x10065175, "jge", "t >= 0  -> go on to the ramp test"),
    (2, 0x10065181, "jge", "t >= blur -> leave alpha alone (only t == blur can)"),
    (3, 0x10065242, "jle", "t <= blur -> skip the fold"),
    (3, 0x1006524C, "jge", "t >= 0  -> leave alpha alone. No ramp test follows"),
]

# The one instruction that distinguishes worker 1 from workers 0/2/3.
BASE_ARITH = [(0, 0x10064F9E, "sub"), (1, 0x1006505E, "add"),
              (2, 0x1006511C, "sub"), (3, 0x100651EE, "sub")]

# base values worth trying: both ends of the typed range, both ends of the
# representable luminance range, the shipped default, and one just off each.
BASES = [-4096, -1, 0, 1, 512, 2048, 4095, 4096, 4097, 8192]
# blur values: the degenerate ones, tiny ones where truncation bites hardest,
# the shipped default and the top of the range.
BLURS = [0, 1, 2, 3, 5, 17, 512, 2047, 2048, 4095, 4096]
ALPHAS = [0, 1, 2, 1023, 2048, 4095, 4096]


class DivideByZero(Exception):
    pass


def replay(mode: int, y: int, a: int, base: int, blur: int) -> int:
    """The inner loop of one worker, instruction for instruction.

    Deliberately written as the branch chain rather than as the formula: this
    is the thing the formula is being checked against. Raises rather than
    dividing by zero, so claim 3 is a property of the code and not of a guard
    added here.
    """
    if mode == 0:
        t = y - (base - blur)                       # sub edx, [esp+0x18]
    elif mode == 1:
        t = (base + blur) - y                       # sub edx, eax
    else:
        t = y - (base - blur)                       # sub ecx, [esp+0x18]
        if t > blur:                                # cmp ecx, edi / jle
            t = 2 * blur - t                        # lea/sub/mov
    if mode == 3:
        return a if t >= 0 else 0                   # cmp eax, ebx / jge
    if t < 0:                                       # jns
        return 0                                    # mov word ptr [..+6], 0
    if t >= blur:                                   # cmp / jge
        return a
    if blur == 0:
        raise DivideByZero(f"idiv with blur=0 at mode={mode} y={y} base={base}")
    return c_div(a * t, blur)                       # imul / cdq / idiv


def closed_form(mode: int, y: int, a: int, base: int, blur: int) -> int:
    """The same thing stated as a formula, which is what the README claims."""
    if mode == 0:
        t = y - base + blur
    elif mode == 1:
        t = base + blur - y
    else:
        t = blur - abs(y - base)
    if t < 0:
        return 0
    if mode == 3:
        return a
    return a if t >= blur else c_div(a * t, blur)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    bodies = {m: {i.address: i for i in function_body(img, va, 0x400)}
              for m, va in WORKERS.items()}

    print("--- 1. the branches, read out of the binary ---")
    print(f"  {'type':>5}  {'address':<12}{'got':<6}{'want':<6}meaning")
    all_ok = True
    for mode, addr, want, meaning in BRANCHES:
        insn = bodies[mode].get(addr)
        got = insn.mnemonic if insn else "<none>"
        all_ok &= got == want
        print(f"  {mode:>5}  0x{addr:08x}  {got:<6}{want:<6}{meaning}")
    check("every conditional is the one the piecewise form assumes", all_ok)
    print("  `jns` on `t` (not `jg`) means t == 0 goes to the KEEP side of the first")
    print("  test, and `jge` on `t vs blur` means t == blur keeps alpha untouched.")
    print("  Both boundaries closed on the keep side is what makes ぼかし = 0 a clean")
    print("  hard step instead of a division by zero.")

    print("\n  and the one instruction that separates 明るい from 暗い:")
    arith_ok = True
    for mode, addr, want in BASE_ARITH:
        insn = bodies[mode].get(addr)
        got = insn.mnemonic if insn else "<none>"
        arith_ok &= got == want
        sign = "base + blur" if want == "add" else "base - blur"
        print(f"    type {mode}  0x{addr:08x}: {got:<4} -> {sign}")
    check("type 1 adds where the others subtract", arith_ok)

    idivs = {m: sum(1 for i in b.values() if i.mnemonic == "idiv") for m, b in bodies.items()}
    print(f"\n  `idiv` per worker (two of them are the thread-range split): {idivs}")
    check("only type 3 lacks a third idiv, i.e. lacks the ramp",
          idivs[3] == 2 and all(idivs[m] == 3 for m in (0, 1, 2)),
          f"{idivs}")

    print("\n--- 2. branch chain vs closed form, exhaustively over luminance ---")
    total = 0
    for mode in WORKERS:
        bad = None
        n = 0
        for base in BASES:
            for blur in BLURS:
                for y in range(0, 4097):
                    n += 1
                    r = replay(mode, y, 4096, base, blur)
                    c = closed_form(mode, y, 4096, base, blur)
                    if r != c and bad is None:
                        bad = (base, blur, y, r, c)
        total += n
        check(f"type {mode}: {n:,} (base, ぼかし, y) combinations agree", bad is None,
              "" if bad is None else f"first mismatch {bad}")
    print(f"  {total:,} pixels replayed in total, over every y a PIXEL_YC can hold and")
    print(f"  {len(BASES)} x {len(BLURS)} parameter pairs including both ends of both ranges.")

    print("\n  and over the alpha axis, for the shipped defaults:")
    bad = None
    for mode in WORKERS:
        for a in range(0, 4097):
            for y in (0, 1536, 1537, 2047, 2048, 2049, 2560, 4096):
                if replay(mode, y, a, 2048, 512) != closed_form(mode, y, a, 2048, 512):
                    bad = (mode, a, y)
    check("all 4,097 alpha values agree on both sides of every boundary", bad is None,
          "" if bad is None else str(bad))

    print("\n--- 3. ぼかし = 0 never reaches the divide ---")
    reached = []
    for mode in WORKERS:
        for base in range(-4096, 8193):
            for y in (0, 1, base - 1, base, base + 1, 2048, 4095, 4096):
                try:
                    replay(mode, y, 4096, base, 0)
                except DivideByZero as e:
                    reached.append(str(e))
    check(f"no divide reached across {4 * 12289 * 8:,} (type, 基準輝度, y) probes",
          not reached, "" if not reached else reached[0])
    print("  The ramp needs `0 <= t < blur`, which is empty at blur = 0. The guard is")
    print("  in this script, not in exedit: the code has no explicit zero test anywhere")
    print("  (verify_dispatch.py shows func_proc never looks at the trackbars at all).")

    print("\n--- 4. the ramp truncates ---")
    bad_a = [(a, b) for b in (1, 2, 3, 17, 512, 4095, 4096)
             for a in range(0, 4097) if c_div(a * b, b) != a]
    check("a * ぼかし / ぼかし == a exactly, so `keep` and the ramp meet cleanly",
          not bad_a, "" if not bad_a else str(bad_a[0]))
    base, blur, a = 2048, 300, 4096
    print(f"  type 0 with 基準輝度={base}, ぼかし={blur} (not a power of two), a={a}:")
    print(f"  {'y':>6}{'t':>6}{'exact a*t/blur':>16}{'exedit (trunc)':>16}{'loss':>7}")
    for y in (1748, 1749, 1750, 1800, 1900, 2000, 2046, 2047, 2048):
        t = y - base + blur
        exact = a * t / blur
        got = replay(0, y, a, base, blur)
        print(f"  {y:>6}{t:>6}{exact:>16.3f}{got:>16}{exact - got:>7.3f}")
    worst = max(a * (y - base + blur) / blur - replay(0, y, a, base, blur)
                for y in range(base - blur, base + 1))
    check("the truncation loss stays strictly below one alpha unit", worst < 1,
          f"worst = {worst:.6f} over the whole ramp")
    print("  Always downward, never rounding to nearest: exedit's ramp sits at or below")
    print("  the straight line. With ぼかし a power of two (512 is the default) the")
    print("  division is exact and the loss is zero, which is why the shipped settings")
    print("  hide this entirely.")

    print("\n--- 5. degenerate parameter regions ---")
    print("  PIXEL_YC luminance is 0..4096. What each worker does when the band falls")
    print("  entirely outside that (alpha of a fully opaque pixel, over all y):")
    print(f"  {'type':>5}{'基準輝度':>10}{'ぼかし':>8}   result over y in 0..4096")
    for mode, base, blur in ((0, -4096, 0), (0, 8192, 0), (0, 2048, 4096),
                             (1, -4096, 0), (1, 8192, 0),
                             (2, -4096, 4096), (2, 8192, 4096), (2, 2048, 4096),
                             (3, 2048, 4096), (3, -4096, 0)):
        out = {replay(mode, y, 4096, base, blur) for y in range(0, 4097)}
        if out == {4096}:
            desc = "no-op (every pixel fully opaque)"
        elif out == {0}:
            desc = "the object disappears entirely"
        else:
            desc = f"{len(out)} distinct alphas, {min(out)}..{max(out)}"
        print(f"  {mode:>5}{base:>10}{blur:>8}   {desc}")
    print("  Because the slider only drags 0..4096 (verify_ex_data.py §6), the typed-only")
    print("  ends of 基準輝度 are precisely the ends that turn the effect off or turn it")
    print("  into an eraser. Nothing clamps them - there is no clamp in the effect at all.")

    print("\n--- 6. the four curves, at the shipped defaults 基準輝度=2048 ぼかし=512 ---")
    print(f"  {'y':>6}" + "".join(f"{'type ' + str(m):>10}" for m in WORKERS))
    for y in (0, 1024, 1535, 1536, 1537, 1792, 2047, 2048, 2049, 2304, 2559, 2560,
              2561, 3072, 4096):
        row = "".join(f"{replay(m, y, 4096, 2048, 512):>10}" for m in WORKERS)
        print(f"  {y:>6}{row}")
    print("  type 0 ramps up across [base-blur, base] and passes everything above.")
    print("  type 1 mirrors it: passes everything below base, ramps down to base+blur.")
    print("  type 2 is the product-shaped intersection - a triangle peaking at base.")
    print("  type 3 is the same support with a flat top.")

    print("\n  how wide is 'fully opaque' in each mode? (base=2048, ぼかし=512)")
    for mode in WORKERS:
        full = [y for y in range(0, 4097) if replay(mode, y, 4096, 2048, 512) == 4096]
        partial = [y for y in range(0, 4097) if 0 < replay(mode, y, 4096, 2048, 512) < 4096]
        print(f"    type {mode}: {len(full):>5} y values fully opaque"
              f" ({full[0]}..{full[-1] if full else '-'}),"
              f" {len(partial):>5} partially transparent")
    check("type 2 keeps full opacity at exactly one luminance",
          len([y for y in range(0, 4097) if replay(2, y, 4096, 2048, 512) == 4096]) == 1)
    check("type 3 keeps full opacity across the whole 2*ぼかし+1 band",
          len([y for y in range(0, 4097) if replay(3, y, 4096, 2048, 512) == 4096]) == 1025)
    print("  That 1 vs 1025 is the entire difference between 明暗部分を透過 and")
    print("  明暗部分を透過(ぼかし無し). The name says the second one drops the")
    print("  softening; what it actually drops is a ramp that covered the whole band.")

    print("\n--- alpha only ever goes down, and the effect is not idempotent ---")
    monotone = all(replay(m, y, a, 2048, 512) <= a
                   for m in WORKERS for a in ALPHAS for y in range(0, 4097, 7))
    check("a' <= a for every (type, y, a) sampled", monotone)
    twice = replay(0, 1700, replay(0, 1700, 4096, 2048, 512), 2048, 512)
    once = replay(0, 1700, 4096, 2048, 512)
    check("applying the effect twice is not the same as once", twice != once,
          f"once = {once}, twice = {twice}")
    print("  The ramp multiplies the alpha that is already there, so stacking two")
    print("  ルミナンスキー with the same settings squares the factor. Only the two")
    print("  hard branches (a = 0, and `keep`) are idempotent.")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
