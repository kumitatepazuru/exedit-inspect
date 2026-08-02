"""What func_proc does with the four trackbars, checked against the
disassembly rather than paraphrased from it.

Five claims:

  1. **`濃さ` is the only trackbar that gets converted.** It goes through the
     shared magic-number divide (`0x10624dd3`, param_scaling.md §2) to
     `density = trunc(濃さ_raw * 4096 / 1000)`; `X`, `Y` and `拡散` are used
     as raw pixel counts. Checked over every raw value each trackbar can take.

  2. **`濃さ == 0` is an early-out**, and it is the *only* one - `拡散 = 0`,
     `X = Y = 0` all still run the whole pipeline (with kernel widths of 1,
     i.e. an identity blur).

  3. **`X` and `Y` are clamped so that `w+|X|` fits the allocated row stride
     and `h+|Y|` fits the allocated row count**, and the clamp is written so
     that the *sign* survives: an offset that was pointing left still points
     left afterwards, it just gets shorter.

  4. **`拡散` is then clamped against whatever margin is LEFT OVER**, so the
     final canvas `(w+|X|+2r, h+|Y|+2r)` always fits the allocated buffer.
     Two consequences fall out of the order: a large `X` eats the budget the
     blur would have used, and `r` is never compared against `w` or `h`.

  5. **`r` is never clamped against the object's own size.** ライト and 発光
     both start with a `trunc(dimension/2) - 2` style clamp; シャドー has no
     equivalent, so an object thinner than the kernel drives the sliding
     window's middle phase to a negative count. This script works out exactly
     when that happens and what it costs (box_blur.md §4 catalogues the same
     failure for クロマキー / カラーキー / 境界ぼかし).

Also checked here: the `- r` that the negative-X branch subtracts before
clamping the result to 0 (0x10088145) can never survive, so `g_X` is exactly
`max(X, 0)` - a claim about unreachable code, so it is proved by exhausting
the reachable inputs rather than by reading the branch.

Run via main.py:
    uv run main.py inspect/shadow/verify_params.py
"""

from tools.cints import c_div, divisor_of, msvc_div

FULL = 4096

DENSITY_RAW = (0, 1000)      # 濃さ: raw range, display scale 10 -> 0.0..100.0
OFFSET_RAW = (-1000, 1000)   # X / Y: raw range, display scale 1 -> pixels
SPREAD_RAW = (0, 500)        # 拡散: raw range, display scale 1 -> pixels


def density(raw: int) -> int:
    """0x10087ffe-0x10088015: trunc(raw * 4096 / 1000), the Q12 opacity."""
    return msvc_div(raw << 12)


def clamp_offset(offset: int, dim: int, budget: int) -> int:
    """0x10088059-0x100880b5, one axis.

    `budget` is the allocated stride (fpip+0xEC) or row count (fpip+0xF0).
    The two branches differ only in which way round the subtraction goes; both
    land on `sign(offset) * (budget - dim)`.
    """
    grown = dim + abs(offset)
    if grown <= budget:
        return offset
    return offset + (budget - grown if offset > 0 else grown - budget)


def geometry(w, h, x, y, spread, separate=False, stride=None, rows=None):
    """func_proc 0x10087fdc-0x100881a8 in full.

    The real (stride, rows) are however much exedit pre-allocated for this
    object's buffer; this analysis did not pin that down, so they are
    parameters with generous defaults - the same stand-in
    inspect/light/simulate_light_reference.py uses.
    """
    stride = stride if stride is not None else w + 512
    rows = rows if rows is not None else h + 512

    if separate:                       # 0x1008802e-0x1008803c
        x = y = 0

    x = clamp_offset(x, w, stride)
    y = clamp_offset(y, h, rows)
    grown_w, grown_h = w + abs(x), h + abs(y)

    r = spread                         # 0x100880b9-0x100880e9: margin clamp only
    if 2 * r > stride - grown_w:
        r = c_div(stride - grown_w, 2)
    if 2 * r > rows - grown_h:
        r = c_div(rows - grown_h, 2)

    r1 = c_div(r, 2)                   # 0x1008836c-0x10088387
    r2 = r - r1
    return {
        "w": w, "h": h, "x": x, "y": y, "r": r,
        "kernel_a": 2 * r1 + 1, "kernel_b": 2 * r2 + 1,
        "canvas_w": grown_w + 2 * r, "canvas_h": grown_h + 2 * r,
        # 0x1008812f-0x1008819b
        "shadow_x": max(x, 0), "shadow_y": max(y, 0),
        "object_x": max(-x, 0) + r, "object_y": max(-y, 0) + r,
        # 0x10088103-0x10088129, in 1/4096-pixel units
        "centre_dx": -x * 2048, "centre_dy": -y * 2048,
        "stride": stride, "rows": rows,
    }


def pass_emit_count(n: int, kernel: int) -> int:
    """Outputs one sliding-window pass writes: head `kernel`, middle
    `n - kernel` (skipped when negative), tail `kernel - 1`."""
    return kernel + max(0, n - kernel) + (kernel - 1)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. 濃さ is the only converted trackbar ---")
    d = divisor_of(0x10624DD3, 6)
    check(f"magic 0x10624dd3 with shift 6 really divides by {d}", d == 1000)
    bad = [raw for raw in range(DENSITY_RAW[0], DENSITY_RAW[1] + 1)
           if density(raw) != raw * FULL // 1000]
    check(f"all {DENSITY_RAW[1] - DENSITY_RAW[0] + 1} 濃さ raw values match "
          "trunc(raw*4096/1000)", not bad, f"first mismatch {bad[:1]}")
    print(f"  {'濃さ raw':>10}{'shown':>9}{'density':>9}")
    for raw in (0, 1, 400, 500, 819, 1000):
        print(f"  {raw:>10}{raw / 10:>8.1f}{density(raw):>9}")
    check("濃さ = 100.0% is exactly Q12 1.0", density(1000) == FULL, f"got {density(1000)}")
    check("the default 濃さ = 40.0% is 1638/4096 = 39.99%", density(400) == 1638,
          f"got {density(400)}")
    print("  X, Y and 拡散 never touch this: there is exactly one 0x10624dd3 in the whole")
    print("  effect (disasm_params.py), and it is the one above.")

    print("\n--- 2. 濃さ == 0 is the only early-out ---")
    print("  0x10087fc4 tests track[2] and nothing else. 拡散 = 0 gives kernel widths of 1,")
    print("  which is an identity box average, so the pipeline still runs end to end:")
    g = geometry(100, 60, 0, 0, 0)
    check("拡散 = 0, X = Y = 0: both kernels are 1 and the canvas is unchanged",
          g["kernel_a"] == 1 and g["kernel_b"] == 1
          and (g["canvas_w"], g["canvas_h"]) == (100, 60),
          f"kernels {g['kernel_a']}/{g['kernel_b']}, canvas {g['canvas_w']}x{g['canvas_h']}")
    print("  So 濃さ = 0 is the only way to make シャドー cost nothing; 拡散 = 0 with the")
    print("  default X/Y still allocates, blurs (trivially) and composites.")

    print("\n--- 3. the X / Y clamp keeps the sign and fills the buffer exactly ---")
    bad = []
    for stride in (60, 100, 301):
        for w in (1, 17, 60, 99):
            if w > stride:
                continue
            for x in range(OFFSET_RAW[0], OFFSET_RAW[1] + 1):
                cx = clamp_offset(x, w, stride)
                if w + abs(cx) > stride:
                    bad.append(("overflows", stride, w, x, cx))
                elif cx and (cx > 0) != (x > 0):
                    bad.append(("sign flipped", stride, w, x, cx))
                elif abs(cx) > abs(x):
                    bad.append(("grew", stride, w, x, cx))
    check("12 (stride, w) pairs x all 2001 offsets: never overflows, never flips sign, "
          "never grows", not bad, f"{len(bad)} bad, first {bad[:1]}")
    print(f"  {'stride':>7}{'w':>5}{'X raw':>7}{'X used':>8}{'w+|X|':>7}")
    for x in (-1000, -80, -40, 0, 24, 300, 1000):
        cx = clamp_offset(x, 60, 100)
        print(f"  {100:>7}{60:>5}{x:>7}{cx:>8}{60 + abs(cx):>7}")
    check("a huge negative X saturates at -(stride-w) and stays negative",
          clamp_offset(-1000, 60, 100) == -40)

    print("\n--- 4. 拡散 is clamped against what is LEFT, so the canvas always fits ---")
    bad = []
    for w, h, stride, rows in ((100, 60, 140, 90), (10, 10, 512, 512), (300, 200, 301, 201)):
        for x in (-1000, -40, 0, 24, 1000):
            for y in (-1000, -24, 0, 40, 1000):
                for spread in range(SPREAD_RAW[0], SPREAD_RAW[1] + 1, 7):
                    g = geometry(w, h, x, y, spread, stride=stride, rows=rows)
                    if g["canvas_w"] > stride or g["canvas_h"] > rows or g["r"] < 0:
                        bad.append((w, h, x, y, spread, g))
    check("3 buffer shapes x 25 offset pairs x 72 拡散 values: the grown canvas never "
          "exceeds the allocated buffer and r never goes negative", not bad,
          f"{len(bad)} bad, first {bad[:1]}")

    print("\n  the ordering costs the blur whatever the offset already spent:")
    print(f"  {'X':>6}{'拡散':>7}{'X used':>9}{'r used':>9}{'canvas w':>10}")
    for x in (0, -20, -40, -60, -100):
        g = geometry(100, 60, x, 0, 50, stride=200, rows=200)
        print(f"  {x:>6}{50:>7}{g['x']:>9}{g['r']:>9}{g['canvas_w']:>10}")
    check("with stride=200 and w=100, 拡散=50 already fills the row: r stays 50 at X=0",
          geometry(100, 60, 0, 0, 50, stride=200, rows=200)["r"] == 50)
    check("... and X=-100 eats the whole margin, collapsing r to 0",
          geometry(100, 60, -100, 0, 50, stride=200, rows=200)["r"] == 0,
          f"got {geometry(100, 60, -100, 0, 50, stride=200, rows=200)['r']}")
    print("  The canvas width is pinned at the stride in every one of those rows: the two")
    print("  consumers of the margin - the offset and the blur - share one budget, and the")
    print("  offset is served first.")

    print("\n--- 4b. g_X = max(X, 0): the `- r` on the negative branch is dead ---")
    bad = []
    for x in range(OFFSET_RAW[0], 1):
        for r in range(0, SPREAD_RAW[1] + 1, 3):
            # 0x10088145-0x10088151: g_X = (X-r >= 0) ? X-r : 0
            emulated = x - r if x - r >= 0 else 0
            if emulated != max(x, 0):
                bad.append((x, r, emulated))
    check("all X <= 0 x 168 radii: the branch always lands on 0, i.e. g_X == max(X,0)",
          not bad, f"first {bad[:1]}")
    print("  r is non-negative by construction (§4: it is either 拡散 >= 0 or half a")
    print("  non-negative margin), and X is non-positive on that branch, so X-r < 0 always.")
    print("  The subtraction is real code that can never change the stored value.")

    print("\n--- 5. r is NOT clamped against w or h, unlike ライト / 発光 ---")
    print("  Consequence: when a kernel is wider than the axis it slides along, the middle")
    print("  phase's count `n - kernel` goes negative and is skipped, so the pass emits")
    print("  `2*kernel - 1` outputs instead of `n + kernel - 1`, and its head phase reads")
    print("  `kernel` source samples out of an axis only `n` long.")
    print("  Pass 1 nominally emits h+kernelB-1 rows into scratch plane 1, which is")
    print("  canvas_h rows tall before plane 2 starts.")
    print(f"  {'h':>4}{'拡散':>7}{'kernel B':>10}{'nominal':>9}{'emitted':>9}"
          f"{'plane 1':>9}{'overrun':>9}")
    for h, spread in ((60, 10), (5, 10), (2, 3), (1, 4), (2, 5), (1, 5)):
        g = geometry(200, h, 0, 0, spread, stride=1024, rows=1024)
        emitted = pass_emit_count(h, g["kernel_b"])
        nominal = h + g["kernel_b"] - 1
        print(f"  {h:>4}{spread:>7}{g['kernel_b']:>10}{nominal:>9}{emitted:>9}"
              f"{g['canvas_h']:>9}{max(0, emitted - g['canvas_h']):>9}")
    g = geometry(200, 60, 0, 0, 10, stride=1024, rows=1024)
    check("a healthy object (h=60, 拡散=10) emits exactly h+kernelB-1 rows",
          pass_emit_count(60, g["kernel_b"]) == 60 + g["kernel_b"] - 1)
    check("... and pass 3 then adds kernelA-1 more, reaching h+2r = canvas_h",
          60 + g["kernel_b"] - 1 + g["kernel_a"] - 1 == g["canvas_h"],
          f"{g['canvas_h']} vs {60 + g['kernel_b'] + g['kernel_a'] - 2}")

    print("\n  Only the FIRST pass on each axis can degenerate: pass 3's input is")
    print("  h+kernelB-1 rows and pass 4's is w+kernelB-1 columns, both >= kernelA for any")
    print("  h, w >= 1 because kernelA <= kernelB by construction.")
    bad = []
    for h in range(1, 40):
        for spread in range(0, 200):
            g = geometry(200, h, 0, 0, spread, stride=1024, rows=1024)
            if h + g["kernel_b"] - 1 < g["kernel_a"]:
                bad.append((h, spread))
    check("no (h, 拡散) makes pass 3's middle phase negative", not bad, f"first {bad[:1]}")

    print("\n  exhaustively, where does pass 1 write past the grown canvas?")
    bad_shapes = []
    for h in range(1, 40):
        for spread in range(0, 200):
            g = geometry(200, h, 0, 0, spread, stride=1024, rows=1024)
            if pass_emit_count(h, g["kernel_b"]) > g["canvas_h"]:
                bad_shapes.append((h, spread))
    hs = sorted({h for h, _ in bad_shapes})
    check("only objects 1 or 2 pixels tall can overrun, and only for odd 拡散",
          hs == [1, 2] and all(s % 2 == 1 for _, s in bad_shapes),
          f"heights {hs}")
    print(f"  {len(bad_shapes)} (h, 拡散) combinations out of {39 * 200}, all with h <= 2:")
    print(f"    {bad_shapes[:8]} ...")
    print("  The overrun is at most 2 rows and lands inside scratch plane 2, which the next")
    print("  pass rewrites anyway. The *reads* are the part that shows: for any h < kernel")
    print("  the head phase pulls alpha from rows below the object, i.e. from whatever the")
    print("  allocated buffer happened to hold (README §11).")
    print("  ライト clamps with `trunc(dim/2) - 2` and 発光 with `dim/2 - 1` before anything")
    print("  else; シャドー's only clamp is the buffer-margin one from §4, which does not")
    print("  bound r by the object at all.")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
