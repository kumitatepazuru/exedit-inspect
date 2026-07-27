"""What 拡散 actually controls: it is split into two blur radii, not one.

func_proc computes, at 0x1001c431-0x1001c444:

    r2 = trunc(拡散 * 0.44722719141323786)
    r1 = 拡散 - r2

and then runs the whole diffuse-and-composite pipeline twice - once with r1,
once with r2 - so 拡散 is the *sum* of the two radii rather than either one
of them. The larger radius runs first (0x1001c52c stores r1), and the second
round diffuses the already-diffused image, which is why the result is not the
same as one blur of radius 拡散.

The constant is the interesting part. This script checks the claim that
0.44722719141323786 is not an approximation of anything irrational but
literally the double nearest to 1/2.236 - i.e. someone wrote sqrt(5) rounded
to three decimal places and divided by it. Consequences:

    拡散 / r2  = 2.236        (sqrt(5) = 2.2360679... , off by 3e-5)
    r1  / r2   = 1.236        (sqrt(5) - 1)
    r2  / r1   = 0.80906...   (phi/2 = 0.80901..., the golden ratio again)

Nothing downstream depends on that provenance - the radii are integers and
the truncation swamps the 3e-5 - so it is recorded here as a fact about the
constant, not as an explanation of why sqrt(5) was chosen at all. That part
is still open (see README section 9).

Run via main.py:
    uv run main.py inspect/diffusion_light/verify_radius_split.py
"""

import math
import struct

from tools.disasm import dump_all
from tools.pe_image import PEImage

SPLIT = (0x1001C431, 0x1E)
CONST_VA = 0x1009A468

ANNOTATIONS = {
    0x1001C431: "fild 拡散 (already clamped against the buffer size)",
    0x1001C435: "* the constant below",
    0x1001C43B: "_ftol: truncate toward zero",
    0x1001C440: "edi = r2",
    0x1001C444: "ebp = 拡散 - r2 = r1",
}

# The raw value is used as a pixel count with no scaling (tools.track_scale
# reports scale 1 for this trackbar), so raw == the number the UI shows.
TRACK_MIN, TRACK_MAX, TRACK_DEFAULT = 0, 500, 12
SLIDER_MAX = 100  # the drag range stops here; higher values need typing


def split(diffusion_raw: int, k: float) -> tuple[int, int]:
    """Replay of 0x1001c431-0x1001c444."""
    r2 = int(diffusion_raw * k)  # int() truncates toward zero, like _ftol
    return diffusion_raw - r2, r2


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_all(img, {"func_proc: 拡散 -> (r1, r2)": SPLIT}, annotations=ANNOTATIONS)

    k = img.f64(CONST_VA)
    bits = struct.unpack("<Q", struct.pack("<d", k))[0]
    print(f"\n--- the constant at 0x{CONST_VA:08x} ---")
    print(f"  value  = {k!r}   (bits 0x{bits:016x})")
    print(f"  1/k    = {1 / k!r}")
    print(f"  k == the double nearest 1/2.236 : {k == 1 / 2.236}")
    print(f"  (1-k)/k = {(1 - k) / k!r}      <- r1:r2 ratio")
    print(f"  sqrt(5)          = {math.sqrt(5)!r}")
    print(f"  1/sqrt(5)        = {1 / math.sqrt(5)!r}   (k is off by {k - 1 / math.sqrt(5):.3e})")
    print(f"  k/(1-k)          = {k / (1 - k)!r}   vs phi/2 = {(1 + math.sqrt(5)) / 4!r}")

    print("\n--- 拡散 -> radii, over the whole trackbar range ---")
    print(f"  {'拡散':>6} {'r1':>6} {'r2':>6} {'r1+r2':>7} {'r1/r2':>8}   rounds actually run")
    for raw in (0, 1, 2, 3, 4, 5, 10, TRACK_DEFAULT, 20, 50, 100, 200, 300, 400, 500):
        r1, r2 = split(raw, k)
        ratio = f"{r1 / r2:.4f}" if r2 else "-"
        rounds = [f"r={r}" for r in (r1, r2) if r]
        print(f"  {raw:6d} {r1:6d} {r2:6d} {r1 + r2:7d} {ratio:>8}   "
              f"{', '.join(rounds) or 'none (identity)'}")

    print("\n--- invariants over every reachable value ---")
    bad_sum = [raw for raw in range(TRACK_MIN, TRACK_MAX + 1)
               if sum(split(raw, k)) != raw]
    print(f"  r1 + r2 == 拡散 for all {TRACK_MAX - TRACK_MIN + 1} values: {not bad_sum}")
    bad_order = [raw for raw in range(TRACK_MIN, TRACK_MAX + 1)
                 if split(raw, k)[0] < split(raw, k)[1]]
    print(f"  r1 >= r2 (the big radius always runs first): {not bad_order}")
    only_one = [raw for raw in range(TRACK_MIN, TRACK_MAX + 1) if split(raw, k)[1] == 0]
    print(f"  values where round 2 is skipped entirely (r2 == 0): {only_one}")
    print(f"  values where nothing happens at all (r1 == r2 == 0): "
           f"{[raw for raw in range(TRACK_MIN, TRACK_MAX + 1) if split(raw, k) == (0, 0)]}")
    print(f"\n  default 拡散={TRACK_DEFAULT} -> {split(TRACK_DEFAULT, k)};  "
          f"slider stops at {SLIDER_MAX} -> {split(SLIDER_MAX, k)};  "
          f"typed max {TRACK_MAX} -> {split(TRACK_MAX, k)}")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
