"""Pin down what 強さ is: not a gain on the light, but the opacity of the
diffused layer.

Two separate claims, checked separately:

  1. the conversion. func_proc turns the raw trackbar value into a Q12 number
     with the standard MSVC magic-number divide (0x1001c343-0x1001c358). This
     re-runs that literal instruction sequence for every reachable raw value
     0..1000 and compares it against plain truncating integer division, so an
     off-by-one or a rounding-mode mistake would have to show up somewhere.
     Note the range: unlike 発光, whose 強さ goes to 200% and keeps the
     overflow as a separate additive floor, 拡散光's tops out at raw 1000 ->
     exactly 4096, so the value is always a fraction of 1.0 and there is no
     over-drive path in the code at all.

  2. the consumption. Both halves of the filter use it as a blend weight, but
     they spell it differently because one has an alpha channel and the other
     does not:

       object effect   ga = (box_average_alpha * strength) >> 12
                       then a normal source-over of the diffused pixel
                       (opacity ga) onto the original.

       frame filter    out.c = src.c + (((blur.c - src.c) * strength) >> 12)
                       i.e. a plain lerp, with a shortcut that writes the
                       diffused value directly when strength >= 4096.

     The annotated dumps below are the exact instructions; the Python replays
     show the two agree at the endpoints (0 -> untouched, 4096 -> fully
     diffused) even though only one of them can express "half transparent".

Run via main.py:
    uv run main.py inspect/diffusion_light/verify_strength.py
"""

from tools.cints import MAGIC_1000, msvc_div, to_i32
from tools.disasm import dump_all
from tools.pe_image import PEImage

# The conversion, and the three shapes it is consumed in.
CONVERT = (0x1001C336, 0x32)
CONSUME_OBJECT = (0x1001CCA9, 0x2A)    # ramp-up loop of the growing horizontal worker
CONSUME_FRAME = (0x1001E8E5, 0x30)     # frame worker, the lerp

ANNOTATIONS = {
    0x1001C339: "raw 強さ",
    0x1001C33D: "0 -> return, the filter is a no-op",
    0x1001C343: "raw << 12",
    0x1001C348: "magic-number divide by 1000 ...",
    0x1001C35F: "... stored as g_1011efdc",
    0x1001CCA9: "eax = sum of alpha over the window",
    0x1001CCB1: "/ kernel width -> the box-averaged alpha",
    0x1001CCBA: "* strength ...",
    0x1001CCC1: "... >> 12: ga, the opacity of the diffused pixel",
    0x1001CCC4: "written straight into the destination alpha",
    0x1001E8E5: "strength >= 4096 ?",
    0x1001E8ED: "yes: write the diffused luma with no blend at all",
    0x1001E8F2: "no: edx = src.y",
    0x1001E8F5: "esi = blur.y - src.y",
    0x1001E8FA: "* strength",
    0x1001E8FD: ">> 12",
    0x1001E900: "+ src.y  -> a lerp from the original toward the diffused value",
}


def strength_q12(raw: int) -> int:
    """Replay of shl 12 / imul magic / sar 6 / sign fixup at 0x1001c343."""
    return msvc_div(to_i32(raw << 12), MAGIC_1000, 6)


def object_alpha(sum_alpha: int, kernel_width: int, strength: int) -> int:
    """ga, as computed at 0x1001ccb1-0x1001ccc1 (and three more copies)."""
    return ((sum_alpha // kernel_width) * strength) >> 12


def frame_blend(src: int, blurred: int, strength: int) -> int:
    """Replay of 0x1001e8e5-0x1001e900."""
    if strength >= 0x1000:
        return blurred
    return src + (((blurred - src) * strength) >> 12)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_all(PEImage(dll_path), {
        "func_proc: 強さ -> Q12": CONVERT,
        "object effect: box-averaged alpha * strength": CONSUME_OBJECT,
        "frame filter: lerp by strength": CONSUME_FRAME,
    }, annotations=ANNOTATIONS)

    print("\n--- conversion: every reachable raw value 0..1000 ---")
    bad = [(r, strength_q12(r), r * 4096 // 1000) for r in range(1001)
           if strength_q12(r) != r * 4096 // 1000]
    if bad:
        print(f"  MISMATCH on {len(bad)} values, first few: {bad[:8]}")
    else:
        print("  OK: identical to raw*4096//1000 (truncating) for all 1001 values.")
    print(f"  raw=1000 (UI 100.0) -> {strength_q12(1000)}  "
          f"(0x1000, i.e. exactly 'fully opaque'; the range cannot exceed it)")
    for raw in (0, 1, 250, 500, 750, 999, 1000):
        print(f"  raw={raw:5d}  UI={raw / 10:6.1f}  ->  strength={strength_q12(raw):5d}"
              f"  = {strength_q12(raw) / 4096:.4f}")

    print("\n--- object effect: ga for a window that is fully opaque (alpha 4096 everywhere) ---")
    for radius in (2, 7, 30):
        kw = 2 * radius + 1
        for raw in (250, 500, 1000):
            ga = object_alpha(0x1000 * kw, kw, strength_q12(raw))
            print(f"  radius={radius:3d} kw={kw:4d}  強さ={raw / 10:5.1f}  ->  ga={ga:5d}")
    print("  (a half-covered window halves ga again: the diffused layer is only as")
    print("   opaque as the average coverage under it, times 強さ)")

    print("\n--- frame filter: the lerp at the endpoints ---")
    for raw in (0, 250, 500, 1000):
        s = strength_q12(raw)
        row = [frame_blend(src, 3000, s) for src in (0, 1000, 2000, 3000)]
        print(f"  強さ={raw / 10:5.1f} (strength={s:4d})  src 0/1000/2000/3000 with "
              f"blur.y=3000 -> {row}")
    print("  強さ=0 would leave the frame untouched, which is why func_proc returns early.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
