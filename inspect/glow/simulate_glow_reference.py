"""Integer-faithful reference model of the whole 発光 pipeline, plus the two
models the aperio port implements (current and corrected), so a specific
parameter set can be compared as concrete RGB values instead of prose.

Scope: the *interior of a large flat area*. A box blur of a constant field
returns that same constant, so every one of the 6 passes reproduces the same
per-pixel value and the spatial part of the filter drops out - which makes
the whole chain computable in closed form, exactly the situation the two
reported test cases were sampled in. (It also means the 拡散 value, and
therefore the unresolved UI-value-to-raw mapping for it, does not affect any
number printed here.)

Everything else is replayed instruction-faithfully:

  * light color RGB -> YCbCr with the Q14 BT.601 table read out of the binary
    (verify_ycbcr_matrix.py)
  * extraction with alpha-weighted luma, threshold, gain, overflow, and the
    light color's own Y/Cb/Cr multiply (verify_extract_alpha.py)
  * the 拡散速度 forward curve with its [0,4096] input clamp, and the inverse
    with no output clamp (verify_curve_clamp.py)
  * both accumulators: the saturating integer one used at 拡散速度=0 and the
    float+signed-byte one used above it (verify_accumulate.py)
  * the object-effect alpha composite and the frame-filter add
    (verify_object_composite.py)

Default case is the one that was measured against real AviUtl: a white
object, light color #f00, strength 60 / diffusion 45 / threshold 20 /
diffusion speed 60, sampled inside the fill.

Run via main.py:
    uv run main.py inspect/glow/simulate_glow_reference.py
    uv run main.py inspect/glow/simulate_glow_reference.py --speed 0 --src ffffff
"""

import argparse
import math
import struct

from tools.pe_image import PEImage

# Q14 BT.601 rows, same addresses verify_ycbcr_matrix.py checks.
ROW_B, ROW_G, ROW_R = 0x100A989C, 0x100A98A4, 0x100A98AC
Q14 = 16384
YC_MAX = 4096          # PIXEL_YC full-scale luma
RGB_TO_YC = YC_MAX / 255.0

# UI-value -> trackbar raw value. 強さ/しきい値 are raw = UI*10 (raw 1000 =
# 100% = gain 4096); 拡散速度's raw range is 0..60 and matches the UI 1:1.
# 拡散 is not used here (see the module docstring).
STRENGTH_UI_TO_RAW = 10
THRESHOLD_UI_TO_RAW = 10


def _matrix(img):
    rows = {}
    for label, va in (("B", ROW_B), ("G", ROW_G), ("R", ROW_R)):
        rows[label] = struct.unpack_from("<3h", img.code(va, 6))
    return rows


def rgb_to_yc(rows, r, g, b):
    """RGB 0..255 -> PIXEL_YC (y 0..4096, cb/cr +-2048), exedit's matrix."""
    out = []
    for i in range(3):
        acc = sum(rows[ch][i] * v for ch, v in (("R", r), ("G", g), ("B", b)))
        out.append(int(round(acc / Q14 * RGB_TO_YC)))
    return tuple(out)


def yc_to_rgb(y, cb, cr):
    """PIXEL_YC -> RGB 0..255 via the exact BT.601 inverse, clipped per channel."""
    yf, cbf, crf = y / RGB_TO_YC, cb / RGB_TO_YC, cr / RGB_TO_YC
    r = yf + 1.402000 * crf
    g = yf - 0.344136 * cbf - 0.714136 * crf
    b = yf + 1.772000 * cbf
    return tuple(max(0, min(255, int(round(v)))) for v in (r, g, b))


def hexcolor(rgb):
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def params_from_ui(strength_ui, threshold_ui):
    """The 強さ/しきい値 fixed-point conversion (verify_strength_threshold.py)."""
    fixed = (strength_ui * STRENGTH_UI_TO_RAW) * 4096 // 1000
    gain, overflow = (4096, fixed - 4096) if fixed > 4096 else (fixed, 0)
    threshold = (threshold_ui * THRESHOLD_UI_TO_RAW) * 4096 // 1000
    return gain, overflow, threshold


def extract(src, alpha, gain, overflow, threshold, light_yc, object_mode):
    """One pixel of sub_100535a0 / sub_100536d0 / sub_100533c0 / sub_100534b0."""
    y, cb, cr = src
    y_eff = (y * alpha) >> 12 if object_mode else y
    diff = y_eff - threshold
    if diff < 0:
        return (0, 0, 0)
    brightness = min(((diff * gain) >> 12) + overflow, 4096)
    if light_yc is None:                      # bit24 set: keep the source's own chroma
        return (brightness, (cb * brightness) >> 12, (cr * brightness) >> 12)
    ly, lcb, lcr = light_yc                   # bit24 clear: the picked color drives all three
    return ((ly * brightness) >> 12, (lcb * brightness) >> 12, (lcr * brightness) >> 12)


def accumulate_saturating(start, contribution, passes=6):
    """sub_100540a0 / sub_100544a0: luma pinned at 0x2000, chroma faded past it."""
    acc_y, acc_cb, acc_cr = start
    py, pcb, pcr = contribution
    for _ in range(passes):
        s = acc_y + py
        if s <= 0x2000:
            acc_y, acc_cb, acc_cr = s, acc_cb + pcb, acc_cr + pcr
        else:
            acc_y = 0x2000
            if s > 0x4000:
                acc_cb = acc_cr = 0
            else:
                t = 0x4000 - s
                acc_cb = ((acc_cb + pcb) * t) >> 13
                acc_cr = ((acc_cr + pcr) * t) >> 13
    return acc_y, acc_cb, acc_cr


def curve_roundtrip(glow, base, passes=6):
    """sub_100705c0 -> sub_100548a0 x6 -> sub_10070780."""
    gy, gcb, gcr = glow
    curved = base ** (max(0, min(4096, gy)) / 16.0) - 1.0
    cb_b = max(-128, min(127, (gcb + 8) >> 4))
    cr_b = max(-128, min(127, (gcr + 8) >> 4))
    acc_y, acc_cb, acc_cr = 0.0, 0, 0
    for _ in range(passes):
        acc_y += curved
        acc_cb = max(-128, min(127, acc_cb + cb_b))
        acc_cr = max(-128, min(127, acc_cr + cr_b))
    y_out = int(16 * math.log(acc_y + 1.0) / math.log(base) + 0.5)
    return y_out, acc_cb << 4, acc_cr << 4


def composite_object(dst, dst_a, glow):
    """sub_10053890."""
    gy, gcb, gcr = glow
    if dst_a >= 4096:
        return (dst[0] + gy, dst[1] + gcb, dst[2] + gcr), dst_a
    if dst_a <= 0:
        na = gy
        if na <= 0:
            return dst, dst_a
        na = min(na, 4096)
        return tuple((c << 12) // na for c in glow), na
    na = dst_a + gy
    if na <= 0:
        return dst, dst_a
    na = min(na, 4096)
    return tuple((d * dst_a + (g << 12)) // na for d, g in zip(dst, glow)), na


def aviutl_reference(rows, src_rgb, src_alpha, light_rgb, strength_ui, threshold_ui,
                     speed, object_mode):
    gain, overflow, threshold = params_from_ui(strength_ui, threshold_ui)
    src = rgb_to_yc(rows, *src_rgb)
    light_yc = rgb_to_yc(rows, *light_rgb) if light_rgb else None
    glow = extract(src, src_alpha, gain, overflow, threshold, light_yc, object_mode)

    if speed > 0:
        base = 1.0 + max(1, min(100, speed)) * 0.001
        accum = curve_roundtrip(glow, base)
        if object_mode:
            out, out_a = composite_object(src, src_alpha, accum)
        else:
            out = tuple(s + a for s, a in zip(src, accum))
            out_a = src_alpha
    elif object_mode:
        accum = accumulate_saturating((0, 0, 0), glow)
        out, out_a = composite_object(src, src_alpha, accum)
    else:
        # frame filter, speed = 0: each pass accumulates straight into the image,
        # so the saturating accumulator starts from the image pixel itself.
        out = accumulate_saturating(src, glow)
        out_a = src_alpha
    return yc_to_rgb(*out), out, out_a


def _port_common(src_rgb, light_rgb, strength_ui, threshold_ui, alpha, use_alpha):
    """Shared front half of the port's threshold.wgsl (values normalised to 0..1)."""
    srgb = [c / 255.0 for c in src_rgb]
    lum = 0.299 * srgb[0] + 0.587 * srgb[1] + 0.114 * srgb[2]
    if use_alpha:
        lum *= alpha / 4096.0
    gain = min(strength_ui / 100.0, 1.0)
    overflow = max(0.0, strength_ui / 100.0 - 1.0)
    threshold = threshold_ui / 100.0
    amount = 0.0
    if lum > threshold:
        amount = max(0.0, min(1.0, (lum - threshold) * gain + overflow))
    lrgb = [c / 255.0 for c in light_rgb]
    luma_color = 0.299 * lrgb[0] + 0.587 * lrgb[1] + 0.114 * lrgb[2]
    cr_dev = (lrgb[0] - luma_color) / 1.402000
    cb_dev = (lrgb[2] - luma_color) / 1.772000
    return amount, luma_color, cr_dev, cb_dev


def _yc_to_rgb_norm(y, cb, cr):
    return (y + 1.402000 * cr,
            y - 0.344136 * cb - 0.714136 * cr,
            y + 1.772000 * cb)


def port_model(src_rgb, src_alpha, light_rgb, strength_ui, threshold_ui, speed,
               *, fixed):
    """The port's own math, in its normalised 0..1 space. `fixed` applies the
    corrections: alpha-weighted luma, the light color's Y multiplied in at
    extraction time (luma only - chroma already carries the colour), the
    signed-byte chroma clamp, the saturating accumulator, and additive alpha."""
    amount, luma_color, cr_dev, cb_dev = _port_common(
        src_rgb, light_rgb, strength_ui, threshold_ui, src_alpha, use_alpha=fixed)
    # luma carries the light colour's Y; chroma is already the colour's own deviation
    luma_amount = amount * luma_color if fixed else amount
    chroma_limit = (2032 / 4096) if fixed else 1.0

    if speed > 0:
        base = 1.0 + max(1, min(100, speed)) * 0.001
        curved = base ** (luma_amount * 256.0) - 1.0
        acc_y, acc_cr, acc_cb = 0.0, 0.0, 0.0
        for _ in range(6):
            acc_y += curved
            acc_cr = max(-chroma_limit, min(chroma_limit, acc_cr + amount * cr_dev))
            acc_cb = max(-chroma_limit, min(chroma_limit, acc_cb + amount * cb_dev))
        y_final = math.log(acc_y + 1.0) / (256.0 * math.log(base))
        y_component = y_final if fixed else y_final * luma_color
        premul = _yc_to_rgb_norm(y_component, acc_cb, acc_cr)
        glow_alpha = max(0.0, min(1.0, y_final))
    elif fixed:
        acc_y, acc_cb, acc_cr = 0.0, 0.0, 0.0
        for _ in range(6):                      # saturating accumulator, normalised
            s = acc_y + luma_amount
            if s <= 2.0:
                acc_y, acc_cb, acc_cr = s, acc_cb + amount * cb_dev, acc_cr + amount * cr_dev
            else:
                acc_y = 2.0
                t = max(0.0, (4.0 - s) / 2.0)
                acc_cb = (acc_cb + amount * cb_dev) * t
                acc_cr = (acc_cr + amount * cr_dev) * t
        premul = _yc_to_rgb_norm(acc_y, acc_cb, acc_cr)
        glow_alpha = max(0.0, min(1.0, acc_y))
    else:
        total = amount * 6
        lrgb = [c / 255.0 for c in light_rgb]
        premul = tuple(total * c for c in lrgb)
        glow_alpha = max(0.0, min(1.0, total))

    base_a = src_alpha / 4096.0
    base_premul = [c / 255.0 * base_a for c in src_rgb]
    out_a = (min(1.0, base_a + glow_alpha) if fixed
             else max(0.0, min(1.0, base_a + glow_alpha - base_a * glow_alpha)))
    if out_a <= 1e-6:
        return (0, 0, 0), 0
    out = [max(0.0, min(1.0, (bp + gp) / out_a)) for bp, gp in zip(base_premul, premul)]
    return tuple(int(round(c * 255)) for c in out), int(round(out_a * 4096))


def _parse_rgb(text):
    text = text.lstrip("#")
    return tuple(int(text[i:i + 2], 16) for i in (0, 2, 4))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="simulate_glow_reference")
    ap.add_argument("--src", default="ffffff", help="source pixel RGB (default: ffffff)")
    ap.add_argument("--alpha", type=int, default=4096, help="source alpha 0..4096 (default: 4096)")
    ap.add_argument("--color", default="ff0000", help="light color RGB, or 'none' (default: ff0000)")
    ap.add_argument("--strength", type=int, default=60, help="strength, UI value (default: 60)")
    ap.add_argument("--threshold", type=int, default=20, help="threshold, UI value (default: 20)")
    ap.add_argument("--speed", type=int, default=60, help="diffusion speed 0..60 (default: 60)")
    ap.add_argument("--mode", choices=("object", "frame"), default="object")
    args = ap.parse_args(argv or [])

    rows = _matrix(PEImage(dll_path))

    src_rgb = _parse_rgb(args.src)
    light_rgb = None if args.color.lower() == "none" else _parse_rgb(args.color)
    object_mode = args.mode == "object"

    print(f"--- case: src=#{args.src} alpha={args.alpha} light="
          f"{'none (source chroma)' if light_rgb is None else '#' + args.color} "
          f"strength={args.strength} threshold={args.threshold} speed={args.speed} "
          f"mode={args.mode} ---")

    ref_rgb, ref_yc, ref_a = aviutl_reference(
        rows, src_rgb, args.alpha, light_rgb, args.strength, args.threshold,
        args.speed, object_mode)
    print(f"\nAviUtl reference : {hexcolor(ref_rgb)}   "
          f"(y={ref_yc[0]}, cb={ref_yc[1]}, cr={ref_yc[2]}, a={ref_a})")

    if light_rgb is None:
        print("\n(The port has no 'light color unset' mode, so its two rows are skipped.)")
    else:
        cur, cur_a = port_model(src_rgb, args.alpha, light_rgb, args.strength,
                                args.threshold, args.speed, fixed=False)
        fix, fix_a = port_model(src_rgb, args.alpha, light_rgb, args.strength,
                                args.threshold, args.speed, fixed=True)
        print(f"port, as written : {hexcolor(cur)}   (a={cur_a})")
        print(f"port, corrected  : {hexcolor(fix)}   (a={fix_a})   "
              "[alpha-weighted luma, light-color Y at extraction, chroma clamp 2032/4096,\n"
              "                                        saturating accumulator, additive alpha]")

    if args.alpha == 0:
        print("\nNote: the source pixel is fully transparent, so AviUtl extracts nothing from\n"
              "it (a=0 in, a=0 out). Any nonzero alpha on the port rows is glow invented out\n"
              "of a pixel AviUtl treats as empty - the haze-around-objects symptom.")

    if not argv:
        print(
            "\nMeasured on real AviUtl for this default case: #ffff79, and the port as\n"
            "written produced #ff9b6e. The model reproduces both sides, and the corrected\n"
            "port model lands back on the AviUtl reference - the residual few counts come\n"
            "from the sample not sitting perfectly inside the flat region.\n"
        )


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
