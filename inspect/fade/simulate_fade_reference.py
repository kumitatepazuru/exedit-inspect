"""An integer-faithful reimplementation of フェード, and a render of a whole
object's timeline.

Assembled from disasm_params.py / verify_seconds_to_frames.py /
verify_timeline.py / verify_alpha_curve.py / verify_worker.py, keeping the
original's arithmetic: `_ftol` and `idiv` truncate toward zero (`c_div`), `sar`
floors, the seconds-to-frames conversion happens in double precision before the
truncation, and the two ramps are `((k+1) << 12) / (n+1)` with no clamp.

What is *not* modelled, and why it does not change the result:

  * the multi-thread split. The worker is per-pixel with no cross-thread state
    and no unconditional write outside the row loop, so one thread produces
    identical output (verify_worker.py §3).
  * `*(fpip+0x114)`, the 1/100-frame remainder of the current time. フェード
    reads `*(fpip+0xA8)` only, so sub-frame time does not reach it.
  * whatever 時間制御 does to `*(fpip+0xA8)` upstream. The simulation takes the
    frame number as given, which is exactly the interface フェード sees.

`--delay` stands in for `*(fpip+0x118)`, the per-character delay テキスト
writes; leave it at 0 for any other object.

Run via main.py:
    uv run main.py inspect/fade/simulate_fade_reference.py
    uv run main.py inspect/fade/simulate_fade_reference.py --in 1.5 --out 0.25 --fps 24
    uv run main.py inspect/fade/simulate_fade_reference.py --length 40 --delay 12
"""

import argparse

from tools.cints import c_div, sar

FULL = 4096


# ---------------------------------------------------------------- parameters

def to_frames(raw: int, rate: int, scale: int) -> int:
    """0x1004dd59-0x1004dd71: x87 in doubles, then _ftol toward zero."""
    return int(raw * float(rate) / (float(scale) * 100.0))


# --------------------------------------------------------------- func_proc

def func_proc(frame, start, end, in_raw, out_raw, rate, scale, delay=0):
    """0x1004dd40. Returns (retval, alpha); alpha is None when no worker runs."""
    in_f = to_frames(in_raw, rate, scale)
    out_f = to_frames(out_raw, rate, scale)

    g = FULL                                              # 0x1004dd4b
    t = frame - start - delay                             # 0x1004dd92-0x1004dd9a
    if t < in_f:                                          # 0x1004dd9e
        a = c_div((t + 1) << 12, in_f + 1)                # 0x1004dda4-0x1004ddaa
        if a < FULL:                                      # 0x1004ddac
            g = a
    u = end - frame                                       # 0x1004ddb8-0x1004ddc4
    if u < out_f:                                         # 0x1004ddc6
        a = c_div((u + 1) << 12, out_f + 1)               # 0x1004ddca-0x1004ddd0
        if g > a:                                         # 0x1004ddd2
            g = a

    if g >= FULL:                                         # 0x1004dde4
        return 1, None
    if g <= 0:                                            # 0x1004ddeb
        return 0, g
    return 1, g


# ------------------------------------------------------------------- worker

def worker(image, w, h, stride, g):
    """0x1004de20, single-threaded. `image` is a flat list of (y, cb, cr, a)."""
    for row in range(h):
        base = stride * row
        for x in range(w):
            y, cb, cr, a = image[base + x]
            image[base + x] = (y, cb, cr, sar(a * g, 12))   # movsx/imul/sar/mov
    return image


def apply_effect(image, w, h, stride, **kw):
    """func_proc + worker, as exedit calls them."""
    ret, g = func_proc(**kw)
    if ret == 0:
        return None, 0                       # exedit drops the object entirely
    if g is None:
        return image, FULL                   # untouched
    return worker(image, w, h, stride, g), g


# ------------------------------------------------------------------ display

def bar(alpha, width=40):
    n = max(0, min(width, alpha * width // FULL))
    return "#" * n + "." * (width - n)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="simulate_fade_reference")
    p.add_argument("--in", dest="fade_in", type=float, default=0.5,
                   help="イン in seconds, as shown in the UI (default: %(default)s)")
    p.add_argument("--out", dest="fade_out", type=float, default=0.5,
                   help="アウト in seconds (default: %(default)s)")
    p.add_argument("--fps", default="30", help="30, 29.97, 24, 23.976, 60, 59.94")
    p.add_argument("--length", type=int, default=30, help="object length in frames")
    p.add_argument("--delay", type=int, default=0,
                   help="*(fpip+0x118), the テキスト per-character delay [frames]")
    p.add_argument("--start", type=int, default=100,
                   help="the object's first frame on the timeline")
    args = p.parse_args(argv or [])

    rate, scale = {"30": (30, 1), "29.97": (30000, 1001), "24": (24, 1),
                   "23.976": (24000, 1001), "60": (60, 1), "59.94": (60000, 1001)}[args.fps]
    in_raw = round(args.fade_in * 100)
    out_raw = round(args.fade_out * 100)
    start = args.start
    end = start + args.length - 1

    in_f = to_frames(in_raw, rate, scale)
    out_f = to_frames(out_raw, rate, scale)
    print(f"イン   {args.fade_in:.2f} s = raw {in_raw:4d} -> {in_f:4d} frames")
    print(f"アウト {args.fade_out:.2f} s = raw {out_raw:4d} -> {out_f:4d} frames")
    print(f"object: frames {start}..{end} ({args.length} long) at {args.fps} fps"
          f"{'' if not args.delay else f', per-character delay {args.delay} frames'}")
    print(f"fp[0x118]={start}  fp[0x11C]={end}  *(fpip+0x118)={args.delay}\n")

    print("  frame   t     u    alpha   %      exit")
    peak = 0
    for frame in range(start, end + 1):
        ret, g = func_proc(frame, start, end, in_raw, out_raw, rate, scale, args.delay)
        t = frame - start - args.delay
        u = end - frame
        if g is None:
            label, shown = "return 1 (untouched)", FULL
        elif ret == 0:
            label, shown = "return 0 (object dropped)", 0
        else:
            label, shown = "worker", g
        peak = max(peak, shown)
        print(f"  {frame:5d} {t:5d} {u:5d} {shown:8d} {shown / FULL * 100:5.1f}  "
              f"{bar(shown)}  {label}")
    print(f"\n  peak alpha over the object: {peak} ({peak / FULL * 100:.1f}%)")
    if peak < FULL:
        print("  イン + アウト reach past each other, so the object never becomes opaque.")

    print("\n--- one row of pixels, at the frame where alpha is lowest ---")
    frame = start + args.delay if args.delay else start
    ret, g = func_proc(frame, start, end, in_raw, out_raw, rate, scale, args.delay)
    w, h, stride = 8, 1, 8
    image = [(2048, 100, -100, a) for a in (0, 1, 512, 1024, 2048, 3072, 4095, 4096)]
    before = [px[3] for px in image]
    out, applied = apply_effect(list(image), w, h, stride,
                                frame=frame, start=start, end=end,
                                in_raw=in_raw, out_raw=out_raw,
                                rate=rate, scale=scale, delay=args.delay)
    print(f"  frame {frame}, alpha multiplier {applied} ({applied / FULL * 100:.1f}%)")
    print(f"  alpha in : {before}")
    if out is None:
        print("  alpha out: -- the object is not drawn at all --")
    else:
        after = [px[3] for px in out]
        print(f"  alpha out: {after}")
        print(f"  y/cb/cr  : unchanged, {out[0][:3]} everywhere")
        print(f"  a' <= a  : {all(x <= y for x, y in zip(after, before))}"
              "   (the multiplier is < 4096 on every path that reaches the worker)")
    print("""
  Two consequences of multiplying the alpha in place:

    * an already-transparent pixel stays transparent, and a semi-transparent
      object fades from *its* opacity, not from 4096. フェード composes with
      透明度 and with アルファ-writing effects by plain multiplication.
    * y/cb/cr are left as they are. The buffer is not premultiplied, so
      nothing else has to be rescaled - but it also means フェード cannot make
      an object darker, only more transparent.""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
