"""Nail down what one ぼかし pass actually computes per pixel, and how the
three worker families differ at the image edge.

Every pass is an unweighted sliding-window sum - there is no Gaussian kernel
anywhere in this filter - but two details make it more than a plain box blur,
and both are easy to get wrong by eye:

  * On the object path the sum is ALPHA WEIGHTED. Each sample contributes
    `colour * min(a,4096)/4096` to the colour sums, and the emitted colour is
    divided by the sum of the alphas, not by the sample count. That is a
    premultiply / un-premultiply round trip, so a transparent pixel adds no
    colour instead of dragging the result toward black - the reason a blurred
    object's halo keeps its hue instead of turning grey. The alpha channel
    itself is a plain average.

  * The DIVISOR for the alpha channel is what encodes the edge policy, and it
    is not the same in all three families:

        object / サイズ固定 off : always the full kernel width
        object / サイズ固定 on  : the number of samples still inside the canvas
        frame                   : the number of samples still inside the frame

    Dividing by the full kernel while the window hangs off the edge is exactly
    "treat everything outside as transparent", which is why that worker fades
    the border out - and why it is also the one allowed to write 2*radius
    extra rows and grow the canvas. The other two renormalise instead, so the
    border keeps its opacity and the output keeps its size.

This script dumps the accumulate/emit code with annotations, extracts every
divisor site mechanically, and then runs a literal Python transcription of all
three policies on a small test column so the difference is visible as numbers.

Run via main.py:
    uv run main.py inspect/blur/verify_box_average.py
"""

from tools.cints import c_div
from tools.disasm import dump_range, function_body
from tools.pe_image import PEImage

OBJECT_GROW_INNER = (0x1000EB82, 0xE4)     # phase 1 of 0x1000eae0
FAMILIES = {
    0x1000EAE0: "object / int / サイズ固定 off  (vertical)",
    0x1000F310: "object / int / サイズ固定 on   (vertical)",
    0x1000FCB0: "frame  / int                  (vertical)",
}

ANNOTATIONS = {
    0x1000EB82: "eax = src.a  (int16 at +6)",
    0x1000EB88: "a == 0 -> contribute nothing at all, not even to the alpha sum",
    0x1000EB8E: "a >= 4096 (fully opaque) ? -> 0x1000ebc0, add the colour as-is",
    0x1000EB93: "edx = src.y (int16 at +0)",
    0x1000EB98: "--- translucent: premultiply each channel by a/4096 ---",
    0x1000EB9B: "sar 12 = arithmetic shift, so negative cb/cr round toward -inf",
    0x1000EB9E: "sum_y += (y * a) >> 12",
    0x1000EBB2: "sum_cb += (cb * a) >> 12",
    0x1000EBDC: "sum_cr += (cr * a) >> 12",
    0x1000EBC0: "--- opaque: sum_y += y, sum_cb += cb, sum_cr += cr (weight 1) ---",
    0x1000EBE6: "sum_a += a   (the raw a, not min(a,4096))",
    0x1000EBEC: "sum_a == 0 -> leave dst.y/cb/cr untouched (stale pixel kept)",
    0x1000EBF0: "st0 = (double)sum_a",
    0x1000EBF4: "st0 = (double)sum_y",
    0x1000EBF8: "* 4096.0",
    0x1000EBFE: "/ sum_a      <- un-premultiply: divide colour by the ALPHA sum",
    0x1000EC00: "_ftol: truncate toward zero -> dst.y",
    0x1000EC3D: "dst.a = sum_a / kernel_width   <- the edge policy lives here",
    0x1000EC4C: "advance src and dst by one row (stride * 8 bytes)",
}


# --------------------------------------------------------------------------
# Literal Python transcription of one vertical pass, per family.
# A pixel is (y, cb, cr, a); `None` marks a destination row never written.
# --------------------------------------------------------------------------

class Acc:
    """The four running sums the workers keep in registers/stack slots."""

    def __init__(self):
        self.y = self.cb = self.cr = self.a = 0

    def add(self, px, sign=1):
        y, cb, cr, a = px
        if a == 0:                       # test eax,eax / je
            return
        if a < 0x1000:                   # cmp eax,0x1000 / jge
            self.y += sign * ((y * a) >> 12)
            self.cb += sign * ((cb * a) >> 12)
            self.cr += sign * ((cr * a) >> 12)
        else:
            self.y += sign * y
            self.cb += sign * cb
            self.cr += sign * cr
        self.a += sign * a

    def emit(self, divisor, prev=None):
        if self.a != 0:
            y = int(self.y * 4096.0 / self.a)      # fmul 4096 / fdiv / _ftol
            cb = int(self.cb * 4096.0 / self.a)
            cr = int(self.cr * 4096.0 / self.a)
        else:                                       # colour left untouched
            y, cb, cr = prev if prev else (0, 0, 0)
        return (y, cb, cr, c_div(self.a, divisor))


def pass_object_grow(src, radius):
    """0x1000eae0: fixed divisor, output is 2*radius rows longer."""
    kernel = 2 * radius + 1
    acc, out, lead, trail = Acc(), [], 0, 0
    for _ in range(kernel):                                  # phase 1
        acc.add(src[lead]); lead += 1
        out.append(acc.emit(kernel))
    for _ in range(len(src) - kernel):                       # phase 2
        acc.add(src[lead]); lead += 1
        acc.add(src[trail], sign=-1); trail += 1
        out.append(acc.emit(kernel))
    for _ in range(kernel - 1):                              # phase 3
        acc.add(src[trail], sign=-1); trail += 1
        out.append(acc.emit(kernel))
    return out


def pass_object_fixed(src, radius):
    """0x1000f310: divisor = samples still inside the canvas, size preserved."""
    h, kernel = len(src), 2 * radius + 1
    acc, out, lead, trail = Acc(), [None] * h, 0, 0
    for _ in range(radius):                                  # phase 1: prefill
        acc.add(src[lead]); lead += 1
    row = 0
    for n in range(kernel - radius):                         # phase 2
        acc.add(src[lead]); lead += 1
        out[row] = acc.emit(radius + n + 1); row += 1
    for _ in range(h - kernel):                              # phase 3
        acc.add(src[lead]); lead += 1
        acc.add(src[trail], sign=-1); trail += 1
        out[row] = acc.emit(kernel); row += 1
    for n in range(radius):                                  # phase 4
        acc.add(src[trail], sign=-1); trail += 1
        if row < h:
            out[row] = acc.emit(kernel - n - 1)
        row += 1
    return out


def pass_frame(src, radius):
    """0x1000fcb0: no alpha at all, divisor = running valid-sample count."""
    h, kernel = len(src), 2 * radius + 1
    sy = scb = scr = 0
    n, lead, trail = 0, 0, 0
    out = [None] * h
    row = 0

    def emit():
        return (c_div(sy, n), c_div(scb, n), c_div(scr, n), None)

    for _ in range(radius):                                  # phase 1: prefill
        y, cb, cr, _a = src[lead]; lead += 1
        sy += y; scb += cb; scr += cr
    n = radius
    for _ in range(kernel - radius):                         # phase 2
        y, cb, cr, _a = src[lead]; lead += 1
        sy += y; scb += cb; scr += cr
        n += 1
        out[row] = emit(); row += 1
    for _ in range(h - kernel):                              # phase 3
        y, cb, cr, _a = src[lead]; lead += 1
        sy += y; scb += cb; scr += cr
        y, cb, cr, _a = src[trail]; trail += 1
        sy -= y; scb -= cb; scr -= cr
        out[row] = emit(); row += 1
    for _ in range(radius):                                  # phase 4
        y, cb, cr, _a = src[trail]; trail += 1
        sy -= y; scb -= cb; scr -= cr
        n -= 1
        if row < h:
            out[row] = emit()
        row += 1
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_range(img, *OBJECT_GROW_INNER,
               label="0x1000eae0 phase 1: accumulate one sample, then emit one pixel",
               resolve=False, annotations=ANNOTATIONS)

    print("\n--- every alpha/luma divisor in the three vertical families ---")
    for addr, kind in FAMILIES.items():
        print(f"\n  0x{addr:08x}  {kind}")
        body = function_body(img, addr)
        for i, insn in enumerate(body):
            if insn.mnemonic != "idiv":
                continue
            ctx = " ; ".join(f"{b.mnemonic} {b.op_str}" for b in body[max(0, i - 3):i])
            print(f"    0x{insn.address:08x}: idiv {insn.op_str:22s} <- {ctx}")

    print("""
  Reading those divisors back:
    0x1000eae0  idiv ecx with ecx = [0x1011ec3c]        -> always the kernel width
    0x1000f310  lea ecx,[radius + n + 1] / [0x1011ec3c] / kernel - n - 1
                                                        -> in-canvas sample count
    0x1000fcb0  idiv edi, edi incremented in phase 2 and
                decremented in phase 4                  -> in-frame sample count""")

    # ---- numeric demonstration -------------------------------------------
    radius = 2
    op, tr = (4096, 0, 0, 4096), (0, 0, 0, 0)          # opaque white / transparent
    red = (1000, -1000, 2000, 4096)                     # opaque, strongly coloured
    src = [tr, tr, op, red, op, tr, tr, tr]

    print(f"\n--- one vertical pass over an 8-row column, radius={radius} "
          f"(kernel={2 * radius + 1}) ---")
    print("  source rows (y, cb, cr, a):")
    for i, px in enumerate(src):
        print(f"    [{i}] {px}")

    grow = pass_object_grow(src, radius)
    fixed = pass_object_fixed(src, radius)
    frame = pass_frame(src, radius)

    print(f"\n  object / サイズ固定 off -> {len(grow)} rows "
          f"(input {len(src)} + 2*{radius}), image shifted down by {radius}:")
    for i, px in enumerate(grow):
        print(f"    [{i:2d}] y={px[0]:5d} cb={px[1]:6d} cr={px[2]:5d} a={px[3]:5d}")

    print(f"\n  object / サイズ固定 on  -> {len(fixed)} rows, alpha renormalised:")
    for i, px in enumerate(fixed):
        print(f"    [{i:2d}] y={px[0]:5d} cb={px[1]:6d} cr={px[2]:5d} a={px[3]:5d}")

    print(f"\n  frame (no alpha)        -> {len(frame)} rows:")
    for i, px in enumerate(frame):
        print(f"    [{i:2d}] y={px[0]:5d} cb={px[1]:6d} cr={px[2]:5d}")

    interior = all(grow[i + radius][:3] == fixed[i][:3]
                   for i in range(radius, len(src) - radius))
    print(f"\n  colours agree between the two object workers away from the edge: {interior}")
    print(f"  alpha at the top edge: grow={[p[3] for p in grow[:4]]}"
          f"  fixed={[p[3] for p in fixed[:4]]}")

    print("""
Verdict:
  One pass = an unweighted sliding window; the colour channels are averaged
  with alpha as the weight and divided by the alpha sum, the alpha channel is
  averaged on its own. Only the divisor of that alpha average differs between
  the three families, and that single number is the whole edge policy:

    サイズ固定 off  divides by the full kernel -> outside counts as transparent,
                    the border fades, and the canvas grows by 2*radius
    サイズ固定 on   divides by the in-canvas count -> the border keeps its
                    opacity, the canvas keeps its size
    frame           same renormalising rule, with no alpha channel to weight by

  A sample with a == 0 is skipped entirely, so fully transparent pixels never
  pull the colour toward black; when a whole window is transparent the
  destination colour is left as whatever was already in the buffer, and only
  its alpha (0) is written.
""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
