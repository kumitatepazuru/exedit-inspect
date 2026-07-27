"""What a ray's samples turn into, and the two surprises in the encoding.

Both workers finish a pixel the same way (0x1004ec2e / 0x1004f07c):

    avgY = sumY / length
    out  = avgY - T                       T = 4096 - strength
    if out <= 0:  write 0,0,0,0           fully transparent, nothing else
    cb = sumCb/length - T*(sumCb/length)/avgY
    cr = sumCr/length - T*(sumCr/length)/avgY
    if out < 4096:  y=4096, cb=cb*4096/out, cr=cr*4096/out, a=out
    else:           y=out,  cb=cb,          cr=cr,          a=4096

Surprise one: the two chroma steps cancel. Scaling by (avgY-T)/avgY and then
by 4096/(avgY-T) leaves cb*4096/avgY - the *threshold drops out entirely*. In
the out < 4096 branch, which is where a glint spends almost all of its area,
強さ changes only the alpha. The colour of the streak is fixed by the ray's
average and does not shift as the parameter is turned down.

Surprise two: this is an unpremultiply. Writing y=4096 with a=out is exactly
"divide the premultiplied colour (out, cb, cr) by out/4096", i.e. the glint's
brightness is re-expressed as its opacity at constant full luminance. That is
why 閃光 needs no compositing pass of its own for the light itself - the
alpha it writes is the light.

The 16-bit store that follows has no clamp (`mov word ptr [ebp+2], ax`), so
this script also checks how much headroom cb*4096/avgY actually has, using the
Q14 BT.601 table exedit converts colours with.

Run via main.py:
    uv run main.py inspect/glint/verify_output_encoding.py
"""

from tools.cints import c_div
from tools.pe_image import PEImage

# Per-input-channel Q14 rows (Y, Cb, Cr), in AviUtl PIXEL order b, g, r.
# Same table inspect/luminous/verify_ycbcr_matrix.py checks against BT.601.
COEF_VA = {"b": 0x100A989C, "g": 0x100A98A4, "r": 0x100A98AC}


def encode(sum_y: int, sum_cb: int, sum_cr: int, length: int, T: int):
    """The tail of either worker, exactly as written."""
    avg_y = c_div(sum_y, length)
    out = avg_y - T
    if out <= 0:
        return 0, 0, 0, 0
    cb = c_div(sum_cb, length)
    cr = c_div(sum_cr, length)
    cb -= c_div(T * cb, avg_y)
    cr -= c_div(T * cr, avg_y)
    if out < 0x1000:
        return 0x1000, c_div(cb << 12, out), c_div(cr << 12, out), out
    return out, cb, cr, 0x1000


def to_i16(v: int) -> int:
    """`mov word ptr [...], ax` - a plain 16-bit store, no saturation."""
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def ycc_of_rgb(img: PEImage, r: int, g: int, b: int):
    """The ratios exedit's own coefficient table produces for an 8-bit colour."""
    out = []
    for i in range(3):  # 0 = Y, 1 = Cb, 2 = Cr
        acc = 0
        for ch, val in (("b", b), ("g", g), ("r", r)):
            acc += img.i16(COEF_VA[ch] + 2 * i) * val
        out.append(acc / 16384)
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("1) the threshold cancels out of the emitted chroma")
    print("   analytically: cb * (avgY-T)/avgY * 4096/(avgY-T) == cb * 4096/avgY")
    print(f"   {'avgY':>6}{'sumCb/len':>11}{'T=0':>8}{'T=512':>8}{'T=1024':>8}"
          f"{'T=2048':>8}{'T=3000':>8}   spread")
    for avg_y, cb_avg in ((4000, 800), (2000, -600), (900, 300), (3500, -1500)):
        row = []
        for T in (0, 512, 1024, 2048, 3000):
            length = 64
            y, cb, cr, a = encode(avg_y * length, cb_avg * length, 0, length, T)
            row.append(cb if a else None)
        shown = [f"{v:>8}" if v is not None else f"{'cut':>8}" for v in row]
        live = [v for v in row if v is not None]
        spread = (max(live) - min(live)) if live else 0
        print(f"   {avg_y:>6}{cb_avg:>11}{''.join(shown)}   {spread}")
    print("   the residual spread is integer truncation in the two divides, never")
    print("   more than a couple of units - 強さ moves the alpha, not the colour.")

    print("\n2) the write is an unpremultiply, not a fade")
    print(f"   {'avgY':>6}{'T':>6}{'out':>6} | {'y':>6}{'cb':>7}{'a':>6} | "
          f"premultiplied back: y*a/4096")
    for avg_y, T in ((4000, 0), (4000, 2048), (4000, 3600), (5000, 0), (8000, 0)):
        length = 32
        y, cb, cr, a = encode(avg_y * length, 500 * length, 0, length, T)
        if not a:
            print(f"   {avg_y:>6}{T:>6}{avg_y - T:>6} | {'transparent':>21} |")
            continue
        print(f"   {avg_y:>6}{T:>6}{avg_y - T:>6} | {y:>6}{cb:>7}{a:>6} | "
              f"{y * a // 4096:>6}  (== out: {y * a // 4096 == avg_y - T})")
    print("   above 4096 the alpha saturates and the luminance carries the excess,")
    print("   so a very bright glint goes superwhite instead of more opaque.")

    print("\n3) headroom of the unclamped 16-bit chroma store")
    print("   cb_written = cb_source * 4096 / avgY, and the ratio cb/y survives the")
    print("   alpha weighting untouched (both are multiplied by the same alpha), so")
    print("   the worst case is whichever in-gamut colour has the largest |cb|/y:")
    print(f"   {'colour':>10}{'Y':>9}{'Cb':>9}{'Cr':>9}{'|Cb|/Y':>9}{'|Cr|/Y':>9}"
          f"{'cb written':>12}")
    worst = 0
    for name, rgb in (("#0000ff", (0, 0, 255)), ("#ff0000", (255, 0, 0)),
                      ("#00ff00", (0, 255, 0)), ("#ff00ff", (255, 0, 255)),
                      ("#000080", (0, 0, 128)), ("#ffffff", (255, 255, 255))):
        y, cb, cr = ycc_of_rgb(img, *rgb)
        rb = abs(cb) / y if y else 0
        rr = abs(cr) / y if y else 0
        written = int(max(rb, rr) * 4096)
        worst = max(worst, written)
        print(f"   {name:>10}{y:>9.1f}{cb:>9.1f}{cr:>9.1f}{rb:>9.3f}{rr:>9.3f}{written:>12}")
    print(f"   worst in-gamut value written: {worst}, against the int16 limit 32767")
    print(f"   -> {'no overflow from ordinary image content' if worst < 32767 else 'OVERFLOWS'}.")
    print("   It only becomes reachable if an upstream effect leaves out-of-gamut YC")
    print("   in the buffer (chroma high relative to luminance); then the store wraps:")
    for cb_avg, avg_y in ((2000, 200), (3000, 300)):
        raw = c_div(cb_avg << 12, avg_y)
        print(f"     avgCb={cb_avg} avgY={avg_y} -> {raw} stored as {to_i16(raw)}"
              f"{'  (wrapped, hue flips)' if to_i16(raw) != raw else ''}")

    print("\n4) the two workers differ only in what they accumulate")
    print("   0x1004e9c0 (光色の設定 = no colour, ex_data bit24 set):")
    print("     a = src.a;  if a < 4096: sum += src.y/cb/cr * a >> 12  else: sum += src.y/cb/cr")
    print("   0x1004ee20 (a colour was picked, bit24 clear):")
    print("     a = src.a;  if a < 4096: sum += colour.y/cb/cr * a >> 12 else: sum += colour...")
    print("   -> with a colour set, the source luminance is never read at all. The ray")
    print("      measures coverage only, so a dark object and a bright one of the same")
    print("      shape glint identically. That is the opposite of 発光, where the chosen")
    print("      colour multiplies the extracted brightness.")
    print("   -> in both, out-of-range samples are skipped entirely rather than counted")
    print("      as zero, but `length` is the divisor regardless, so a ray running off")
    print("      the edge of the source is averaged as if the missing samples were black.")

    print("\n5) with a colour set, 強さ has a hard cut-off that depends on the colour")
    print("   In colour mode the largest avgY reachable is the colour's own Y (every")
    print("   sample fully opaque). Nothing renders at all unless T < that, so a dark")
    print("   light colour needs a high 強さ before the glint appears:")
    print(f"   {'colour':>10}{'colour Y':>10}{'needs T <':>11}{'i.e. 強さ >':>13}")
    for name, rgb in (("#ffffff", (255, 255, 255)), ("#ffff00", (255, 255, 0)),
                      ("#ff0000", (255, 0, 0)), ("#00ff00", (0, 255, 0)),
                      ("#0000ff", (0, 0, 255)), ("#000080", (0, 0, 128))):
        y8 = ycc_of_rgb(img, *rgb)[0]
        y4096 = int(y8 * 4096 / 256)
        # T = 4096 - trunc(raw*4096/1000) < y4096  ->  raw > (4096-y4096)*1000/4096
        raw = (4096 - y4096) * 1000 // 4096 + 1
        print(f"   {name:>10}{y4096:>10}{y4096:>11}{raw / 10:>12.1f}")
    print("   a dark blue light is therefore invisible below 強さ 88.7 no matter how")
    print("   bright the object is - the object's luminance is not in the sum at all.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
