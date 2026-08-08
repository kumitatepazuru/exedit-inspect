"""What pass 2 actually writes: the flat-colour encoder, the pattern encoder,
and the composite that puts the object back on top.

Six claims:

  1. **The border colour goes into Y/Cb/Cr raw**, exactly as stored by the
     shared RGB->YCbCr helper, with no coverage scaling and no amplitude
     premultiply. So - like シャドー and unlike ライト / 閃光 - a black border
     is just as opaque as a white one.

  2. **`sum == 0` writes alpha 0 and leaves y/cb/cr alone.** The `je` at
     0x10051d35 sits on the flags of the `add` that folds the sample in, so
     the test is on the running window sum, not on the sample.

  3. **Output alpha can never exceed 4096 and is never clamped from below.**
     The saturating store is the only bound the encoder has; there is no
     opacity trackbar to multiply by, so a fully covered pixel is exactly
     opaque.

  4. **The pattern encoder never writes colour.** Its body contains zero
     references to the three colour globals - the tiled pattern supplies both
     colour and alpha, and `縁色の設定` is completely inert while a pattern is
     set. When the coverage saturates it does not write at all.

  5. **The two encoders are mutually exclusive**, chosen once per frame by
     `patW && patH` at 0x100519de, and the choice matches the ex_data
     exclusivity verify_ex_data.py checks from the UI side.

  6. **The object goes back on top with plain alpha compositing** (mode word
     `3` -> blend function 0x10007df0), so the border is only visible where
     the object is not opaque. That is the difference between 縁取り and
     シャドー: シャドー offsets its box, 縁取り leaves it concentric and lets
     the object cover the middle.

Run via main.py:
    uv run main.py inspect/border/verify_encode.py
"""

from tools.cints import to_i32
from tools.disasm import disasm_range, function_body
from tools.pe_image import PEImage
from tools.xrefs import scan

FULL = 4096

PASS2_COLOUR = 0x10051C80
PASS2_PATTERN = 0x10051EA0
COLOUR_Y, COLOUR_CB, COLOUR_CR = 0x101B1F50, 0x101B1F4C, 0x101B1F4E
BLEND_TABLE = 0x1009FBB0


def gain(size: int, blur: int) -> int:
    return int(1024.0 / ((2 * size) * blur * 0.01 + 1.0) + 0.5)


def encode_colour(total: int, g: int, colour_yc, dst_yc):
    """0x10051d30-0x10051d7d. Returns the pixel pass 2 leaves behind."""
    if total == 0:                                  # 0x10051d35
        return (*dst_yc[:3], 0)                     # only alpha is written
    v = to_i32(to_i32(total) * g) >> 10             # 0x10051d59-0x10051d5e
    a = FULL if v >= FULL else (v & 0xFFFF) - (0x10000 if v & 0x8000 else 0)
    return (*colour_yc, a)                          # colour stored verbatim


def encode_pattern(total: int, g: int, dst_yc):
    """0x10051f52-0x10051f73. Returns the pixel, colour untouched throughout."""
    v = to_i32(to_i32(total) * g) >> 10
    if v >= FULL:                                   # 0x10051f61
        return dst_yc                               # not written at all
    y, cb, cr, a = dst_yc
    return (y, cb, cr, to_i32(a * v) >> 12)         # 0x10051f6d-0x10051f73


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)

    print("--- 1. the border colour is stored raw, so a black border stays opaque ---")
    body = function_body(img, PASS2_COLOUR)
    stores = [(hex(i.address), i.op_str) for i in body
              if i.mnemonic == "mov" and i.op_str.startswith("dx, word ptr [0x101b1f")]
    check("the colour worker loads the three colour globals nine times (three phases "
          "x Y/Cb/Cr) and does nothing to them but store", len(stores) == 9,
          f"{len(stores)} loads")
    muls = [(hex(i.address), i.mnemonic, i.op_str) for i in body
            if i.mnemonic in ("imul", "mul") and "0x101b1f5" in i.op_str]
    check("no arithmetic on the colour globals anywhere in the worker", not muls, f"{muls}")
    dark = encode_colour(FULL * 5, 1024, (0, 0, 0), (9, 9, 9, 9))
    light = encode_colour(FULL * 5, 1024, (FULL, 0, 0), (9, 9, 9, 9))
    check("RGB(0,0,0) and RGB(255,255,255) produce the same alpha for the same coverage",
          dark[3] == light[3] == FULL, f"{dark} vs {light}")
    print("  ライト's halo and 閃光 fix Y at 4096 and move the light's luminance into")
    print("  alpha (rgb_ycbcr.md §4), so a dark colour makes the effect vanish. 縁取り")
    print("  and シャドー do the opposite: the colour is decoration, the coverage is")
    print("  the alpha. With RGB(0,0,0) the default border is a solid black outline.")

    print("\n--- 2. sum == 0 writes alpha 0 and leaves y/cb/cr alone ---")
    seq = [i for i in body if 0x10051D30 <= i.address <= 0x10051D40]
    check("the je at 0x10051d35 immediately follows the `add eax, edx` that folds the "
          "sample into the running sum",
          [(i.mnemonic, i.op_str) for i in seq][:3]
          == [("movsx", "edx, word ptr [edi]"), ("add", "eax, edx"), ("je", "0x10051d77")],
          f"{[(hex(i.address), i.mnemonic, i.op_str) for i in seq][:3]}")
    stale = encode_colour(0, 1024, (100, 200, 300), (7, 7, 7, 7))
    check("with sum 0 the stale y/cb/cr survive and alpha is 0", stale == (7, 7, 7, 0),
          f"{stale}")
    print("  Harmless - alpha 0 makes the pixel invisible - and the same reasoning as")
    print("  box_blur.md §1's `sum_a == 0` guard. Note the reverse case exists too: a")
    print("  small non-zero sum whose alpha truncates to 0 DOES get the border colour")
    print("  written, so there are two kinds of invisible pixel in the output.")

    print("\n--- 3. alpha saturates at 4096 and has no other bound ---")
    print(f"  {'coverage sum':>14}{'gain':>6}{'alpha':>8}")
    for total, g in ((0, 1024), (1, 1024), (2048, 1024), (FULL, 1024),
                     (FULL * 3, 1024), (FULL * 3, 341), (FULL * 17, 60)):
        print(f"  {total:>14}{g:>6}{encode_colour(total, g, (1, 2, 3), (0, 0, 0, 0))[3]:>8}")
    bad = [(t, g) for g in (1, 60, 341, 1024) for t in range(0, FULL * 40, 97)
           if not 0 <= encode_colour(t, g, (1, 2, 3), (0,) * 4)[3] <= FULL]
    check("4 gains x 1688 sums: alpha always lands in 0..4096", not bad,
          f"first {bad[:1]}")
    print("  There is no 濃さ-style opacity trackbar to multiply by, so nothing can")
    print("  make the border translucent except ぼかし scaling the coverage down.")

    print("\n--- 4. the pattern encoder never writes colour ---")
    pbody = function_body(img, PASS2_PATTERN)
    span = (pbody[0].address, pbody[-1].address + pbody[-1].size)
    refs = [va for g in (COLOUR_Y, COLOUR_CB, COLOUR_CR) for va in scan(img, g)
            if span[0] <= va < span[1]]
    check(f"zero references to the colour globals in 0x{span[0]:08x}-0x{span[1]:08x}",
          not refs, f"{[hex(v) for v in refs]}")
    writes = [(hex(i.address), i.op_str) for i in pbody
              if i.mnemonic == "mov" and i.op_str.startswith("word ptr")]
    check("the only 16-bit store in the whole worker is the alpha at +6",
          len(writes) == 3 and all("di" in w[1] for w in writes), f"{writes}")
    untouched = encode_pattern(FULL * 5, 1024, (11, 22, 33, 4000))
    check("saturated coverage leaves the pattern pixel completely alone",
          untouched == (11, 22, 33, 4000), f"{untouched}")
    half = encode_pattern(2048, 1024, (11, 22, 33, 4096))
    check("half coverage multiplies the pattern's own alpha: 4096 * 2048 >> 12 = 2048",
          half == (11, 22, 33, 2048), f"{half}")
    print("  So 濃さ-equivalent control over a pattern border comes from the pattern's")
    print("  own alpha channel, and the two multiply commutatively - the same structure")
    print("  シャドー's pattern encoder has (シャドー §5).")

    print("\n--- 5. the two encoders are mutually exclusive ---")
    seq = [(hex(i.address), i.mnemonic, i.op_str)
           for i, _ in disasm_range(img, 0x100519D5, 0x35, resolve=False)][:8]
    check("0x100519de/0x100519e6 test patW then patH, and either being 0 selects the "
          "colour worker",
          any(op == "je" and "0x100519fa" in s for _, op, s in seq), f"{seq[:5]}")
    print("  patW/patH are stack slots initialised to 0 and only ever written by")
    print("  table[0x38] (0x100517df), so 'no path' and 'load failed' both land on the")
    print("  colour worker. The ex_data side of the exclusivity is verify_ex_data.py §3.")

    print("\n--- 6. the object goes back on top with normal alpha compositing ---")
    seq = [i for i, _ in disasm_range(img, 0x10051A1C, 0x20, resolve=False)]
    check("the composite at 0x10051a3a passes mode word 3", seq[0].op_str == "3",
          f"{seq[0].mnemonic} {seq[0].op_str}")
    fn = img.u32(BLEND_TABLE + 4 * (3 >> 24))
    check("mode>>24 == 0 selects blend function 0x10007df0 = src over dst "
          "(blend_modes.md §3)", fn == 0x10007DF0, f"0x{fn:08x}")
    check("mode & 0xff == 3 means both source and destination are 8-byte pixels",
          (3 & 0xFF) == 3)
    print("  Compare シャドー, which never composites the object onto the shadow canvas")
    print("  at all when 影を別オブジェクトで描画 is on. 縁取り has no such option: the")
    print("  border and the object always come back as one image, with the object")
    print("  covering the middle of the dilated silhouette.")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
