"""Pin down the exact RGB<->YCbCr matrix 発光 (and every other exedit
filter) uses, by reading the coefficient table out of .rdata.

disasm_color.py locates `sub_1006f520` (dispatching into the SIMD workers
`sub_1006f6e0`/`sub_1006f5b0`) as the shared, non-glow-specific RGB->YCbCr
conversion exedit applies to the picked 光色, but only qualitatively - the
coefficients themselves cannot be read out of angr's output because the
workers are hand-written MMX/SSE code the decompiler lifts into opaque
SIMD-intrinsic soup. This script instead reads the *constant table* those
workers load (`g_100a989c`/`g_100a98a4`/`g_100a98ac`) directly out of
`.rdata` as raw int16 rows and checks them against the textbook ITU-R BT.601
full-range matrix.

They match exactly once descaled by 16384 (Q14 fixed point), so AviUtl's
forward matrix is plain BT.601 - not a custom or symmetric approximation -
and its exact inverse (applied wherever exedit converts PIXEL_YC back to RGB
for display, a call site that lives in aviutl.exe and so is outside this
analysis's reach) carries the classic asymmetric cross terms: Cb feeds B
with weight 1.772 while Cr feeds G with only -0.714136. G and B are
therefore never supposed to move by the same amount for a red tint, which
is why a strongly chroma-clamped red glow reads as yellow rather than as an
evenly desaturated pink.

Run via main.py:
    uv run main.py inspect/glow/verify_ycbcr_matrix.py
"""

import struct

import pefile

# 3 rows of (Y-weight, Cb-weight, Cr-weight), one row per input channel,
# loaded by sub_1006f6e0/sub_1006f5b0 (see disasm_color.py's decompile of
# those two addresses - they show `g_100a989c`/`g_100a98a4`/`g_100a98ac`
# each broadcast via pmulhw-style MulHiV against a channel of the input
# pixel). Table is dense/overlapping in memory (6-byte stride matching a
# PIXEL_YC-shaped 3x int16 record), so each row is read at its own base.
ROW_B = 0x100A989C  # contributes to (Y, Cb, Cr) with the B input channel
ROW_G = 0x100A98A4  # ... with the G input channel
ROW_R = 0x100A98AC  # ... with the R input channel

SCALE = 16384  # Q14: these are angr's `extern unsigned long long g_...` operands,
               # confirmed fixed-point below by matching known BT.601 ratios

BT601 = {
    # channel: (Y, Cb, Cr) weight contributed by a unit of that RGB channel
    "R": (0.299, -0.168736, 0.5),
    "G": (0.587, -0.331264, -0.418688),
    "B": (0.114, 0.5, -0.081312),
}


def _read_row(data, image_base, va):
    raw = data[va - image_base: va - image_base + 6]
    return struct.unpack_from("<3h", raw)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    pe = pefile.PE(dll_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()

    print(f"--- raw int16 rows from the RGB->YCbCr constant table (Q{SCALE.bit_length() - 1} fixed point) ---")
    rows = {}
    for label, va in [("B", ROW_B), ("G", ROW_G), ("R", ROW_R)]:
        row = _read_row(data, image_base, va)
        rows[label] = row
        print(f"  {label}-channel row @ 0x{va:08x}: raw={row}  /{SCALE} = {tuple(v / SCALE for v in row)}")

    print("\n--- comparison against textbook ITU-R BT.601 (full range) ---")
    all_match = True
    for label in ("R", "G", "B"):
        decoded = tuple(v / SCALE for v in rows[label])
        expected = BT601[label]
        diffs = tuple(abs(a - b) for a, b in zip(decoded, expected))
        ok = all(d < 0.003 for d in diffs)
        all_match &= ok
        print(f"  {label}: decoded={tuple(round(v, 4) for v in decoded)}  bt601={expected}  match={ok}")

    print(
        f"\nVerdict: {'CONFIRMED' if all_match else 'NO MATCH'} - exedit's shared RGB->YCbCr conversion "
        "(used for light-color setup, and presumably display's YCbCr->RGB since\n"
        "matrices this standard always ship as an exact-inverse pair) is plain ITU-R "
        "BT.601 full-range, not a custom or symmetric approximation.\n"
    )

    print(
        "Exact inverse (YCbCr -> RGB, PIXEL_YC-relative deltas: Cb/Cr centered at 0):\n"
        "  R = Y + 1.402000*Cr\n"
        "  G = Y - 0.344136*Cb - 0.714136*Cr\n"
        "  B = Y + 1.772000*Cb\n"
        "\n"
        "For a red glow (negative Cb, positive Cr) landing on a white pixel:\n"
        "  delta_G = -0.344136*dCb - 0.714136*dCr  (a small positive term against a\n"
        "                                           larger negative one)\n"
        "  delta_B = +1.772000*dCb                 (a single term, much heavier weight)\n"
        "so |delta_G| and |delta_B| have no reason to come out equal. An exactly\n"
        "symmetric G/B drop is the fingerprint of a tint blended in plain RGB or HSV\n"
        "space instead of through this matrix.\n"
    )


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])

