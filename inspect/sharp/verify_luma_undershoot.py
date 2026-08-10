"""The negative-luma cleanup at the end of the combine worker, and the two
other places in exedit that use it.

An unsharp mask undershoots: next to a bright edge the darker side goes below
0. exedit does not simply clamp that to black. It runs

    y' >= 0            -> leave everything alone (no upper bound either)
    -1024 < y' < 0     -> cb *= (y'+1024)/1024 ; cr *= (y'+1024)/1024 ; y' = 0
    y' <= -1024        -> y' = cb = cr = 0

so the last quarter-stop of undershoot is spent desaturating the pixel instead
of clipping it. Clamping alone would leave a fully saturated colour sitting at
luma 0, which reads as a hard coloured fringe; this ramps the colour out as the
luma dives, and the pixel lands on true black rather than on "black with a
tint".

This is not シャープ's own invention. The identical sequence - same -1024
threshold, same `+0x400` then `sar 10` - appears in `色調補正` and in one of the
blend functions of the shared table `0x1009fbb0`. This script finds every
occurrence mechanically (both `cmp` encodings: the `0x81 /7` general form and
the `0x3d` eax short form), attributes each to its owner, dumps one site per
owner, and then tabulates the function itself.

Run via main.py:
    uv run main.py inspect/sharp/verify_luma_undershoot.py
"""

import re

from tools.cints import sar
from tools.disasm import dump_range
from tools.filter_table import walk
from tools.pe_image import PEImage

BLEND_TABLE = 0x1009FBB0
# cmp site -> (address of the `test` that starts the block, bytes to dump)
SITES = {
    0x10089C7E: ("シャープ combine worker, fast path", 0x10089C76, 0x30),
    0x10089D1E: ("シャープ combine worker, general path", 0x10089D1A, 0x2C),
}


def owners(img: PEImage):
    """(start, label) for every function this project can name."""
    out = [(r.func_proc, r.name) for r in walk(img)]
    for i in range(32):
        va = img.u32(BLEND_TABLE + 4 * i)
        out.append((va, f"blend table[0x{i:02x}]"))
    return sorted(set(out))


def attribute(table, va):
    best = None
    for a, n in table:
        if a <= va and (best is None or a > best[0]):
            best = (a, n)
    return f"{best[1]} +0x{va - best[0]:x}" if best else "?"


def cleanup(y, cb, cr):
    """0x10089c76-0x10089ca5 / 0x10089d1a-0x10089d3e."""
    if y >= 0:
        return y, cb, cr
    if y <= -1024:
        return 0, 0, 0
    return 0, sar(cb * (y + 1024), 10), sar(cr * (y + 1024), 10)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    table = owners(img)

    print("--- (1) every `cmp r32, -1024` in .text ---")
    found = []
    for sec in img.pe.sections:
        if sec.Name.rstrip(b"\x00") != b".text":
            continue
        base = img.image_base + sec.VirtualAddress
        blob = img.code(base, sec.Misc_VirtualSize)
        for pat in (rb"\x81[\xf8-\xff]\x00\xfc\xff\xff",   # cmp r32, imm32
                    rb"\x3d\x00\xfc\xff\xff"):             # cmp eax, imm32
            for m in re.finditer(pat, blob):
                found.append(base + m.start())
    for va in sorted(found):
        follow = img.code(va + (6 if img.u8(va) == 0x81 else 5), 8)
        has_add = re.search(rb"\x81[\xc0-\xc7]\x00\x04\x00\x00|\x05\x00\x04\x00\x00", follow)
        print(f"  0x{va:08x}  {attribute(table, va):<34s}"
              f"{'  + add r32,0x400 within 8 bytes' if has_add else ''}")
    print(f"  {len(found)} site(s); the ones in シャープ are "
          f"{[hex(a) for a in sorted(SITES)]}")
    print("""
  0x100081e0 is entry 0x02 of the blend function table 0x1009fbb0
  (blend_modes.md §3) - the one 加算 (0x11) and 通常 (0x00) sit beside, i.e.
  the subtractive blend, which undershoots for the same reason シャープ does.
  色調補正 gets there by lowering brightness/contrast past black.""")

    print("\n--- (2) the two copies inside シャープ, side by side ---")
    for label, start, size in SITES.values():
        dump_range(img, start, size, label=label, resolve=False)
    print("""
  Same constants, same order, only the register allocation differs; the fast
  path additionally reloads edx (the scratch pointer) afterwards because the
  general path clobbered it. 色調補正's copy adds an upper clamp at 0x2000
  right after (`cmp esi, 0x2000` at 0x10014f49) - シャープ has no upper clamp
  at all.""")

    print("\n--- (3) the function itself ---")
    print("      y'      out.y   chroma scale   (cb,cr) = (2048, -1024) becomes")
    for y in (256, 0, -1, -128, -256, -512, -768, -1023, -1024, -2000):
        oy, ocb, ocr = cleanup(y, 2048, -1024)
        scale = "1" if y >= 0 else ("0" if y <= -1024 else f"{(y + 1024) / 1024:.3f}")
        print(f"    {y:7d} {oy:8d}   {scale:<14s} ({ocb}, {ocr})")
    print("""
  The ramp is linear in the luma and one quarter of full scale wide, so a
  pixel that undershoots by 25% or more of the range comes out pure black.
  Note the asymmetry: nothing similar happens on the bright side. Overshoot is
  passed through unbounded and only clipped when aviutl.exe converts to RGB
  (rgb_ycbcr.md §3), which is why シャープ's halos are much more visible on the
  light side of an edge than on the dark side.""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
