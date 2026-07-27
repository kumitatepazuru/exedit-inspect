"""Annotated disassembly of 拡散光's func_proc (0x1001c330), which is where
both トラックバー values are turned into the numbers the workers actually use.

func_proc is small (0x3db bytes) and does five things, all visible in one
dump:

  1. 強さ -> a Q12 opacity, via the usual MSVC "multiply by 0x10624dd3 and
     shift" divide-by-1000. Checked numerically in verify_strength.py.
  2. 拡散 -> *two* radii, by multiplying by a single double constant and
     truncating. Checked in verify_radius_split.py.
  3. when this is the object effect and サイズ固定 is off: clamp 拡散 so the
     grown canvas still fits the buffer, and blank one row above each of the
     two object buffers. Checked in verify_canvas_growth.py.
  4. decide whether the canvas can be grown *by the blur workers themselves*
     or has to be grown up-front through exedit's own draw API.
  5. run two rounds of (vertical pass, horizontal pass + composite), one per
     radius, publishing the current radius through two globals.

The globals are worth naming once, because every worker reads them and
nothing else in exedit does (`tools.xrefs --addr 0x1011efdc` etc. shows all
references land inside 拡散光):

    g_1011efdc = strength     Q12 opacity from 強さ  (4096 = 100.0)
    g_1011efe4 = radius       radius of the round currently running
    g_1011efe0 = kernel width = 2*radius + 1

Run via main.py:
    uv run main.py inspect/diffusion_light/disasm_params.py
"""

from tools.disasm import dump_all
from tools.pe_image import PEImage

FUNC_PROC = (0x1001C330, 0x3DB)

ANNOTATIONS = {
    0x1001C336: "eax = fp->track",
    0x1001C339: "track[0] = 強さ  (raw 0..1000, shown as 0.0..100.0)",
    0x1001C33D: "強さ == 0 -> return TRUE without touching a pixel",
    0x1001C343: "raw << 12",
    0x1001C348: "0x10624dd3 = ceil(2**38/1000): MSVC's signed divide-by-1000",
    0x1001C34F: "sar 6 -> the 2**38 half of the magic",
    0x1001C358: "+1 when negative; raw >= 0 here so this never fires",
    0x1001C35F: "g_1011efdc = strength = trunc(raw*4096/1000); 4096 = fully opaque",
    0x1001C36A: "flag & 0x20 -> object effect (both registrations share this func_proc)",
    0x1001C36C: "ebp = track[1] = 拡散, used as a pixel count with no scaling at all",
    0x1001C374: "frame filter: no canvas to grow, skip straight to the radius split",
    0x1001C37A: "eax = fp->check",
    0x1001C37D: "check[0] = サイズ固定 (only exists on the object registration)",
    0x1001C385: "サイズ固定 on -> canvas stays put, skip the preamble",
    0x1001C38B: "ecx = w = *(fpip+0xB4)",
    0x1001C391: "edi = *(fpip+0xEC) = row stride in pixels, and the width limit",
    0x1001C39A: "w + 拡散*4 > stride ?  (4x the growth that really happens - a margin)",
    0x1001C3A2: "cdq/and 3/add: c_div(stride-w, 4), truncating toward zero",
    0x1001C3B1: "same clamp again against *(fpip+0xF0), the height limit",
    0x1001C3E3: "edi = *(fpip+0xAC), the current object image",
    0x1001C3EE: "step back one full row: this is buffer[-1], outside the image",
    0x1001C3F5: "blank (w+4*拡散) pixels there - the 'outside the object' source row",
    0x1001C40A: "and the same one row above *(fpip+0xB0), the spare buffer",
    0x1001C428: "second blank row written here",
    0x1001C431: "fild 拡散 (already clamped)",
    0x1001C435: "* 0.44722719141323786, which is exactly 1/2.236 (2.236 = sqrt(5) to 3dp)",
    0x1001C43B: "_ftol truncates toward zero -> r2, the smaller radius",
    0x1001C444: "r1 = 拡散 - r2, so r1 + r2 == 拡散 exactly",
    0x1001C446: "stash r2 in the (now dead) fpip argument slot",
    0x1001C464: "2*r1 vs w ...",
    0x1001C474: "... 2*r1 vs h ...",
    0x1001C47B: "... 2*r2 vs w ...",
    0x1001C47F: "... 2*r2 vs h: all four smaller -> the workers can grow the canvas alone",
    0x1001C485: "otherwise grow it up-front instead, through exedit's own draw table",
    0x1001C495: "eax = fp+0x64: not FILTER::hwnd but exedit's private API table (0x100a41e0)",
    0x1001C4AF: "and set サイズ固定 = 1 locally, so the fixed-size workers run below",
    0x1001C4B7: "table[0x48](buf, 0, 0, w+2R, h+2R, 0,0,0,0, mode=2): clear the new canvas",
    0x1001C4EC: "table[0x44](dst, R,R, src, 0,0, w,h, 0, 0x13000003): blit the image into it",
    0x1001C4FB: "swap *(fpip+0xAC) <-> *(fpip+0xB0)",
    0x1001C51E: "w += 2R",
    0x1001C524: "h += 2R",
    0x1001C52C: "g_1011efe4 = radius of round 1 = r1 (the LARGER radius runs first)",
    0x1001C532: "r1 == 0 -> skip round 1 completely",
    0x1001C53D: "g_1011efe0 = 2*r1 + 1 = kernel width",
    0x1001C55A: "サイズ固定 / pre-grown: vertical pass 0x1001d710",
    0x1001C56A: "growing: vertical pass 0x1001c710",
    0x1001C584: "h += 2r immediately after the vertical pass",
    0x1001C594: "frame filter: vertical pass 0x1001e4f0",
    0x1001C5AD: "サイズ固定 / pre-grown: horizontal pass + composite 0x1001dbd0",
    0x1001C5BC: "growing: horizontal pass + composite 0x1001cb10",
    0x1001C5DC: "w += 2r after the horizontal pass",
    0x1001C5E8: "swap: this round's output becomes the next round's input",
    0x1001C5F6: "frame filter: horizontal pass + composite 0x1001e770",
    0x1001C609: "g_1011efe4 = radius of round 2 = r2",
    0x1001C60F: "r2 == 0 -> skip round 2 (happens for every 拡散 <= 2)",
    0x1001C61A: "g_1011efe0 = 2*r2 + 1",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_all(img, {"func_proc": FUNC_PROC}, annotations=ANNOTATIONS)

    table = 0x100A41E0
    print(
        "\nThe two calls through fp+0x64 go to exedit's own function table at "
        f"0x{table:08x},\ninstalled into every effect struct at startup "
        "(0x100315a4: `mov [esi+0x64], ebx`).\nFILTER::hwnd nominally lives at "
        "+0x64; exedit never registers these structs with\nAviUtl, so it reuses "
        "the slot.\n"
    )
    for off in (0x44, 0x48):
        print(f"  [0x{table:08x}+0x{off:02x}] = 0x{img.u32(table + off):08x}")
    print(
        "\nNeither address is referenced anywhere else in the image "
        "(tools.xrefs), i.e. they\nare only ever reached through that table. "
        "Both start by testing bit 1 of their\nlast argument to pick 8 vs 6 "
        "bytes per pixel, and both fold a negative x/y into\nthe width/height - "
        "so the first eight arguments are (buf, x, y, ...) rectangles.\n"
        "\nParameter constants resolved above:\n"
        "  0x10624dd3 + sar 6 + sign fixup = signed divide by 1000\n"
        "  0x1009a468 = 0.44722719141323786 = 1/2.236 (the 拡散 split; see "
        "verify_radius_split.py)\n"
        "  0x10091ad8 = MSVC _ftol, i.e. truncation toward zero, not rounding\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
