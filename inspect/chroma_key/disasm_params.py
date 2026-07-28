"""func_proc, annotated instruction by instruction.

クロマキー's func_proc is unusually small - it never touches a pixel. All it
does is

  1. bail out unless `ex_data.status == 1` (a key colour has been picked),
  2. write five globals describing the two-or-three scratch maps and the
     border-correction radius,
  3. fire one `exec_multi_thread_func` call, or three of them, depending on the
     two checkboxes.

The two trackbars that shape the key (`色相範囲`, `彩度範囲`) are *not* passed
through globals; every worker reads `fp->track[]` itself. That is why the
parameter conversion appears once per worker rather than once in func_proc, and
why the second dump below is a worker prologue rather than more of func_proc.

The annotations are the claims; the instructions beside them are the evidence.

Run via main.py:
    uv run main.py inspect/chroma_key/disasm_params.py
"""

from tools.disasm import dump_all
from tools.pe_image import PEImage

FUNC_PROC = (0x10012DE0, 0x130)

# The parameter conversion, as it appears in the simplest worker. The same
# eleven instructions appear in 0x100130b0 / 0x10013340 / 0x10013500 with only
# the stack slots renumbered.
WORKER_PARAMS = (0x10012F3E, 0x7C)

ANNOTATIONS = {
    # ---- func_proc -----------------------------------------------------
    0x10012DE1: "esi = fp",
    0x10012DE5: "fp->ex_data_ptr (+0x4c)",
    0x10012DE8: "ex_data.status (+8) != 1 ?",
    0x10012DEC: "  -> return TRUE without touching a pixel. 0 = no key colour",
    0x10012DF2: "fp->track (+0x44)",
    0x10012DF6: "track[2] = 境界補正",
    0x10012DFB: "  == 0 -> the single-pass path at 0x10012ec8",
    0x10012E01: "edi = fpip",
    0x10012E05: "push fpip / push fp: the two extra args every worker call below shares",
    0x10012E07: "*(fpip+0xB0) = the pair buffer ...",
    0x10012E0D: "... becomes scratch map A (2 bytes per pixel)",
    0x10012E13: "*(fpip+0xEC) = row stride in pixels",
    0x10012E19: "* *(fpip+0xB8) = h  -> stride*h pixels",
    0x10012E26: "map B starts one whole 16-bit map past map A ...",
    0x10012E29: "... so the pair buffer holds both: 4 of its 8 bytes per pixel",
    0x10012E35: "g_1011ec8c = r = 境界補正",
    0x10012E3A: "kernel width = 2r+1 ...",
    0x10012E3E: "... g_1011ec88. The box-blur pair every effect in this repo uses",
    0x10012E44: "fp->check (+0x48)",
    0x10012E47: "check[0] = 色彩補正",
    0x10012E4A: "  == 0 -> the two-map path at 0x10012e8f",
    0x10012E4C: "色彩補正 needs a third map: borrow the shared scratch 0x101a5328",
    0x10012E51: "worker 1/3: build the key-distance map (+ the hue-only map)",
    0x10012E69: "worker 2/3: vertical box average of the map, in place-ish A<-B",
    0x10012E79: "worker 3/3: horizontal box average + apply to the image",
    0x10012E84: "3 calls x 3 args = 9 dwords",
    0x10012E92: "same three passes without the hue-only map",
    0x10012EA2: "pass 2 is shared by both 境界補正 paths - it only sees the map",
    0x10012EB2: "pass 3 differs: 0x10013880 has no hue map to read",
    0x10012EC8: "境界補正 == 0: no map, no blur, one worker over the image",
    0x10012ECB: "check[0] = 色彩補正 again",
    0x10012ED9: "色彩補正 on  -> 0x100130b0 (alpha + chroma + 透過補正)",
    0x10012EF8: "色彩補正 off -> 0x10012f10 (alpha only)",
    0x10012F07: "every path returns TRUE",
    # ---- the key parameters, computed per worker ------------------------
    0x10012F3E: "ex_data.color_yc.cr (+4)   <- the picked colour ...",
    0x10012F42: "ex_data.color_yc.cb (+2)   <- ... only its chroma, never its y",
    0x10012F53: "st0 = cr",
    0x10012F57: "st0 = cb, st1 = cr",
    0x10012F5B: "fpatan -> atan2(cr, cb): the key's hue angle in the Cb-Cr plane",
    0x10012F61: "x 65536/(2*pi): the angle becomes a 16-bit binary turn",
    0x10012F67: "_ftol - truncate toward zero. key_hue is now an integer",
    0x10012F73: "abs(cr) ...",
    0x10012F7C: "... abs(cb) ...",
    0x10012F80: "... key_sat = max of the two: a Chebyshev norm, not a Euclidean one",
    0x10012F94: "fp->track: the worker reads the trackbars itself",
    0x10012F97: "track[0] = 色相範囲",
    0x10012F99: "track[1] = 彩度範囲",
    0x10012F9C: "彩度範囲 * key_sat ...",
    0x10012FA1: "... >> 8: sat_range is a *fraction of the key's own saturation*",
    0x10012FAC: "hue_range = 色相範囲 << 7 (256 -> 32768 = half a turn = everything)",
    0x10012FB5: "row loop: y from thread_id*h/thread_num",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_all(img, {
        "func_proc 0x10012de0": FUNC_PROC,
        "key parameters, as computed inside worker 0x10012f10": WORKER_PARAMS,
    }, annotations=ANNOTATIONS)

    print(
        "\n"
        "The five globals func_proc writes, and who reads them:\n"
        "  g_1011ec7c  scratch map A = *(fpip+0xB0)                pass 2 writes, pass 3 reads\n"
        "  g_1011ec80  scratch map B = map A + 2*stride*h          pass 1 writes, passes 2/3 read\n"
        "  g_1011ec84  scratch map C = the shared buffer 0x101a5328  pass 1 writes, pass 3 reads\n"
        "              (only allocated when 色彩補正 is on)\n"
        "  g_1011ec88  kernel width 2r+1                           passes 2 and 3\n"
        "  g_1011ec8c  r = 境界補正                                 passes 2 and 3\n"
        "\n"
        "Both 16-bit maps live inside the pair buffer *(fpip+0xB0), which is 8 bytes\n"
        "per pixel - two 2-byte maps fit in the first half of it. The effect is\n"
        "otherwise fully in place on *(fpip+0xAC): the buffers are never swapped, the\n"
        "canvas never grows, and there is no frame-filter registration to branch on.\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
