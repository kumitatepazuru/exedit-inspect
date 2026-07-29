"""func_proc and the key worker, annotated instruction by instruction.

カラーキー's func_proc is the smallest in this repository - 40 instructions,
no pixel loop, no arithmetic beyond `2r+1`:

  1. bail out unless `ex_data.status == 1` (a key colour has been picked),
  2. fire the key worker,
  3. if `境界補正 != 0`, write two globals (`r` and `2r+1`) and fire three more
     workers - the first of which is **the key worker again**.

Everything that decides which pixels disappear is in the worker prologue, which
is the second dump below. It reads `ex_data.color_yc` and `fp->track[0..1]` and
turns them into six plain integer bounds:

    ymin  = key.y  - 輝度範囲      ymax  = key.y  + 輝度範囲
    cbmin = key.cb - 色差範囲      cbmax = key.cb + 色差範囲
    crmin = key.cr - 色差範囲      crmax = key.cr + 色差範囲

There is no scaling, no fixed point and no floating point anywhere in the
chain: the trackbars are compared against PIXEL_YC fields in their own units.

The annotations are the claims; the instructions beside them are the evidence.

Run via main.py:
    uv run main.py inspect/color_key/disasm_params.py
"""

from tools.disasm import dump_all
from tools.pe_image import PEImage

FUNC_PROC = (0x100162C0, 0x79)
KEY_WORKER = (0x10016340, 0xE4)

ANNOTATIONS = {
    # ---- func_proc ------------------------------------------------------
    0x100162C1: "esi = fp",
    0x100162C5: "fp->ex_data_ptr (+0x4c)",
    0x100162C8: "ex_data.status (+8) != 1 ?",
    0x100162CC: "  -> return TRUE without touching a pixel. 0 = no key colour yet",
    0x100162CE: "fp->exfunc (+0x60), the EXFUNC* exedit patches in at startup",
    0x100162D2: "edi = fpip",
    0x100162D8: "worker 0x10016340 = the key test. Fired unconditionally",
    0x100162DD: "exfunc->exec_multi_thread_func (+0xCC)",
    0x100162E3: "fp->track (+0x44)",
    0x100162E9: "track[2] = 境界補正",
    0x100162EE: "  == 0 -> done. The whole effect was that one worker",
    0x100162F0: "g_1011ed38 = r = 境界補正",
    0x100162F5: "kernel width 2r+1 ...",
    0x100162F9: "... g_1011ed34. The box-blur pair every effect in this repo uses",
    0x10016303: "the SAME worker again - see verify_dispatch.py. Idempotent, so this",
    0x10016308: "  costs one extra full-image pass and changes nothing",
    0x10016313: "worker 2: vertical box average of the alpha, *(fpip+0xAC) -> *(fpip+0xB0)",
    0x10016323: "worker 3: horizontal box average + the stretch, applied back to the image",
    0x1001632E: "3 calls x 3 args = 9 dwords, cleaned in one go",
    0x10016332: "every path returns TRUE",
    # ---- the key worker -------------------------------------------------
    0x1001634E: "*(fpip+0xB8) = h",
    0x1001635C: "y1 = (thread_id+1) * h / thread_num",
    0x10016364: "arg2 = fp",
    0x10016367: "ex_data.color_yc.y (+0) - and unlike クロマキー this one IS used",
    0x10016370: "fp->track: the worker reads the trackbars itself",
    0x10016373: "track[0] = 輝度範囲",
    0x10016375: "track[1] = 色差範囲: ONE range shared by both chroma axes",
    0x10016378: "ymin = key.y - 輝度範囲",
    0x1001637A: "ymax = key.y + 輝度範囲",
    0x1001637C: "ex_data.color_yc.cb (+2)",
    0x10016380: "ex_data.color_yc.cr (+4)",
    0x1001638A: "cbmax = key.cb + 色差範囲",
    0x1001638C: "cbmin = key.cb - 色差範囲",
    0x10016394: "crmin = key.cr - 色差範囲",
    0x10016396: "crmax = key.cr + 色差範囲",
    0x100163A2: "y0 = thread_id * h / thread_num - the split is by row",
    0x100163B0: "empty row range (h < thread_num) -> return",
    0x100163B6: "*(fpip+0xEC) = row stride in pixels",
    0x100163BC: "*(fpip+0xAC) = the object buffer. No flag&0x20 branch: object only",
    0x100163C7: "8 bytes per pixel (PIXEL_YCA)",
    0x100163CA: "*(fpip+0xB4) = w",
    0x100163D4: "pixel y",
    0x100163D7: "y < ymin -> keep",
    0x100163DB: "y > ymax -> keep. Both bounds are INCLUSIVE",
    0x100163E1: "pixel cb",
    0x100163E5: "cb < cbmin -> keep",
    0x100163E9: "cb > cbmax -> keep",
    0x100163EF: "pixel cr",
    0x100163F3: "cr < crmin -> keep",
    0x100163F9: "cr > crmax -> keep",
    0x100163FF: "inside all three intervals: alpha = 0. The only write in the worker, and",
    0x10016405: "  it is an unconditional 0 - there is no soft edge anywhere in this path",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_all(img, {
        "func_proc 0x100162c0": FUNC_PROC,
        "the key worker 0x10016340": KEY_WORKER,
    }, annotations=ANNOTATIONS)

    print(
        "\n"
        "The two globals func_proc writes, and who reads them:\n"
        "  g_1011ed38  r = 境界補正         passes 2 and 3\n"
        "  g_1011ed34  kernel width 2r+1    passes 2 and 3\n"
        "\n"
        "That is the whole of the shared state. クロマキー needs five globals because\n"
        "it builds 16-bit mattes in scratch buffers; カラーキー needs two because its\n"
        "matte IS the pixel alpha - the key worker has already written it into\n"
        "*(fpip+0xAC), and the border passes read it back from there.\n"
        "\n"
        "The effect is fully in place on *(fpip+0xAC). The pair buffer *(fpip+0xB0) is\n"
        "used by 境界補正 as a one-pass scratch (its alpha field only, y/cb/cr are\n"
        "left as they were), the buffers are never swapped, the canvas never grows,\n"
        "and there is no frame-filter registration to branch on.\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
