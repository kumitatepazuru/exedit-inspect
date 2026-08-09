"""func_proc, annotated instruction by instruction.

エッジ抽出's func_proc is one of the smallest in the binary - 0xc9 bytes, and it
never touches a pixel. All it does is

  1. convert the two trackbars into Q12 fixed point and park them in two
     globals (`強さ` /1000, `しきい値` /10000 - two *different* magic divisors),
  2. decompose `色の設定` into Y/Cb/Cr through the shared `0x1006fed0`,
  3. fire exactly one `exec_multi_thread_func` call, picked by the two
     checkboxes,
  4. swap `*(fpip+0xAC)` with `*(fpip+0xB0)`, because the workers wrote the
     result into the pair buffer rather than in place.

There is no early return, no canvas growth, no `flag & 0x20` branch (only one
registration exists) and no `サイズ固定`. The five globals are the entire
interface to the workers, which read neither `fp` nor `fp->track[]`.

The annotations are the claims; the instructions beside them are the evidence.

Run via main.py:
    uv run main.py inspect/edge_extraction/disasm_params.py
"""

from tools.disasm import dump_all
from tools.pe_image import PEImage

FUNC_PROC = (0x10022D60, 0xD0)

ANNOTATIONS = {
    0x10022D61: "esi = fp",
    0x10022D66: "fp->track (+0x44)",
    0x10022D69: "edi = fp->ex_data_ptr (+0x4c)",
    0x10022D6C: "track[0] = 強さ",
    0x10022D6E: "0x10624dd3: the /1000 magic every effect uses (param_scaling.md)",
    0x10022D73: "強さ * 4096 ...",
    0x10022D78: "... sar 6 -> /1000. raw 1000 (UI 100.0) = 4096 = x1.0",
    0x10022D7D: "a *different* magic for the second trackbar ...",
    0x10022D87: "g_10134e74 = strength, Q12. Read by all three workers, nowhere else",
    0x10022D90: "track[1] = しきい値",
    0x10022D93: "しきい値 * 4096 ...",
    0x10022D98: "... 0x68db8bad + sar 12 = /10000, not /1000 (verify_param_scaling.py)",
    0x10022DA2: "g_10134e6c = threshold, Q12, signed. raw 10000 (UI 100.00) = 4096",
    0x10022DA8: "ex_data dword[0] = 0x00RRGGBB ...",
    0x10022DAB: "... sub_1006fed0(Y*, Cb*, Cr*, colour) - shared with 発光/閃光/グロー",
    0x10022DB5: "Y -> 0x10134e78, Cb -> 0x10134e70, Cr -> 0x10134e72",
    0x10022DBF: "eax = fp->check (+0x48)",
    0x10022DC2: "edi = fpip",
    0x10022DC9: "check[0] = 輝度エッジを抽出",
    0x10022DCB: "push fpip / push fp: the two extra args every worker call shares",
    0x10022DCD: "  != 0 -> the luminance worker, whatever check[1] says",
    0x10022DD1: "fp->exfunc (+0x60)",
    0x10022DD4: "worker 0x100234c0: gradient of y*a, one sqrt",
    0x10022DD9: "EXFUNC::exec_multi_thread_func (+0xCC)",
    0x10022DE1: "check[1] = 透明度エッジを抽出",
    0x10022DEB: "worker 0x10023880: gradient of a alone, one sqrt, no premultiply",
    0x10022DFB: "both off -> worker 0x10022e30: y, cb, cr each get their own sqrt",
    0x10022E06: "eax = *(fpip+0xB0), the pair buffer the worker just wrote",
    0x10022E0C: "edx = *(fpip+0xAC), the input",
    0x10022E15: "swap them: the edge image becomes the object ...",
    0x10022E1B: "... so the original pixels are gone. This effect replaces, never blends",
    0x10022E21: "return TRUE. No early return exists anywhere in func_proc",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_all(img, {"func_proc 0x10022d60": FUNC_PROC}, annotations=ANNOTATIONS)

    print(
        "\n"
        "The five globals func_proc writes, and who reads them:\n"
        "  g_10134e6c  しきい値 T, Q12 signed   subtracted from the magnitude, once per pixel\n"
        "  g_10134e70  colour Cb (word)         written verbatim into every output pixel\n"
        "  g_10134e72  colour Cr (word)         同上\n"
        "  g_10134e74  強さ, Q12 unsigned       multiplies (magnitude - T)\n"
        "  g_10134e78  colour Y (word)          同上\n"
        "\n"
        "`uv run main.py tools.xrefs --addr 0x10134e74` shows every reference to each of\n"
        "them lands inside 0x10022d60..0x10023ae5, i.e. inside エッジ抽出.\n"
        "\n"
        "Note what is *not* here: no `test .., 0x20` (there is only one registration,\n"
        "the object-effect one), no canvas growth, no early return on 強さ == 0, and no\n"
        "read of `ex_data` bit24 - エッジ抽出's ex_data has no `no_color` field at all\n"
        "(verify_ex_data.py).\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
