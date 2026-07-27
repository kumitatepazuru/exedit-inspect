"""Raw capstone disassembly of 境界ぼかし's func_proc, from entry through the
two exec_multi_thread_func dispatch calls.

This is the whole function - 境界ぼかし has no separate worker-selection
dispatcher the way ぼかし/発光 do (see inspect/blur, inspect/luminous); func_proc
itself computes the two radii, clamps them, and picks one of two worker pairs
based on the `透明度の境界をぼかす` checkbox.

What this pins down that decompile_boundary_blur.py's angr output leaves
ambiguous:

  * the radius formula reuses ぼかし's exact magic-number divide-by-1000
    sequence (0x10624dd3 imul + sar 6 + sign fix) - same compiler, same
    constant, so verify_radius_clamp.py's exhaustive check can reuse
    ぼかし's `magic_div_1000` verbatim,
  * the radii are clamped independently to (width/2, height/2) computed from
    *(fpip+0xB4)/*(fpip+0xB8) - unlike ぼかし there is no further hi/lo split
    and no canvas growth of any kind (no calls into exedit's offscreen
    helper table at all), and
  * exec_multi_thread_func's args for the FIRST worker of each pair are
    pushed once and shared with the second call (`push edi; push esi` at
    0x10011ba5/ba6, reused by both `call [.+0xcc]`), which is why
    decompile_boundary_blur.py's angr output renders the first call with no
    visible arguments - they are not missing, just stack-shared.

Run via main.py:
    uv run main.py inspect/boundary_blur/disasm_params.py
"""

from tools.disasm import dump_range
from tools.pe_image import PEImage

FUNC_PROC = (0x10011B00, 0x126)

ANNOTATIONS = {
    0x10011B01: "esi = fp   (2nd param, fpip, is read into edi later at 0x10011b5c once its stack slot is known)",
    0x10011B05: "eax = fp->track   (FILTER+0x44)",
    0x10011B08: "edx = track[0] = 範囲 raw",
    0x10011B0C: "範囲 == 0 -> skip straight to the two exec_multi_thread_func calls with rx=ry=0",
    0x10011B12: "eax = track[1] = 縦横比 raw",
    0x10011B1B: "縦横比 <= 0 ? -> 0x10011b3e (ecx stays 範囲, i.e. this is the vertical/ry seed)",
    0x10011B1F: "--- 縦横比 > 0: shrink ecx (ry) ---",
    0x10011B24: "ecx = 1000 - 縦横比",
    0x10011B26: "0x10624dd3: same MSVC magic constant ぼかし uses for /1000 (disasm_params.py in inspect/blur)",
    0x10011B2B: "ecx = (1000 - 縦横比) * 範囲",
    0x10011B2E: "imul/sar 6 => (x * 0x10624dd3) >> 38, i.e. x / 1000",
    0x10011B35: "+ sign bit: truncate toward zero",
    0x10011B3A: "ecx = trunc(範囲 * (1000 - 縦横比) / 1000)   <- ry",
    0x10011B3E: "縦横比 >= 0 ? -> 0x10011b5c (both stay 範囲, ebx unset only when < 0 taken below)",
    0x10011B40: "--- 縦横比 < 0: shrink ebx (rx) ---",
    0x10011B4E: "same magic divide by 1000",
    0x10011B5A: "ebx = trunc(範囲 * (1000 + 縦横比) / 1000)   <- rx",
    0x10011B5C: "edi = fpip",
    0x10011B60: "g_1011ec4c = ebx  (rx, pre-clamp)",
    0x10011B66: "g_1011ec48 = ecx  (ry, pre-clamp)",
    0x10011B6C: "eax = *(fpip+0xB4)  = object canvas width [pixels]",
    0x10011B72: "cdq/sub/sar 1: eax = width / 2   (rounding-toward-zero halving, same idiom as blur's index[45]/2)",
    0x10011B79: "rx <= width/2 ? keep : clamp",
    0x10011B7B: "g_1011ec4c = width/2   (rx clamped)",
    0x10011B8B: "eax = *(fpip+0xB8) = object canvas height [pixels]",
    0x10011B94: "eax = height / 2",
    0x10011B98: "ry <= height/2 ? keep : clamp",
    0x10011B9A: "g_1011ec48 = height/2   (ry clamped)",
    0x10011BA2: "edx = fp->check   (FILTER+0x48)",
    0x10011BA7: "check[0] == 0 ?  (透明度の境界をぼかす UNCHECKED -> fall through to OFF path)",
    0x10011BAC: "--- OFF path: geometric rounded-corner erosion (sub_10011c30 / sub_10011db0) ---",
    0x10011BB4: "g_1011ec54 = 2*rx+1   (horizontal kernel width)",
    0x10011BB9: "g_1011ec50 = 2*ry+1   (vertical kernel width)",
    0x10011BBF: "edx = fp->exfunc",
    0x10011BC7: "exec_multi_thread_func(sub_10011c30, fp, fpip)  <- args are the edi/esi pushed just above",
    0x10011BD2: "exec_multi_thread_func(sub_10011db0, fp, fpip)",
    0x10011BE9: "--- ON path (check[0] != 0): real alpha box blur (sub_10012060 / sub_10012200) ---",
    0x10011BFF: "exec_multi_thread_func(sub_10012060, fp, fpip)",
    0x10011C0F: "exec_multi_thread_func(sub_10012200, fp, fpip)",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_range(PEImage(dll_path), *FUNC_PROC,
               label="func_proc: トラックバー -> radii -> worker dispatch",
               resolve=False, annotations=ANNOTATIONS)

    magic = 0x10624DD3
    print(
        "\n"
        "Summary (verified numerically in verify_radius_clamp.py):\n"
        "  rx = ry = 範囲\n"
        "  縦横比 > 0  -> ry = trunc(範囲 * (1000 - 縦横比) / 1000)\n"
        "  縦横比 < 0  -> rx = trunc(範囲 * (1000 + 縦横比) / 1000)\n"
        "  rx = min(rx, width  // 2)   (*(fpip+0xB4))\n"
        "  ry = min(ry, height // 2)   (*(fpip+0xB8))\n"
        "  no hi/lo split (unlike ぼかし), no canvas growth of any kind\n"
        "  check[0]==0 (unchecked, default) -> sub_10011c30/sub_10011db0 (geometric erosion)\n"
        "  check[0]!=0 (checked)            -> sub_10012060/sub_10012200 (real alpha box blur)\n"
        f"  magic constant 0x{magic:08x} = {magic}, same as ぼかし's /1000 (inspect/blur)\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
