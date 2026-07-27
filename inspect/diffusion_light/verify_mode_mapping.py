"""Which of the three worker pairs runs, and what each one reads and writes.

拡散光 is registered twice with a single shared func_proc, and func_proc picks
between *three* pairs of workers on two bits: `fp->flag & 0x20` (object effect
vs frame filter) and, on the object side, `fp->check[0]` (サイズ固定).

Guessing which registration is which from the flag alone would be circular,
so this script reads it off the code instead. Each worker's prologue names the
struct fields it indexes and the byte stride it walks, and those two facts are
enough to tell the modes apart without any assumption:

  * `*(fpip+0xB4)/(0xB8)` with an 8-byte pixel stride is exedit's object
    buffer pair (PIXEL_YCA: y, cb, cr, a) - only an object effect has alpha.
  * `fpip->w/h` (+0xC/+0x10) with a 6-byte stride is AviUtl's own
    FILTER_PROC_INFO frame (PIXEL_YC, no alpha).

Each pair is (vertical, horizontal). The split of work across threads is what
says which is which: the vertical worker divides `w` between threads (one
column range each) and walks down by one stride per step, the horizontal one
divides `h` and walks along by one pixel.

The third distinction - サイズ固定 - matters more than it looks, because the
"growing" pair does not just produce a bigger image, it also normalises the
box average differently at the edges (verify_box_average.py) and needs a
blank source row above the buffer (verify_canvas_growth.py).

Run via main.py:
    uv run main.py inspect/diffusion_light/verify_mode_mapping.py
"""

from tools.disasm import dump_all
from tools.filter_table import find, summarize
from tools.pe_image import PEImage

DISPATCH = (0x1001C543, 0xD4)

WORKER_HEADS = {
    "0x1001c710  object, growing: vertical": (0x1001C710, 0x78),
    "0x1001cb10  object, growing: horizontal + composite": (0x1001CB10, 0x88),
    "0x1001d710  object, サイズ固定: vertical": (0x1001D710, 0x74),
    "0x1001dbd0  object, サイズ固定: horizontal + composite": (0x1001DBD0, 0x88),
    "0x1001e4f0  frame filter: vertical": (0x1001E4F0, 0x68),
    "0x1001e770  frame filter: horizontal + composite": (0x1001E770, 0x78),
}

ANNOTATIONS = {
    # --- dispatch, round 1 (the second round at 0x1001c61f is the same tree)
    0x1001C543: "fp->flag",
    0x1001C545: "& 0x20 -> object effect?",
    0x1001C548: "no: frame filter",
    0x1001C54A: "yes: サイズ固定 (or 'already grown up-front', see verify_canvas_growth.py)",
    0x1001C55A: "exec_multi_thread_func(0x1001d710) - fixed-size vertical",
    0x1001C56A: "exec_multi_thread_func(0x1001c710) - growing vertical",
    0x1001C584: "the growing pair is the only one that changes h here",
    0x1001C594: "exec_multi_thread_func(0x1001e4f0) - frame vertical",
    0x1001C5AD: "0x1001dbd0 - fixed-size horizontal",
    0x1001C5BC: "0x1001cb10 - growing horizontal",
    0x1001C5DC: "... and w",
    0x1001C5E8: "... and swaps the two object buffers",
    0x1001C5F6: "0x1001e770 - frame horizontal",
    # --- object, growing
    0x1001C71A: "*(fpip+0xB8) = h",
    0x1001C724: "*(fpip+0xB4) = w  <- work is split over w: one column range per thread",
    0x1001C73A: "start/end column = thread_id*w/thread_num",
    0x1001C73C: "*(fpip+0xEC) = row stride in pixels",
    0x1001C76C: "read from *(fpip+0xAC)",
    0x1001C772: "write to *(fpip+0xB0)",
    0x1001C77A: "src + column*8 -> 8 bytes per pixel: PIXEL_YCA, this side has alpha",
    0x1001C784: "dst + (kernel_width + column)*8: shifted right, see verify_canvas_growth.py",
    0x1001CB23: "*(fpip+0xB4) = w",
    0x1001CB29: "*(fpip+0xB8) = h  <- split over h: one row range per thread",
    0x1001CB85: "read from *(fpip+0xB0) ...",
    0x1001CB8F: "... at column kernel_width ...",
    0x1001CB92: "... and write back into *(fpip+0xB0) at column 0: in place",
    # --- object, fixed size
    0x1001D724: "w again: vertical, one column range per thread",
    0x1001D770: "read *(fpip+0xAC)",
    0x1001D776: "write *(fpip+0xB0)",
    0x1001D77F: "same column in both - no shift, because the horizontal pass below",
    0x1001D781: "reads a different buffer than it writes",
    0x1001DBE9: "h: horizontal, one row range per thread",
    0x1001DC3F: "read the blurred image from *(fpip+0xB0) ...",
    0x1001DC45: "... and composite into *(fpip+0xAC), which is still the original",
    # --- frame filter
    0x1001E4FD: "fpip->h (+0x10)",
    0x1001E502: "fpip->w (+0xC)  <- vertical",
    0x1001E516: "fpip->max_w (+0x14) = row stride",
    0x1001E52F: "column*6 -> 6 bytes per pixel: PIXEL_YC, no alpha channel at all",
    0x1001E54D: "read fpip->ycp_edit (+4)",
    0x1001E550: "write fpip->ycp_temp (+8)",
    0x1001E783: "fpip->w",
    0x1001E786: "fpip->h  <- horizontal",
    0x1001E7D4: "read the blurred image from ycp_temp ...",
    0x1001E7D7: "... and composite into ycp_edit in place",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    regs = find(img, "拡散光")
    for r in regs:
        checks = ", ".join(f"{n!r}" for n in r.check_names) or "(none)"
        print(f"[{r.index}] struct=0x{r.struct_va:08x} flag=0x{r.flag:08x} "
              f"func_proc=0x{r.func_proc:08x}  {r.role}  checkboxes: {checks}")
    summarize(regs, "拡散光")

    dump_all(img, {"func_proc: worker dispatch, round 1": DISPATCH, **WORKER_HEADS},
             annotations=ANNOTATIONS)

    print(
        "\n"
        "Verdict:\n"
        "  flag=0x20 (object effect)   8-byte PIXEL_YCA in *(fpip+0xAC)/*(fpip+0xB0),\n"
        "                              size in *(fpip+0xB4)/*(fpip+0xB8),\n"
        "                              stride *(fpip+0xEC), limits *(fpip+0xEC)/(0xF0)\n"
        "      サイズ固定 off ->  0x1001c710 / 0x1001cb10   canvas grows by 2r per round\n"
        "      サイズ固定 on  ->  0x1001d710 / 0x1001dbd0   canvas fixed\n"
        "  flag=0x00 (frame filter)    6-byte PIXEL_YC in ycp_edit/ycp_temp,\n"
        "                              size fpip->w/h, stride fpip->max_w\n"
        "                          ->  0x1001e4f0 / 0x1001e770   (no サイズ固定 to have)\n"
        "\n"
        "Both object pairs write their blurred intermediate into the *other* buffer and\n"
        "composite it back against the original; the frame pair does the same through\n"
        "ycp_temp. Nothing in any of the six reads fp->track or fp->check - the two\n"
        "parameters reach them only through the three globals func_proc writes.\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
