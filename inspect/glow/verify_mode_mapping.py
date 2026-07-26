"""Pin down which of func_proc's two branches is the object-effect path and
which is the frame(video)-filter path, by the buffers each one touches.

Everything downstream in this filter is selected by `fp->flag & 0x20`
(extraction worker, vertical blur worker, final composite), so getting this
mapping backwards silently mislabels half the analysis. Rather than guessing
from the registration flags, this script reads the branch itself and reports
which struct fields each side uses:

  flag & 0x20 SET   -> image = *(fpip+0xAC), line width = *(fpip+0xEC),
                       w/h = *(fpip+0xB4)/*(fpip+0xB8), stride 8 bytes/pixel
                       (PIXEL_YCA: y, cb, cr, a - alpha at +6)
  flag & 0x20 CLEAR -> image = fpip->ycp_edit (+4), scratch = ycp_temp (+8),
                       w/h = fpip->w (+0xC) / fpip->h (+0x10),
                       stride 6 bytes/pixel (PIXEL_YC, no alpha)

An 8-byte-per-pixel buffer with an alpha channel is exedit's own object
image; FILTER_PROC_INFO's ycp_edit/ycp_temp are AviUtl's frame buffers. So
the flag&0x20 side - the registration that also owns the `サイズ固定`
checkbox, because an object's canvas has to grow when the glow spills past
its bounding box - is the object-effect path.

Run via main.py:
    uv run main.py inspect/glow/verify_mode_mapping.py
"""

import capstone
import pefile

FUNC_PROC = (0x10053100, 0x2C0)

# Instruction addresses worth calling out, with what they establish.
ANNOTATIONS = {
    0x100531B3: "al = fp->flag",
    0x100531BB: "test al, 0x20",
    0x100531BD: "je -> 0x1005323b (flag&0x20 CLEAR = frame-filter path)",
    0x100531BF: "--- flag&0x20 SET path (object effect) starts here ---",
    0x100531C2: "ecx = fp->check[1] (size-fixed checkbox)",
    0x100531CB: "call exedit's offscreen-draw helper (only when size-fixed is off)",
    0x100531DF: "w = *(fpip+0xB4)   <- exedit object canvas width",
    0x100531EA: "h = *(fpip+0xB8)   <- exedit object canvas height",
    0x100531F6: "compare against *(fpip+0x14) / *(fpip+0x18) = max canvas size",
    0x1005320D: "test ex_data & 0x1000000 (bit24: light color = unset)",
    0x10053218: "extract worker sub_100535a0 (object, bit24 SET = use source chroma)",
    0x1005322B: "extract worker sub_100536d0 (object, bit24 CLEAR = use picked color)",
    0x1005323B: "--- flag&0x20 CLEAR path (frame filter) starts: w = fpip->w (+0xC) ---",
    0x10053245: "h = fpip->h (+0x10)",
    0x1005325A: "extract worker sub_100533c0 (frame, bit24 SET = use source chroma)",
    0x1005326A: "extract worker sub_100534b0 (frame, bit24 CLEAR = use picked color)",
    0x10053275: "diffusion speed (0x101b2000) - frame path only runs the curve block when > 0",
    0x1005329B: "ecx = *(fpip+0xB0) = glow accumulator buffer",
    0x100532A7: "call exfunc[0x48](accumulator, 0,0, w, h, ...) - clear it",
    0x100532CB: "call sub_10070550(accumulator, w, h, speed) - forward curve",
    0x100532E8: "call sub_10070550(ycp_temp,    w, h, speed) - forward curve",
    0x10053330: "call sub_10053a30(radius, fp, fpip) - one of the 6 blur passes",
    0x10053365: "call sub_10070700(*(fpip+0xB0), ...) - inverse curve, once, on the sum",
    0x10053372: "test fp->flag & 0x20 again, to pick the composite",
    0x1005337C: "composite sub_10053890 (object: alpha-aware, always runs)",
    0x1005339F: "composite sub_10053800 (frame: plain add, only when diffusion speed > 0)",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    pe = pefile.PE(dll_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    start, size = FUNC_PROC
    print(f"--- func_proc @ 0x{start:08x}: mode branch and everything it selects ---")
    code = data[start - image_base:start - image_base + size]
    for insn in md.disasm(code, start):
        note = ANNOTATIONS.get(insn.address, "")
        marker = f"    <-- {note}" if note else ""
        print(f"0x{insn.address:08x}: {insn.mnemonic:7s} {insn.op_str}{marker}")

    print(
        "\n"
        "Verdict: the two paths are distinguished by the pixel format they work on.\n"
        "\n"
        "  flag & 0x20 SET  -> OBJECT EFFECT (the registration that has the size-fixed checkbox)\n"
        "      image    : *(fpip+0xAC), 8 bytes/pixel = PIXEL_YCA (y, cb, cr, a)\n"
        "      row pitch: *(fpip+0xEC) pixels          w/h: *(fpip+0xB4), *(fpip+0xB8)\n"
        "      glow src : fpip->ycp_temp (+8)          accum: *(fpip+0xB0), 6 bytes/pixel\n"
        "      extract  : sub_100535a0 / sub_100536d0  composite: sub_10053890 (always)\n"
        "      vertical : sub_100544a0 (diffusion speed = 0)\n"
        "\n"
        "  flag & 0x20 CLEAR -> FRAME (VIDEO) FILTER\n"
        "      image    : fpip->ycp_edit (+4), 6 bytes/pixel = PIXEL_YC (no alpha)\n"
        "      row pitch: fpip->line_size (+0x14)      w/h: fpip->w (+0xC), fpip->h (+0x10)\n"
        "      glow src : fpip->ycp_temp (+8)          accum: ycp_edit itself, or\n"
        "                 *(fpip+0xB0) when diffusion speed > 0\n"
        "      extract  : sub_100533c0 / sub_100534b0  composite: sub_10053800 (speed>0 only)\n"
        "      vertical : sub_100540a0 (diffusion speed = 0)\n"
        "\n"
        "Only exedit's own object images carry alpha, and only an object's canvas can\n"
        "need to grow when the glow spills outside it (hence the size-fixed checkbox + the\n"
        "offscreen-draw call on that same branch). The alpha-carrying 8-byte buffer is\n"
        "therefore the object-effect path.\n"
    )


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
