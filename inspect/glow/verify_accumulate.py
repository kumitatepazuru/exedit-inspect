"""Show how each of the 6 blur passes is folded into the glow accumulator -
which is not the plain unclamped addition it looks like from the call graph.

Two different accumulators exist, picked by 拡散速度 (sub_10053a30):

  diffusion speed = 0  -> sub_100540a0 (frame) / sub_100544a0 (object)
      integer PIXEL_YC accumulator with a saturating luma and a chroma fade:

        s = acc.y + pass.y
        if s <= 0x2000:   acc.y = s
                          acc.cb += pass.cb;  acc.cr += pass.cr
        else:             acc.y = 0x2000                       # luma pinned at 2x white
                          if s > 0x4000:  acc.cb = acc.cr = 0   # colour dropped entirely
                          else:           t = 0x4000 - s
                                          acc.cb = ((acc.cb + pass.cb) * t) >> 13
                                          acc.cr = ((acc.cr + pass.cr) * t) >> 13

      i.e. once the running glow passes 8192 the accumulator stops getting
      brighter and starts *losing saturation* on every further pass, washing
      a strong glow toward white instead of letting it grow without bound.

  diffusion speed > 0  -> sub_100548a0
      float luma accumulator with NO clamp at all (`fadd [esi]` / `fstp [esi]`)
      - the log() applied afterwards is what keeps it bounded - plus a
      signed-byte chroma accumulator clamped to [-128, 127] on every pass.

Both variants therefore diverge from "sum the six passes"; the first
saturates, the second is unbounded in luma but heavily quantised in chroma.

Run via main.py:
    uv run main.py inspect/glow/verify_accumulate.py
"""

import capstone
import pefile

ACCUM_FRAME = (0x100542FA, 0x70)    # sub_100540a0, diffusion speed = 0, into ycp_edit
ACCUM_OBJECT = (0x100546FD, 0x70)   # sub_100544a0, diffusion speed = 0, into *(fpip+0xB0)
ACCUM_SPEED = (0x100549F0, 0x50)    # sub_100548a0, diffusion speed > 0, into *(fpip+0xB0)

ANNOTATIONS = {
    0x100542FA: "eax = acc.y", 0x100546FD: "eax = acc.y",
    0x100542FD: "s = acc.y + pass.y", 0x10054700: "s = acc.y + pass.y",
    0x100542FF: "s > 8192 ?", 0x10054702: "s > 8192 ?",
    0x10054306: "not saturated: store s, then plain chroma adds",
    0x10054709: "not saturated: store s, then plain chroma adds",
    0x1005431B: "s > 16384 ?", 0x1005471E: "s > 16384 ?",
    0x10054320: "pin acc.y at 8192", 0x10054723: "pin acc.y at 8192",
    0x10054327: "past 16384: chroma forced to 0", 0x1005472A: "past 16384: chroma forced to 0",
    0x1005432F: "t = 16384 - s", 0x10054732: "t = 16384 - s",
    0x10054344: "acc.cb = (acc.cb + pass.cb) * t", 0x10054747: "acc.cb = (acc.cb + pass.cb) * t",
    0x1005434D: ">> 13  (i.e. * t/8192, a fade between 1.0 and 0.0)",
    0x10054750: ">> 13  (i.e. * t/8192, a fade between 1.0 and 0.0)",
    0x100549F0: "luma: fadd [esi] - read/add/write, no clamp anywhere",
    0x100549F6: "luma: fstp [esi] - store the running float sum back",
    0x100549FC: "chroma: this pass's byte + accumulated byte",
    0x100549FE: "chroma: clamp at +127",
    0x10054A0A: "chroma: clamp at -128",
    0x10054A14: "chroma: store cb byte at accumulator+4",
    0x10054A3B: "chroma: store cr byte at accumulator+5",
}


def _dump(md, image_base, data, start, size, label):
    print(f"\n--- {label} @ 0x{start:08x} ---")
    code = data[start - image_base:start - image_base + size]
    for insn in md.disasm(code, start):
        note = ANNOTATIONS.get(insn.address, "")
        marker = f"    <-- {note}" if note else ""
        print(f"0x{insn.address:08x}: {insn.mnemonic:7s} {insn.op_str}{marker}")


def accumulate_speed_zero(passes):
    """Faithful replay of the sub_100540a0 / sub_100544a0 accumulation."""
    acc_y = acc_cb = acc_cr = 0
    trace = []
    for py, pcb, pcr in passes:
        s = acc_y + py
        if s <= 0x2000:
            acc_y = s
            acc_cb += pcb
            acc_cr += pcr
        else:
            acc_y = 0x2000
            if s > 0x4000:
                acc_cb = acc_cr = 0
            else:
                t = 0x4000 - s
                acc_cb = ((acc_cb + pcb) * t) >> 13
                acc_cr = ((acc_cr + pcr) * t) >> 13
        trace.append((acc_y, acc_cb, acc_cr))
    return trace


def accumulate_speed_nonzero(passes):
    """Faithful replay of the sub_100548a0 accumulation."""
    acc_y = 0.0
    acc_cb = acc_cr = 0
    trace = []
    for py, pcb, pcr in passes:
        acc_y += py
        acc_cb = max(-128, min(127, acc_cb + pcb))
        acc_cr = max(-128, min(127, acc_cr + pcr))
        trace.append((acc_y, acc_cb, acc_cr))
    return trace


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    pe = pefile.PE(dll_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    _dump(md, image_base, data, *ACCUM_FRAME,
          "sub_100540a0 (frame filter, speed=0): saturating accumulate into ycp_edit")
    _dump(md, image_base, data, *ACCUM_OBJECT,
          "sub_100544a0 (object effect, speed=0): same code, accumulating into *(fpip+0xB0)")
    _dump(md, image_base, data, *ACCUM_SPEED,
          "sub_100548a0 (speed>0): float luma fadd + signed-byte chroma with per-pass clamp")

    print(
        "\nNumeric replay, 6 passes each contributing the same value (a stand-in for the\n"
        "middle of a large flat glow source; real content varies per pass but the\n"
        "saturation behaviour is what matters here).\n"
    )
    print("  diffusion speed = 0, contribution per pass = (y, cb, cr):")
    for py, pcb, pcr in ((512, 200, -100), (1500, 900, -300), (3000, 1500, -500)):
        trace = accumulate_speed_zero([(py, pcb, pcr)] * 6)
        print(f"    pass value y={py:5d} cb={pcb:5d} cr={pcr:5d}")
        for i, (y, cb, cr) in enumerate(trace, 1):
            note = "  <- luma pinned, chroma fading" if y == 0x2000 else ""
            print(f"      after pass {i}: y={y:5d} cb={cb:5d} cr={cr:5d}{note}")

    print("\n  diffusion speed > 0, contribution per pass = (curved luma, cb byte, cr byte):")
    for py, pcb, pcr in ((7.5, -21, 61), (1287.0, -81, 122)):
        trace = accumulate_speed_nonzero([(py, pcb, pcr)] * 6)
        print(f"    pass value y={py:9.2f} cb={pcb:5d} cr={pcr:5d}")
        for i, (y, cb, cr) in enumerate(trace, 1):
            note = "  <- chroma clamped" if abs(cb) == 128 or abs(cr) == 127 else ""
            print(f"      after pass {i}: y={y:11.2f} cb={cb:5d} cr={cr:5d}{note}")

    print(
        "\n"
        "Verdict: neither accumulator is a plain sum.\n"
        "  * speed=0: luma saturates at 8192 (2x full white) and, past that point,\n"
        "    every further pass multiplies the accumulated chroma by (16384-s)/8192,\n"
        "    so an over-driven glow desaturates toward white instead of growing.\n"
        "  * speed>0: luma is accumulated as an unclamped float in curved space (the\n"
        "    later log is what tames it), while chroma is a signed byte re-clamped to\n"
        "    [-128,127] on every single pass - a saturated light colour hits that\n"
        "    ceiling within one or two passes and then stops contributing colour while\n"
        "    the luma keeps climbing, which is what makes a strong red glow read as\n"
        "    yellow/white rather than deeper red.\n"
    )


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
