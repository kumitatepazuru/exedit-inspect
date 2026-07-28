"""What func_proc does with the four trackbars, instruction by instruction.

グロー's parameter block is unusual in two ways compared with every other
effect analysed here, and both are visible in the dump below.

  1. **強さ is never converted.** 発光 / 拡散光 / 閃光 all push their 強さ
     through the shared `raw*4096/1000` magic-number divide. グロー stores
     `fp->track[0]` into 0x101b2018 *raw* (0x10054de6) and multiplies it by
     small integers later. Only しきい値 gets the /1000 treatment
     (0x10054ecc-0x10054ee7). See verify_params.py.

  2. **拡散 becomes three separate radii.** The same raw value lands in
     0x101b2024 (rx) and 0x101b2020 (ry); a third global 0x101b2028 gets
     `trunc(sqrt(rx*rx + ry*ry))` and is then clamped down by both - which,
     since rx and ry start out equal, makes the sqrt dead arithmetic
     (verify_diag_radius.py). 0x101b2028 is the radius the diagonal streak
     workers use.

The per-pass schedule of `通常` (four radii from rx, four strengths from 強さ)
is dumped here too, because it is spread over 0x100551e2-0x1005530f as four
near-identical blocks and is easy to misread: the divisors are 8, 6, 4, 2 and
the /6 is a bare `imul` with no shift.

Run via main.py:
    uv run main.py inspect/glow/disasm_params.py
"""

from tools.disasm import dump_all
from tools.pe_image import PEImage

PARAMS = (0x10054DB0, 0x150)          # entry, early-outs, 拡散 -> rx/ry/diag
CANVAS = (0x10054EC9, 0x50)           # しきい値 conversion + 光色の設定
SCHEDULE = (0x100551E2, 0x140)        # 通常: four (strength, radius) pairs
TAIL = (0x1005542F, 0x20)             # ぼかし tail radius

ANNOTATIONS = {
    0x10054DB9: "eax = fp->ex_data_ptr  (dword[0] = colour+no_color, dword[1] = 形状)",
    0x10054DBC: "ecx = fp->track",
    0x10054DC3: "track[0] = 強さ",
    0x10054DC7: "強さ == 0 -> return 1, nothing is touched",
    0x10054DD4: "track[1] = 拡散",
    0x10054DD9: "拡散 == 0 -> return 1 as well",
    0x10054DE6: "0x101b2018 = 強さ, stored RAW (no /1000 anywhere)",
    0x10054DF3: "0x101b2024 = rx = 拡散",
    0x10054E06: "0x101b2020 = ry = 拡散",
    0x10054E01: "ecx = rx*rx",
    0x10054E0C: "eax = ry*ry",
    0x10054E15: "the only floating point in the whole filter ...",
    0x10054E19: "... sqrt(rx*rx + ry*ry)",
    0x10054E1B: "_ftol: truncate toward zero",
    0x10054E26: "0x101b2028 = trunc(sqrt(rx^2+ry^2)) - the diagonal radius",
    0x10054E2E: "fp->flag & 0x20 -> object effect / frame filter",
    0x10054E3B: "object: w + 2*rx vs max canvas width 0x10196748",
    0x10054E60: "object: h + 2*ry vs max canvas height 0x101920e0",
    0x10054E75: "frame: w + 2*rx vs max FRAME width 0x10178ec0",
    0x10054E97: "frame: h + 2*ry vs max FRAME height 0x101790c8",
    0x10054EB3: "diag = min(diag, rx) ...",
    0x10054EBF: "... and min(diag, ry) - the sqrt never survives this",
    0x10054ED5: "track[2] = しきい値",
    0x10054ED8: "<< 12",
    0x10054EDB: "magic-number divide by 1000 (0x10624dd3, sar 6)",
    0x10054EE7: "0x101b203c = trunc(しきい値 * 4096 / 1000)",
    0x10054EEF: "ex_data dword[0] = 0x00RRGGBB | no_color<<24",
    0x10054EFF: "shared RGB->YCbCr: Y->0x101b2030, Cb->0x101b202c, Cr->0x101b202e",
    0x100551E2: "pass 1: eax = 強さ",
    0x100551EE: "edx = 3 * 強さ ...",
    0x100551F6: "... * 2 = 6 * 強さ",
    0x100551FE: "c_div(rx, 8): cdq / and 7 / sar 3 is truncation toward zero",
    0x10055207: "0x101b201c = rx/8",
    0x10055264: "pass 2: strength /= 2  -> 3 * 強さ",
    0x1005527A: "magic 0x2aaaaaab with NO shift = divide by 6",
    0x1005528E: "0x101b201c = rx/6",
    0x100552AD: "pass 3: strength /= 2",
    0x100552C2: "c_div(rx, 4)",
    0x100552EF: "pass 4: strength /= 2",
    0x10055306: "c_div(rx, 2)",
    0x10055432: "ぼかし = track[3], used as a radius with no scaling at all",
    0x10055437: "0x101b201c = ぼかし",
    0x1005543C: "ぼかし <= 0 -> the two extra V/H rounds are skipped entirely",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_all(PEImage(dll_path), {
        "func_proc: early-outs, 拡散 -> rx / ry / diagonal radius": PARAMS,
        "func_proc: しきい値 -> Q12, 光色の設定 -> YCbCr": CANVAS,
        "func_proc: 通常 の4パス (strength, radius) スケジュール": SCHEDULE,
        "func_proc: ぼかし tail": TAIL,
    }, annotations=ANNOTATIONS)

    print("""
Reading of the above
--------------------
  0x101b2010  h  (object: fpip+0xB8 after growth / frame: fpip->h)
  0x101b2014  w  (object: fpip+0xB4 after growth / frame: fpip->w)
  0x101b2018  strength - RAW 強さ, then rewritten by the 通常 schedule
  0x101b201c  radius of the pass currently running
  0x101b2020  ry = 拡散
  0x101b2024  rx = 拡散
  0x101b2028  diagonal radius = min(rx, ry)  (the sqrt is dead, see verify_diag_radius.py)
  0x101b202c  光色 Cb   (int16)
  0x101b202e  光色 Cr   (int16)
  0x101b2030  光色 Y    (int16)
  0x101b2034  accumulation buffer = fpip+0xB0
  0x101b2038  scratch buffer      = [0x101a5328], shared with 発光
  0x101b203c  threshold = trunc(しきい値 * 4096 / 1000)

Every worker reads its geometry from these globals, so none of them takes an
argument other than (thread_id, thread_num, fp, fpip).""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
