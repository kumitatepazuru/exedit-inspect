"""func_proc, the four workers and the two UI entries, annotated.

ルミナンスキー is the smallest complete effect analysed in this repository:
959 bytes from 0x10064ee0 to 0x1006529e, no globals, no floating point, no
shared helper calls, no scratch buffer. func_proc is 25 instructions and does
exactly one thing - pick a worker from `ex_data.type` and fire it:

    type == 0 -> 0x10064f60   暗い部分を透過
    type == 1 -> 0x10065020   明るい部分を透過
    type == 2 -> 0x100650e0   明暗部分を透過
    else      -> 0x100651b0   明暗部分を透過(ぼかし無し)

There is no early return: every value of `type` runs a worker over every
pixel, whatever the trackbars say.

All four workers share one prologue, which reads the two trackbars straight out
of `fp->track[]` (nothing is passed through a global - see verify_dispatch.py)
and folds them into a single offset:

    worker 0 / 2 / 3:   lo = 基準輝度 - ぼかし     stored at [esp+0x18]
    worker 1:           hi = 基準輝度 + ぼかし     stored at [esp+0x18]
    all four:           ぼかし                     stored at [esp+0x1c] or edi

and then the whole per-pixel decision is four to seven instructions on the
16-bit `y` field. The annotations below are the claims; the instructions beside
them are the evidence.

Run via main.py:
    uv run main.py inspect/luma_key/disasm_params.py
"""

from tools.disasm import dump_all
from tools.pe_image import PEImage

FUNC_PROC = (0x10064EE0, 0x79)
WORKER_DARK = (0x10064F60, 0xBD)
WORKER_BRIGHT = (0x10065020, 0xBF)
WORKER_BAND = (0x100650E0, 0xCE)
WORKER_BAND_HARD = (0x100651B0, 0xB7)
UPDATE_ENTRY = (0x10065270, 0x2F)
WND_PROC = (0x10018080, 0x43)

ANNOTATIONS = {
    # ---- func_proc 0x10064ee0 -------------------------------------------
    0x10064EE0: "eax = fp",
    0x10064EE4: "edx = fpip",
    0x10064EE8: "both are pushed once and reused for all four calls: the worker",
    0x10064EE9: "  address is the only thing that differs between the branches",
    0x10064EEA: "fp->ex_data_ptr (+0x4c)",
    0x10064EED: "ex_data.type - the 4-item combobox. THE ONLY ex_data field",
    0x10064EEF: "type == 0 ?",
    0x10064EF3: "fp->exfunc (+0x60)",
    0x10064EF6: "worker 0x10064f60 = 暗い部分を透過",
    0x10064EFB: "exfunc->exec_multi_thread_func (+0xCC). (worker, fp, fpip)",
    0x10064F04: "return TRUE. No early return anywhere - every type runs a worker",
    0x10064F0A: "type == 1 ?",
    0x10064F12: "worker 0x10065020 = 明るい部分を透過",
    0x10064F26: "type == 2 ?",
    0x10064F2E: "worker 0x100650e0 = 明暗部分を透過",
    0x10064F45: "everything else -> worker 0x100651b0 = 明暗部分を透過(ぼかし無し).",
    0x10064F4A: "  a combobox can only produce 0..3, but 3 is reached by the else",
    # ---- worker 0x10064f60, type 0: 暗い部分を透過 -----------------------
    0x10064F62: "ebx = thread_id",
    0x10064F69: "edi = fpip (arg4)",
    0x10064F6D: "ebp = thread_num (arg2)",
    0x10064F71: "*(fpip+0xB4) = w",
    0x10064F77: "*(fpip+0xB8) = h",
    0x10064F81: "y1 = (thread_id+1) * h / thread_num",
    0x10064F8A: "edx = fp (arg3)",
    0x10064F8E: "*(fpip+0xEC) = row stride in pixels",
    0x10064F96: "fp->track (+0x44): the worker reads the trackbars itself",
    0x10064F99: "track[1] = ぼかし",
    0x10064F9C: "track[0] = 基準輝度",
    0x10064F9E: "lo = 基準輝度 - ぼかし. The ONLY parameter arithmetic in the effect",
    0x10064FA0: "spill ぼかし",
    0x10064FA4: "spill lo",
    0x10064FA8: "y0 = thread_id * h / thread_num - the split is by row",
    0x10064FB2: "empty row range (h < thread_num) -> return",
    0x10064FC0: "8 bytes per pixel (PIXEL_YCA)",
    0x10064FCF: "*(fpip+0xAC) = the object buffer. No flag&0x20 branch: object only,",
    0x10064FD5: "  and no *(fpip+0xB0): the effect is entirely in place",
    0x10064FDD: "w <= 0 -> skip the row",
    0x10064FE1: "t = pixel y ...",
    0x10064FE4: "  ... minus lo, i.e. t = y - 基準輝度 + ぼかし",
    0x10064FE8: "t >= 0 ? if not, fall through to the store",
    0x10064FEA: "t < 0 (y below 基準輝度-ぼかし): alpha = 0, hard",
    0x10064FF2: "esi = ぼかし",
    0x10064FF6: "t >= ぼかし (y at or above 基準輝度) -> leave alpha alone.",
    0x10064FF8: "  `jge`, so y == 基準輝度 is fully opaque. The ramp is BELOW 基準輝度",
    0x10064FFA: "0 < t < ぼかし: the only interpolation in the effect",
    0x10064FFE: "alpha * t ...",
    0x10065002: "  ... / ぼかし. idiv = truncation toward zero, not rounding",
    0x10065004: "the one and only 16-bit store: pixel +6 = alpha. y/cb/cr are never",
    0x10065008: "  written by any worker - this effect only ever removes opacity",
    # ---- worker 0x10065020, type 1: 明るい部分を透過 ---------------------
    0x10065059: "track[1] = ぼかし",
    0x1006505C: "track[0] = 基準輝度",
    0x1006505E: "hi = 基準輝度 + ぼかし. `add` where worker 0 has `sub` - that one",
    0x10065060: "  instruction is the entire difference between the two workers",
    0x100650A1: "pixel y",
    0x100650A4: "hi",
    0x100650A8: "t = hi - y (worker 0 computes y - lo; the sense is mirrored)",
    0x100650AA: "t < 0 (y above 基準輝度+ぼかし): alpha = 0",
    0x100650B8: "t >= ぼかし (y at or below 基準輝度) -> leave alpha alone",
    0x100650C0: "alpha * t / ぼかし. The ramp is ABOVE 基準輝度",
    0x100650C6: "same single store at pixel +6",
    # ---- worker 0x100650e0, type 2: 明暗部分を透過 -----------------------
    0x100650E7: "ebp = thread_id (this worker keeps thread_num on the stack)",
    0x10065117: "edi = track[1] = ぼかし, live in a register for the whole loop",
    0x1006511A: "track[0] = 基準輝度",
    0x1006511C: "lo = 基準輝度 - ぼかし, same as worker 0",
    0x1006515F: "pixel y",
    0x10065162: "t = y - lo",
    0x10065166: "t > ぼかし means y is ABOVE 基準輝度 ...",
    0x1006516A: "  ... so fold it back: t = 2*ぼかし - t = 基準輝度 + ぼかし - y.",
    0x1006516F: "  After this t = ぼかし - |y - 基準輝度| on both sides",
    0x10065173: "t < 0 (outside the band): alpha = 0",
    0x1006517F: "t >= ぼかし can now only mean t == ぼかし, i.e. y == 基準輝度 exactly",
    0x10065187: "everything else is on the ramp: alpha * t / ぼかし.",
    0x1006518B: "  the whole band is ramp - full alpha survives at ONE luminance",
    0x1006518D: "same single store at pixel +6",
    # ---- worker 0x100651b0, type 3: 明暗部分を透過(ぼかし無し) -----------
    0x100651EC: "track[0] = 基準輝度",
    0x100651EE: "lo = 基準輝度 - ぼかし",
    0x1006521B: "ebx = 0, hoisted out of both loops: the compare operand AND the",
    0x1006521D: "  stored value. This worker has no multiply and no divide",
    0x10065233: "pixel y",
    0x1006523A: "t = y - lo",
    0x1006523C: "edx = ぼかし",
    0x10065240: "t > ぼかし ...",
    0x10065244: "  ... fold: t = 2*ぼかし - t. Identical to worker 2 up to here",
    0x1006524A: "t vs 0 - and then nothing else. No ramp, no idiv",
    0x1006524E: "t < 0: alpha = 0. The band survives at FULL alpha, edge to edge",
    # ---- FILTER+0x58 0x10065270 ------------------------------------------
    0x10065270: "eax = fp (this entry takes (editp, fp))",
    0x10065274: "SendMessageA lParam, pushed first and left on the stack",
    0x10065276: "fp->ex_data_ptr",
    0x10065279: "fp->+0x64 = exedit's internal table (0x100a41e0)",
    0x1006527C: "fp->+0xE4 - the same opaque handle クロマキー passes to table[0x68]",
    0x10065282: "ex_data.type -> SendMessageA wParam",
    0x10065285: "CB_SETCURSEL (0x14e)",
    0x1006528C: "control kind 6 = combobox (5 = button, 7 = static; see verify_ex_data.py)",
    0x1006528F: "table[0x4c](fp+0xE4, 6, 0) -> HWND of combobox #0",
    0x10065292: "pops only the three table[0x4c] args; wParam/lParam/msg stay put",
    0x10065296: "SendMessageA(hwnd, CB_SETCURSEL, type, 0). Shared verbatim with",
    0x1006529C: "  インターレース解除, which also has one combobox and a 4-byte ex_data",
    # ---- func_WndProc 0x10018080 -----------------------------------------
    0x10018080: "eax = fp (arg6)",
    0x10018084: "ecx = message (arg2)",
    0x10018089: "0x702 = WM_FILTER_COMMAND",
    0x1001808F: "esi = fp->ex_data_ptr, read before the branch",
    0x10018094: "0x1e1c = the combobox notification. 0x1e1b is the button id クロマキー",
    0x1001809B: "  and カラーキー use; this is the next control id along",
    0x1001809D: "fp+0xE4",
    0x100180A3: "fp->+0x64 = exedit's table",
    0x100180A9: "table[0x80](fp+0xE4, 0) - invoked for its side effect only",
    0x100180AF: "lParam = the new selection index",
    0x100180B6: "ex_data.type = lParam. The whole state this WndProc owns",
    0x100180B8: "return TRUE -> exedit re-renders",
    0x100180BF: "anything else: return FALSE. fp->track[] is never read here",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_all(img, {
        "func_proc 0x10064ee0": FUNC_PROC,
        "worker 0x10064f60  type 0  暗い部分を透過": WORKER_DARK,
        "worker 0x10065020  type 1  明るい部分を透過": WORKER_BRIGHT,
        "worker 0x100650e0  type 2  明暗部分を透過": WORKER_BAND,
        "worker 0x100651b0  type 3  明暗部分を透過(ぼかし無し)": WORKER_BAND_HARD,
        "FILTER+0x58 0x10065270  settings-window update": UPDATE_ENTRY,
        "func_WndProc 0x10018080  (shared, 5 registrations)": WND_PROC,
    }, annotations=ANNOTATIONS)

    print(
        "\n"
        "The four workers side by side. `t` is the value each one tests, `blur` is\n"
        "track[1] = ぼかし and `base` is track[0] = 基準輝度:\n"
        "\n"
        "  type  worker        t                       t < 0     t >= blur   otherwise\n"
        "  ----  ------------  ----------------------  --------  ----------  -------------\n"
        "  0     0x10064f60    y - base + blur         a = 0     keep        a = a*t/blur\n"
        "  1     0x10065020    base + blur - y         a = 0     keep        a = a*t/blur\n"
        "  2     0x100650e0    blur - |y - base|       a = 0     keep        a = a*t/blur\n"
        "  3     0x100651b0    blur - |y - base|       a = 0     keep        (unreachable)\n"
        "\n"
        "Workers 0 and 1 differ in one instruction (`sub` vs `add` at 0x10064f9e /\n"
        "0x1006505e) plus the direction of the subtraction in the loop. Worker 2 adds\n"
        "the fold at 0x10065166 that makes t symmetric about base. Worker 3 is worker 2\n"
        "with the ramp deleted - which also deletes its `imul`, `cdq` and `idiv`, so it\n"
        "is the only worker that cannot divide by zero even in principle.\n"
        "\n"
        "For type 2 the `t >= blur` case degenerates: after the fold t <= blur always,\n"
        "so `keep` fires only at t == blur, i.e. only at y == base exactly. That is why\n"
        "明暗部分を透過 dims the band it keeps and 明暗部分を透過(ぼかし無し) does not.\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
