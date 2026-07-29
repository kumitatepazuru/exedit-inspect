"""angr decompilation of ルミナンスキー's func_proc, its four workers and its
settings hook.

The whole effect is 959 contiguous bytes of .text, `0x10064ee0`-`0x1006529e`.
The function below it ends at `0x10064ed1` and the one above starts at
`0x100652a0` (an x87 spline routine belonging to something else entirely), so
the CFG window is pinned to that stretch rather than derived from `--span`.

This effect decompiles better than anything else in this repository, because
there is nothing in it to trip angr up: no x87, no SSE, no `_ftol`, no magic
division, no globals, no shared helpers (verify_dispatch.py §2 and §7). The
output is close enough to source to read directly. What it shows:

  * func_proc is a four-way `if` on `fp->ex_data_ptr[0]` and nothing else. No
    pixel loop, no early return, no parameter arithmetic.
  * all four workers write to `iter[3]` of an `unsigned short[4]` - the alpha
    field of a PIXEL_YCA - and to nothing else.
  * workers 2 and 3 show the fold plainly: `if (v8 > v2) v8 = v2 * 2 - v8;`,
    the instruction pair that makes the band symmetric about 基準輝度.
  * worker 3 is worker 2 with the `iter[3] = v8 * iter[3] / v2` arm deleted.

Three renderings to distrust, all checked properly in disasm_params.py and
verify_alpha_curve.py:

  * **angr reuses the `tid` parameter slot.** In every worker it emits
    `a0 = track[0] - track[1];` and then `v3 = a0 * h / thread_num;`, which
    would make the thread's first row depend on the trackbars. The
    instructions multiply `ebx`/`ebp` - the original thread id - and the
    decompiler has simply collapsed two live ranges of the same storage.
  * the `dec reg / jne` loops come out as `while (i != 1)`, one iteration
    short. `dec` sets ZF after the decrement, so they run the full count.
  * `iter[3] = v8 * iter[3] / v2` reads with the operands swapped relative to
    `imul eax, edx` (`alpha * t`). Harmless - multiplication commutes - but
    the division that follows does not, and it truncates.
  * in `sub_10065270` the exedit table call comes out with six arguments,
    `field_4c(fp+0xE4, 6, 0, 334, type, 0)`. Only the first three are its own:
    the settings hook pre-pushes `SendMessageA`'s arguments and cleans just
    `0xc` bytes afterwards, so angr reads the leftovers as part of the call.

func_WndProc is not decompiled here: it lives at `0x10018080`, 300 KB away,
and is shared with four other registrations. verify_ex_data.py §3 dumps it
annotated.

Run via main.py:
    uv run main.py inspect/luma_key/decompile_luma_key.py
    uv run main.py inspect/luma_key/decompile_luma_key.py --only worker
"""

from tools.decompile import decompile_cli

REGION = (0x10064E00, 0x100652A0)

TARGETS = {
    "func_proc                                   0x10064ee0": 0x10064EE0,
    "worker type 0: 暗い部分を透過                0x10064f60": 0x10064F60,
    "worker type 1: 明るい部分を透過              0x10065020": 0x10065020,
    "worker type 2: 明暗部分を透過                0x100650e0": 0x100650E0,
    "worker type 3: 明暗部分を透過(ぼかし無し)    0x100651b0": 0x100651B0,
    "FILTER+0x58 settings-window update          0x10065270": 0x10065270,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    decompile_cli(dll_path, TARGETS, argv, region=REGION)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
