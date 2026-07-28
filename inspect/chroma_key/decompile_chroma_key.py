"""angr decompilation of クロマキー's func_proc, its seven workers and its UI code.

Everything the effect does lives in one contiguous stretch of .text,
`0x10012de0`-`0x1001457f`, so a single CFG window covers the lot. The window is
pinned rather than derived from `--span`, because the neighbours on both sides
(`クリッピング` below, `カラーキー` above) are unrelated filters and letting
angr wander into them only slows the run down.

Read the output for *shape*, not for arithmetic. Every worker computes a hue
angle with `fpatan`, which angr does not lift - the whole key metric comes out
as `/* unsupported instruction */`. disasm_params.py and the verify_*.py
scripts supply the formulas; this script is what shows that

  * func_proc itself contains no pixel loop at all - it writes five globals and
    fires one, or three, `exec_multi_thread_func` calls,
  * the seven workers are four independent code paths, not variations that
    share a helper: there is not a single `call` between them,
  * `0x100144c0` (the settings-window label) is the only place `ex_data.color_yc.y`
    is ever read.

Run via main.py:
    uv run main.py inspect/chroma_key/decompile_chroma_key.py
    uv run main.py inspect/chroma_key/decompile_chroma_key.py --only worker
"""

from tools.decompile import decompile_cli

REGION = (0x10012000, 0x10015000)

TARGETS = {
    "func_proc                       0x10012de0": 0x10012DE0,
    "worker: plain                   0x10012f10": 0x10012F10,
    "worker: plain + 色彩補正        0x100130b0": 0x100130B0,
    "worker: 境界補正 pass1          0x10013340": 0x10013340,
    "worker: 境界補正 pass1 + 色彩補正 0x10013500": 0x10013500,
    "worker: 境界補正 pass2 (vertical) 0x100136e0": 0x100136E0,
    "worker: 境界補正 pass3          0x10013880": 0x10013880,
    "worker: 境界補正 pass3 + 色彩補正 0x10013de0": 0x10013DE0,
    "func_WndProc                    0x100143d0": 0x100143D0,
    "settings-window label           0x100144c0": 0x100144C0,
    "FILTER+0x58 hook                0x10014560": 0x10014560,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    decompile_cli(dll_path, TARGETS, argv, region=REGION)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
