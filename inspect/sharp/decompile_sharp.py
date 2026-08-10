"""angr decompilation of シャープ's func_proc and its three workers.

The whole effect is `0x10089030`-`0x10089d99`, four functions back to back, so
one pinned CFG window covers it. The window is fixed rather than derived from
`--span` because the neighbours are unrelated (`シャドー` below, a clipboard
helper and `標準再生` above) and letting angr wander into them only slows the
run down.

Read the output for *shape*, not for arithmetic. Both box-average workers
finish every pixel with `fild`/`fdiv`, which angr does not lift, so the colour
normalisation comes out as `/* unsupported instruction */`; verify_blur_chain.py
supplies those formulas. What this script is for:

  * func_proc has no pixel loop. It copies the source image into the shared
    scratch buffer `[0x101a5328]` with `table[0x44]`, then fires
    `exec_multi_thread_func` five times - V, H, V, H, combine - swapping
    `*(fpip+0xAC)` with `*(fpip+0xB0)` after each of the four blur passes and
    *not* after the last one,
  * the two blur workers (`0x100891c0` vertical, `0x10089690` horizontal) are
    the ordinary alpha-weighted sliding-window box average, each reading only
    its own pair of globals,
  * the combine worker `0x10089b60` is the only one that reads `fp->track[]`
    (`強さ`, via the `/1000` magic divide) and the only one that touches the
    scratch buffer.

Run via main.py:
    uv run main.py inspect/sharp/decompile_sharp.py
    uv run main.py inspect/sharp/decompile_sharp.py --only combine
"""

from tools.decompile import decompile_cli

REGION = (0x10089000, 0x1008A000)

TARGETS = {
    "func_proc                     0x10089030": 0x10089030,
    "worker: vertical box average  0x100891c0": 0x100891C0,
    "worker: horizontal box average 0x10089690": 0x10089690,
    "worker: unsharp combine       0x10089b60": 0x10089B60,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    decompile_cli(dll_path, TARGETS, argv, region=REGION)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
