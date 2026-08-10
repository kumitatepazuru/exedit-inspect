"""angr decompilation of フェード, its worker, and its audio twin 音量フェード.

The whole of フェード is `0x1004dd40`-`0x1004de95` (two functions, 342 bytes)
and 音量フェード sits immediately after it at `0x1004dea0`, so one pinned CFG
window covers all three. The window is fixed rather than derived from `--span`
because the neighbours are unrelated (`閃光` below, a handful of Win32 wrappers
above) and letting angr wander into them only slows the run down.

Read the output for *shape*, not for arithmetic. Both `func_proc`s convert
`イン`/`アウト` from seconds to frames in x87, which angr does not lift, so the
conversion comes out as `/* unsupported instruction */` and a bare call to
`_ftol` (`0x10091ad8`); disasm_params.py and verify_seconds_to_frames.py supply
that formula. What this script is for:

  * フェード's `func_proc` has no pixel loop. It writes one global
    (`0x101a5390`, the Q12 alpha), takes three exits - `>= 4096` return 1 and
    touch nothing, `<= 0` return **0**, otherwise one
    `exec_multi_thread_func` - and never looks at a checkbox or `ex_data`
    (it has neither),
  * the worker `0x1004de20` is a plain row-split loop that reads and writes
    **only** the alpha field of `*(fpip+0xAC)`. `y`/`cb`/`cr` never appear,
  * 音量フェード `0x1004dea0` is the same function with the global replaced by
    a register, the multi-thread dispatch replaced by an inline loop over
    `*(fpip+0x104)`, and one subtraction missing (verify_audio_twin.py).

Run via main.py:
    uv run main.py inspect/fade/decompile_fade.py
    uv run main.py inspect/fade/decompile_fade.py --only worker
"""

from tools.decompile import decompile_cli

REGION = (0x1004DD00, 0x1004E000)

TARGETS = {
    "func_proc           フェード      0x1004dd40": 0x1004DD40,
    "worker: alpha scale フェード      0x1004de20": 0x1004DE20,
    "func_proc           音量フェード  0x1004dea0": 0x1004DEA0,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    decompile_cli(dll_path, TARGETS, argv, region=REGION)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
