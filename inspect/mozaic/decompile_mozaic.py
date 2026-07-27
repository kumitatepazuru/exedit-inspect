"""Decompile the モザイク (mosaic) filter's func_proc and its four worker
functions in exedit.auf.

func_proc's address (0x1006b090) was found with `tools.filter_table --name モザイク`. This
script builds a small angr CFG rooted at that address (CFGFast is run over a
narrow byte range around the target instead of the whole binary, which is
both much faster and avoids pulling in unrelated functions) and runs angr's
Decompiler on func_proc plus every worker it dispatches through
EXFUNC::exec_multi_thread_func.

The decompilation is only a scaffold: it recovers the loop nest and the
integer arithmetic, but renders the x87 block that computes the
alpha-weighted average as `/* unsupported instruction */`, because angr's
decompiler does not lift x87 to C. disasm_mozaic.py reads that part as raw
instructions, and verify_*.py re-derives each piece independently.

Run via main.py:
    uv run main.py inspect/mozaic/decompile_mozaic.py
    uv run main.py inspect/mozaic/decompile_mozaic.py --only func_proc
"""

import argparse

from tools.decompile import decompile_targets

FUNC_PROC = 0x1006B090

# The 2x2 worker matrix dispatched from func_proc: {object effect, frame
# filter} x {タイル風 off, タイル風 on}. See README.md section 1.
WORKERS = {
    "func_proc (dispatcher)": FUNC_PROC,
    "object effect,  タイル風 OFF": 0x1006B180,
    "frame filter,   タイル風 OFF": 0x1006B470,
    "object effect,  タイル風 ON": 0x1006B6B0,
    "frame filter,   タイル風 ON": 0x1006BA40,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", help="substring of a label in WORKERS; decompile just that one")
    args = parser.parse_args(argv or [])

    targets = WORKERS
    if args.only:
        targets = {k: v for k, v in WORKERS.items() if args.only in k}
        if not targets:
            print(f"no worker label contains {args.only!r}; known: {list(WORKERS)}")
            return

    # all five functions live in 0x1006b090..0x1006bd26, so one window covers them
    base = FUNC_PROC & ~0xFFF
    decompile_targets(dll_path, targets, region=(base, base + 0x2000))


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
