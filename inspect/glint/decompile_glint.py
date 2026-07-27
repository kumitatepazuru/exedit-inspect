"""Decompile 閃光's func_proc and the three functions it dispatches to.

func_proc (0x1004e560, from find_glint_addr.py) is only a setup routine: it
converts the trackbars, works out how far the light rays will reach, grows the
object canvas to fit, and then hands one of two per-thread workers to
EXFUNC::exec_multi_thread_func. All of the actual pixel work is in those two
workers, and the choice between them is a single bit of ex_data (see
disasm_params.py):

  0x1004e9c0  ex_data bit24 set   - 光色の設定 left at "no colour": the ray
                                    samples the source pixels' own y/cb/cr
  0x1004ee20  ex_data bit24 clear - a colour was picked: the ray samples only
                                    the source *alpha* and multiplies the
                                    chosen colour by it

0x1004f260 is included because it is not reachable at all - it is the func_proc
of the unregistered frame-filter twin find_glint_addr.py turns up. Decompiling
it is what shows it is a stub: same parameter setup, then a ycp_edit/ycp_temp
swap and `return 1`, with no worker dispatch anywhere in the body.

Read the output knowing angr cannot lift x87: the distance calculation at the
top of each worker's inner loop comes out as `/* unsupported instruction */`
followed by a call to sub_10091ad8, and disasm_params.py covers that gap.
Note also that angr renders the `sumY <= threshold` exit as if it fell into
the centre-pixel path; the raw disassembly shows it jumping to the "write a
transparent pixel" tail instead (verify_output_encoding.py).

Run via main.py:
    uv run main.py inspect/glint/decompile_glint.py
    uv run main.py inspect/glint/decompile_glint.py --only 0x1004e560
"""

import argparse

from tools.decompile import decompile_targets

TARGETS = {
    "func_proc - params, canvas growth, dispatch, final blit": 0x1004E560,
    "worker: ray sampling, source colour (ex_data bit24 set)": 0x1004E9C0,
    "worker: ray sampling, configured colour (bit24 clear)": 0x1004EE20,
    "func_proc of the UNREGISTERED frame-filter twin (stub)": 0x1004F260,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", help="decompile just this VA")
    parser.add_argument("--span", default="0x1200", help="CFG window past the highest address")
    args = parser.parse_args(argv or [])

    targets = TARGETS
    if args.only:
        addr = int(args.only, 0)
        targets = {k: v for k, v in TARGETS.items() if v == addr} or {f"sub_{addr:08x}": addr}

    decompile_targets(dll_path, targets, span=int(args.span, 0))


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
