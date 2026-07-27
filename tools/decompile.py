"""angr-based decompilation of a handful of functions in exedit.auf.

Running CFGFast over the whole 850 KB binary takes minutes and drags in ~100
unrelated filters. Every inspect/ script instead builds a CFG over a narrow
region around the function of interest, which is both fast and keeps angr's
function recovery from merging neighbours. That regioning, plus the
per-function Decompiler invocation and its failure handling, is the same
everywhere, so it lives here.

Two caveats that shape how the output should be read:

  * angr does not lift x87/SSE - anything floating point comes out as
    `/* unsupported instruction */`. exedit does all of its parameter math in
    x87, so the decompilation shows the *shape* of a function (branches, call
    targets, memory it touches) and tools/disasm.py supplies the formulas.
  * a `regions=` window that is too small silently truncates callees. Widen
    --span if a worker decompiles to a stub.

As a library:

    from tools.decompile import decompile_targets
    decompile_targets(dll_path, {"func_proc": 0x1004e560}, span=0x3000)

As a script:

    uv run main.py tools.decompile --addr 0x1004e560
    uv run main.py tools.decompile --addr 0x1004e560 --addr 0x1004f3f0 --span 0x4000
    uv run main.py tools.decompile --addr 0x1004e560 --calls   # list call targets only
"""

import argparse
import logging

import angr

from tools.disasm import disasm_range
from tools.pe_image import PEImage


def build_cfg(proj, addrs, span: int = 0x3000):
    """CFG over a window covering every requested address.

    The window is page-aligned down from the lowest address and extended
    `span` past the highest, so a group of related workers can be recovered in
    one analysis pass.
    """
    logging.getLogger("angr").setLevel(logging.ERROR)
    lo = min(addrs) & ~0xFFF
    hi = max(addrs) + span
    return proj.analyses.CFGFast(regions=[(lo, hi)], force_complete_scan=False, normalize=True)


def decompile_one(proj, cfg, addr: int, label: str = "") -> str | None:
    func = cfg.functions.function(addr=addr)
    print(f"\n{'=' * 74}\n{label or 'sub'}  (0x{addr:08x})\n{'=' * 74}")
    if func is None:
        print("  ! angr did not recover a function at this address")
        return None
    try:
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        text = dec.codegen.text
        print(text)
        return text
    except Exception as e:  # angr raises a wide variety on odd control flow
        print(f"  ! decompilation failed: {e}")
        return None


def decompile_targets(dll_path: str, targets: dict, span: int = 0x3000,
                      region: tuple | None = None) -> None:
    """targets: {label: addr}. `region` pins the CFG window explicitly when a
    script needs the exact window its analysis was originally done with."""
    proj = angr.Project(dll_path, auto_load_libs=False)
    if region is not None:
        logging.getLogger("angr").setLevel(logging.ERROR)
        cfg = proj.analyses.CFGFast(regions=[region], force_complete_scan=False, normalize=True)
    else:
        cfg = build_cfg(proj, list(targets.values()), span)
    for label, addr in targets.items():
        decompile_one(proj, cfg, addr, label)


def decompile_cli(dll_path: str, targets: dict, argv: list[str] | None = None,
                  span: int = 0x3000, region: tuple | None = None,
                  extra: "dict | None" = None) -> None:
    """The `--only <substring>` front end every inspect/*/decompile_*.py wants.

    `extra` is an optional {label: (va, size)} of raw-disassembly companions -
    the tiny x87 CRT stubs angr renders as "unsupported instruction" soup, which
    are worth reading as instructions instead. They are skipped when --only
    narrows the run.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", help="substring of a target label; decompile just those")
    parser.add_argument("--span", default=hex(span), help="CFG window size past the target")
    args = parser.parse_args(argv or [])

    selected = targets
    if args.only:
        selected = {k: v for k, v in targets.items() if args.only in k}
        if not selected:
            print(f"no target label contains {args.only!r}; known: {list(targets)}")
            return

    decompile_targets(dll_path, selected, span=int(args.span, 0), region=region)

    if extra and not args.only:
        img = PEImage(dll_path)
        for label, (addr, size) in extra.items():
            print(f"\n{'=' * 74}\n{label}  (0x{addr:08x}, raw capstone disassembly)\n{'=' * 74}")
            for insn, _ in disasm_range(img, addr, size, resolve=False):
                print(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")


def call_targets(img: PEImage, addr: int, size: int = 0x400) -> list[int]:
    """Direct `call 0x...` targets in a byte range, in order, deduplicated.

    Cheaper and more reliable than reading them out of decompiled text when
    all that is wanted is "which workers does this dispatcher reach".
    """
    seen, out = set(), []
    for insn, _ in disasm_range(img, addr, size, resolve=False):
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            t = int(insn.op_str, 16)
            if t not in seen:
                seen.add(t)
                out.append(t)
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="tools.decompile")
    parser.add_argument("--addr", action="append", required=True, help="function VA; repeatable")
    parser.add_argument("--span", default="0x3000", help="bytes past the highest address to include in the CFG")
    parser.add_argument("--calls", action="store_true",
                        help="just list direct call targets in the range, do not decompile")
    parser.add_argument("--size", default="0x400", help="range scanned by --calls")
    args = parser.parse_args(argv or [])

    addrs = [int(a, 0) for a in args.addr]

    if args.calls:
        img = PEImage(dll_path)
        for a in addrs:
            print(f"call targets from 0x{a:08x}:")
            for t in call_targets(img, a, int(args.size, 0)):
                print(f"  0x{t:08x}")
        return

    decompile_targets(dll_path, {f"sub_{a:08x}": a for a in addrs}, span=int(args.span, 0))


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
