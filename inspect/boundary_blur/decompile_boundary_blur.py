"""Decompile/disassemble the 境界ぼかし (boundary blur) filter's func_proc in
exedit.auf.

func_proc's address (0x10011b00) came from `tools.filter_table --name 境界ぼかし`. This
script builds a small angr CFG over a narrow byte range around it (much
faster than a whole-binary CFG, and it avoids dragging in unrelated
functions), then runs angr's Decompiler on func_proc and on whatever worker
functions it calls.

Unlike ぼかし/発光, 境界ぼかし is registered only ONCE (object effect only,
flag=0x20) - see `tools.filter_table --name 境界ぼかし`. So there is no frame-filter
sibling to compare against.

Run via main.py:
    uv run main.py inspect/boundary_blur/decompile_boundary_blur.py
    uv run main.py inspect/boundary_blur/decompile_boundary_blur.py --span 0x5000
"""

import argparse

import angr

from tools.decompile import build_cfg, decompile_one

FUNC_PROC = 0x10011B00


def _decompile(proj, cfg, addr, label):
    print(f"\n{'=' * 74}\n{label}  (0x{addr:08x})\n{'=' * 74}")
    func = cfg.functions.function(addr=addr)
    if func is None:
        print("  ! angr did not recover a function at this address")
        return None
    try:
        text = proj.analyses.Decompiler(func, cfg=cfg.model).codegen.text
        print(text)
        return text
    except Exception as e:
        print(f"  ! decompilation failed: {e}")
        return None


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--span", type=lambda x: int(x, 0), default=0x4000, help="byte span of the CFG region starting at func_proc's page")
    parser.add_argument("--extra", type=lambda x: int(x, 0), nargs="*", default=[], help="extra addresses to decompile after func_proc")
    args = parser.parse_args(argv or [])

    # The CFG is built here rather than through decompile_targets because this
    # script also lists what angr recovered in the window - that listing is how
    # the worker addresses passed to --extra were found in the first place.
    proj = angr.Project(dll_path, auto_load_libs=False)
    base = FUNC_PROC & ~0xFFF
    cfg = build_cfg(proj, [base], span=args.span)

    print("\nFunctions angr recovered in this region:")
    for f in sorted(cfg.functions.values(), key=lambda f: f.addr):
        print(f"  0x{f.addr:08x}  {f.name}")

    decompile_one(proj, cfg, FUNC_PROC, "func_proc (dispatcher)")
    for addr in args.extra:
        decompile_one(proj, cfg, addr, f"worker 0x{addr:08x}")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
