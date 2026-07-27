"""Establish how ぼかし's four box-blur passes are wired together: the order
they run in, the radius each one gets, and which of them is vertical.

ぼかし does not run one blur - it runs the same box average four times, and
the interesting question is whether those four are four independent blurs or
one chain. They are a chain: every pass reads the current image and writes the
pair buffer, and func_proc swaps the two pointers afterwards, so pass N+1
blurs pass N's output. Two chained box passes per axis convolve into a
triangular kernel, which is what makes ぼかし look smooth rather than boxy
(verify_radius_split.py checks the kernel arithmetic).

func_proc hands the radii to the workers through four fixed globals rather
than through arguments, because MULTI_THREAD_FUNC only gets (thread_id,
thread_num, fp, fpip). This script reads those hand-offs and then scans all
twelve workers for which globals each one actually consumes - that is what
proves the vertical/horizontal split rather than assuming it from the order.

    0x1011ec34  radius of the vertical pass
    0x1011ec38  radius of the horizontal pass
    0x1011ec3c  kernel width of the vertical pass   = 2*radius + 1
    0x1011ec40  kernel width of the horizontal pass = 2*radius + 1

Run via main.py:
    uv run main.py inspect/blur/verify_pass_chain.py
"""

import re

from tools.disasm import disasm_range, function_body
from tools.pe_image import PEImage

FUNC_PROC = (0x1000E2F0, 0x7E4)

G_RADIUS_V = 0x1011EC34
G_RADIUS_H = 0x1011EC38
G_KERNEL_V = 0x1011EC3C
G_KERNEL_H = 0x1011EC40

GLOBALS = {
    G_RADIUS_V: "radius, vertical pass",
    G_RADIUS_H: "radius, horizontal pass",
    G_KERNEL_V: "kernel width, vertical pass   (2*radius+1)",
    G_KERNEL_H: "kernel width, horizontal pass (2*radius+1)",
}

WORKERS = {
    0x1000EAE0: "int  / object / サイズ固定 off",
    0x1000EEF0: "int  / object / サイズ固定 off",
    0x1000F310: "int  / object / サイズ固定 on",
    0x1000F7E0: "int  / object / サイズ固定 on",
    0x1000FCB0: "int  / frame",
    0x1000FF40: "int  / frame",
    0x10010190: "curve/ object / サイズ固定 off",
    0x100105E0: "curve/ object / サイズ固定 off",
    0x10010A30: "curve/ object / サイズ固定 on",
    0x10010F20: "curve/ object / サイズ固定 on",
    0x10011400: "curve/ frame",
    0x100116D0: "curve/ frame",
}
# Workers are laid out back to back, each ending in `ret` followed by nop
# padding (between 2 and 14 nops here). Scanning a fixed span instead would
# spill into the next worker and make every function look like it reads both
# axes' globals - which is exactly the mistake this script exists to rule out.
WORKER_SCAN_LIMIT = 0x700

# The four `mov [global], reg` hand-offs, in program order.
PUBLISH_SITES = {
    0x1000E579: "pass 1 setup: [0x1011ec38] = rx_hi (kept for pass 2)",
    0x1000E581: "pass 1 setup: [0x1011ec34] = ry_hi",
    0x1000E587: "ry_hi == 0 -> skip pass 1 entirely (and skip its buffer swap)",
    0x1000E58D: "pass 1: kernel = 2*ry_hi + 1",
    0x1000E592: "pass 1: [0x1011ec3c] = kernel  -> VERTICAL worker",
    0x1000E61B: "pass 2: reload rx_hi from [0x1011ec38]",
    0x1000E628: "pass 2: kernel = 2*rx_hi + 1",
    0x1000E62D: "pass 2: [0x1011ec40] = kernel  -> HORIZONTAL worker",
    0x1000E6BA: "pass 3 setup: [0x1011ec38] = rx_lo",
    0x1000E6C0: "pass 3 setup: [0x1011ec34] = ry_lo",
    0x1000E6D0: "pass 3: [0x1011ec3c] = 2*ry_lo + 1  -> VERTICAL worker",
    0x1000E763: "pass 4: [0x1011ec40] = 2*rx_lo + 1  -> HORIZONTAL worker",
    0x1000E842: "(光の強さ == 0 copy of the same four passes starts here)",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    insns = [i for i, _ in disasm_range(img, *FUNC_PROC, resolve=False)]

    print("--- how func_proc hands each pass its radius ---")
    for insn in insns:
        if not any(f"0x{g:08x}" in insn.op_str for g in GLOBALS):
            continue
        note = PUBLISH_SITES.get(insn.address, "")
        which = next(GLOBALS[g] for g in GLOBALS if f"0x{g:08x}" in insn.op_str)
        write = "write" if insn.op_str.startswith("dword ptr [0x") else "read "
        print(f"0x{insn.address:08x}: {write} {which:44s}"
              f"{'  <-- ' + note if note else ''}")

    print("\n--- which radius/kernel globals each worker reads ---")
    print("    worker      bytes  role                            globals consumed")
    verdict = {}
    for addr, kind in WORKERS.items():
        insns_w = function_body(img, addr, WORKER_SCAN_LIMIT)
        length = insns_w[-1].address + insns_w[-1].size - addr
        found = set()
        for insn in insns_w:
            for m in re.finditer(r"0x1011ec(?:34|38|3c|40)", insn.op_str):
                found.add(int(m.group(0), 16))
        axis = ("VERTICAL" if found and found <= {G_RADIUS_V, G_KERNEL_V}
                else "HORIZONTAL" if found and found <= {G_RADIUS_H, G_KERNEL_H}
                else "MIXED (!)")
        verdict[addr] = axis
        names = ", ".join(f"0x{g:08x}" for g in sorted(found))
        print(f"    0x{addr:08x}  0x{length:04x}  {kind:30s}  {names}   -> {axis}")

    mixed = [a for a, v in verdict.items() if v == "MIXED (!)"]
    print(f"\n  every worker reads exactly one axis' pair of globals: "
          f"{'yes' if not mixed else 'NO - ' + str(mixed)}")

    print(
        "\n"
        "Verdict: four chained passes, in this order, each skipped when its\n"
        "radius is 0 (a skipped pass also skips its buffer swap):\n"
        "\n"
        "    pass 1  VERTICAL    radius ry_hi = ry - ry//2\n"
        "    pass 2  HORIZONTAL  radius rx_hi = rx - rx//2\n"
        "    pass 3  VERTICAL    radius ry_lo = ry//2\n"
        "    pass 4  HORIZONTAL  radius rx_lo = rx//2\n"
        "\n"
        "  Each pass reads the current image and writes the pair buffer, and\n"
        "  func_proc then swaps them - so this is a chain, not four independent\n"
        "  blurs, and the two passes per axis convolve into a triangular kernel\n"
        "  of total radius exactly 範囲 (verify_radius_split.py).\n"
        "\n"
        "  func_proc contains this four-pass block twice: once for 光の強さ > 0\n"
        "  (float-luma workers, sandwiched between the forward/inverse curve)\n"
        "  and once for 光の強さ == 0 (plain 16-bit workers, no curve at all).\n"
    )


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
