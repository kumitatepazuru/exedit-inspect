"""The centre pixel takes a different path, and that path reads a stack slot
nothing has written for it.

verify_ray_geometry.py shows the ray code bails out to 0x1004ecbd (worker 1) /
0x1004f109 (worker 2) when the sample count or the ray length would be under
2, which happens only within a quarter pixel of (cx, cy) - the one pixel the
glint centre lands on. That path does not sample anything. It reads the source
pixel under the cursor, multiplies it by an alpha, thresholds it, and writes
it with the same encoding as everywhere else.

The alpha it multiplies by is `[esp+0x48]`. This script disassembles both
workers and lists every access to that slot, which is the whole finding:

  * it is written in exactly one place, inside the sampling loop, from the
    alpha of a source sample that was in bounds
  * it is read in exactly one place, the centre path - which is only reached
    when that loop did not run for this pixel

So the centre pixel is weighted by the alpha of the last sample taken for some
*earlier* destination pixel in the same thread's scan order, and by whatever
was on the stack if no earlier pixel in that thread ever sampled anything in
bounds. Worker 2 makes it starker: its centre path never touches the source
image at all, it multiplies the configured colour by that borrowed alpha.

The blast radius is one pixel (occasionally a handful when the centre falls on
a pixel boundary), it is deterministic for a given frame and thread split, and
it changes when the thread count changes because the scan order does. Worth
knowing before treating a reimplementation's centre pixel as a bug.

Run via main.py:
    uv run main.py inspect/glint/verify_center_pixel.py
"""

import re

from tools.disasm import disasm_range
from tools.pe_image import PEImage

WORKERS = {
    "0x1004e9c0 (source colour)": (0x1004E9C0, 0x455, 0x1004ECBD),
    "0x1004ee20 (configured colour)": (0x1004EE20, 0x436, 0x1004F109),
}
SLOT = re.compile(r"\[esp \+ 0x48\]")


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("1) every access to the stack slot the centre path multiplies by")
    for label, (start, size, degen) in WORKERS.items():
        print(f"\n   {label}   centre path begins at 0x{degen:08x}")
        writes = reads = 0
        for insn, _ in disasm_range(img, start, size, resolve=False):
            if not SLOT.search(insn.op_str):
                continue
            is_write = insn.op_str.startswith("dword ptr [esp + 0x48]")
            where = "centre path" if insn.address >= degen else "sampling loop"
            writes, reads = writes + is_write, reads + (not is_write)
            print(f"     0x{insn.address:08x}  {'W' if is_write else 'R'}  "
                  f"{insn.mnemonic} {insn.op_str:<34} ({where})")
        print(f"     -> {writes} write(s), {reads} read(s)")

    print("\n2) why that is a stale read")
    print("   The single write sits after the in-bounds test inside the sampling loop")
    print("   (`movsx edx, word ptr [eax + ecx*8 + 6]` - the sample's alpha). The single")
    print("   read is in the centre path, which is entered only when the loop is skipped")
    print("   for this pixel. Nothing initialises the slot at function entry or at the")
    print("   top of the pixel loop, so the value is left over from a previous pixel.")

    print("\n3) how often it is reached")
    print("   The centre path needs dist8 <= 2, i.e. the pixel centre within 0.25 px of")
    print("   (cx, cy): one destination pixel per thread-slice at most, and only for the")
    print("   thread whose row range contains cy. Every other pixel goes through the ray.")

    print("\n4) what a faithful reimplementation has to decide")
    print("   There is no correct value to substitute - the reference simulation in")
    print("   simulate_glint_reference.py carries the same slot explicitly so it can")
    print("   reproduce the artifact, and takes 0 for the 'nothing sampled yet' case,")
    print("   which is what a zeroed stack would give. Any other choice changes exactly")
    print("   one pixel, and exedit itself will not agree with it run to run.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
