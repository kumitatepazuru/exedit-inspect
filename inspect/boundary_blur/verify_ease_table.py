"""Derive the lookup table the OFF-path (境界ぼかし's default, checkbox
unchecked) erosion worker sub_10011db0 reads at runtime, and prove - by
address arithmetic alone, no emulation needed - that its two access patterns
("g_101dcf78[v]" forward and "g_101def78[-h]" backward) hit the SAME table.

The table itself is not part of the PE file: 0x101dcf78 falls past
.data's raw (on-disk) size, in the zero-filled tail pefile already pads with
zeroes (see the section dump this script prints). It is filled at runtime by
a shared exedit init routine at 0x1006c680, found by searching the whole
.text section for the immediate operand 0x101dcf78/0x101def78 (13 hits; most
are OTHER filters reusing the same shared table - 境界ぼかし is not the only
consumer). The raw capstone dump of 0x1006c680's table-writing loop is:

    0x1006c6bf: xor esi, esi
    0x1006c6c5: fild dword [esp+0x10]          ; esi as double
    0x1006c6c9: fmul qword [0x1009a758]        ; * (pi/4096)
    0x1006c6cf: fcos
    0x1006c6d1: fmul qword [0x1009a4f8]        ; * 2048.0
    0x1006c6d7: fsubr qword [0x1009a4f8]       ; 2048.0 - (...)
    0x1006c6dd: call 0x10091ad8                ; double -> int, truncating
    0x1006c6e2: mov word [esi*2 + 0x101dcf78], ax
    0x1006c6ea: inc esi
    0x1006c6eb: cmp esi, 0x1000
    0x1006c6f5: jle 0x1006c6c5                 ; esi = 0..4096 inclusive

i.e. table[i] = trunc(2048 * (1 - cos(i * pi/4096)))  for i in 0..4096.
0x1009a758/0x1009a4f8 are read directly out of .rdata below - they are
literal doubles baked into the binary, so THIS part is checked against the
actual file bytes, not assumed.

sub_10011db0 (verify_off_path.py) indexes this same 4097-entry array two
ways: forward as g_101dcf78[t] for a value t already in [0,4096], and
backward as *(0x101def78 - 2*t) for a ratio t also in [0,4096]. This script's
only real "verification" is arithmetic: 0x101dcf78 + 4096*2 == 0x101def78,
i.e. 0x101def78 is exactly &table[4096], so the backward form is
table[4096 - t] - the same easing curve, mirrored.

Run via main.py:
    uv run main.py inspect/boundary_blur/verify_ease_table.py
"""

import math

from tools.pe_image import PEImage

C1_VA = 0x1009A758  # pi/4096
C2_VA = 0x1009A4F8  # 2048.0
TABLE_LO = 0x101DCF78  # table[0]
TABLE_HI = 0x101DEF78  # claimed to be table[4096]


def trunc_double_to_int(x):
    """sub_10091ad8: CRT double->int helper used throughout exedit (see
    inspect/blur, inspect/glow READMEs) - truncates toward zero."""
    return math.trunc(x)


def ease(i, c1, c2):
    """table[i], i in 0..4096, using the doubles read straight from .rdata."""
    return trunc_double_to_int(c2 * (1 - math.cos(i * c1)))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    image_base = img.image_base

    data_raw_end = None
    for s in img.pe.sections:
        name = s.Name.decode(errors="replace").strip("\x00")
        va0 = image_base + s.VirtualAddress
        va1 = va0 + s.Misc_VirtualSize
        raw_end = va0 + s.SizeOfRawData
        print(f"  section {name:8s} VA=0x{va0:08x}-0x{va1:08x}  raw(file) ends at 0x{raw_end:08x}")
        if va0 <= TABLE_LO < va1:
            data_raw_end = raw_end
    print(f"  table target 0x{TABLE_LO:08x} is {'PAST' if TABLE_LO >= data_raw_end else 'inside'} "
          f"the raw file image for its section -> runtime-initialized, not a static const array")

    c1 = img.f64(C1_VA)
    c2 = img.f64(C2_VA)
    print(f"\n--- constants read directly from .rdata ---")
    print(f"  0x{C1_VA:08x} = {c1!r}   (pi/4096 = {math.pi / 4096!r}, exact match: {c1 == math.pi / 4096})")
    print(f"  0x{C2_VA:08x} = {c2!r}   (exactly 2048.0: {c2 == 2048.0})")

    print(f"\n--- address arithmetic: is 0x{TABLE_HI:08x} really &table[4096]? ---")
    computed_hi = TABLE_LO + 4096 * 2
    print(f"  0x{TABLE_LO:08x} + 4096*2 = 0x{computed_hi:08x}  -> "
          f"{'MATCHES' if computed_hi == TABLE_HI else 'DOES NOT MATCH'} the address "
          f"sub_10011db0 uses as its backward-indexing base")
    print("  (sub_10011db0's `mov ecx, 0x101def78; sub ecx, eax` with eax=2*t is\n"
          "   therefore reading table[4096 - t] out of the exact same array,\n"
          "   not a second, separate table)")

    print("\n--- the easing curve itself: table[i] = trunc(2048*(1-cos(i*pi/4096))), i=0..4096 ---")
    table = [ease(i, c1, c2) for i in range(4097)]
    print(f"  table[0]    = {table[0]}   (no erosion contribution at the ramp's start)")
    print(f"  table[1024] = {table[1024]}")
    print(f"  table[2048] = {table[2048]}   (theoretical midpoint 2048*(1-cos(pi/2))=2048.0,"
          f" off by one from truncating cos(pi/2)={math.cos(math.pi / 2)!r} instead of exact 0)")
    print(f"  table[3072] = {table[3072]}")
    print(f"  table[4096] = {table[4096]}   (2048*(1-cos(pi)) = 4096, the ramp's max)")
    monotonic = all(table[i] <= table[i + 1] for i in range(4096))
    print(f"  monotonically non-decreasing over 0..4096: {monotonic}")
    print("  shape: a raised-cosine (\"smoothstep\"-like) ease-in curve, not linear and not\n"
          "  a true circular arc - convex near 0, concave near 4096, point-symmetric about\n"
          "  the midpoint. This is what makes the OFF-path corner fade look like a soft\n"
          "  rounded corner instead of a mitred (diagonal-cut) one.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
