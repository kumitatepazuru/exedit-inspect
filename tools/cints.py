"""C / x86 integer semantics, so a Python re-implementation can be compared
against the disassembly instead of merely resembling it.

Python's `//` floors and its `>>` is arithmetic on arbitrary precision, which
matches x86 `sar` but *not* C's `/`. exedit mixes the two freely - `sar eax,
0xc` for fixed-point scaling right next to `idiv` for averaging - and the two
disagree on every negative dividend, which is exactly where chroma lives
(Cb/Cr are signed). Getting this wrong produces a simulation that matches on
greys and drifts on colour.

    c_div(-7, 2)   == -3      # C / and x86 idiv: truncate toward zero
    -7 // 2        == -4      # Python: floor
    sar(-7, 1)     == -4      # x86 sar: floor, same as Python >>

msvc_div is the compiler-generated constant division that shows up all over
exedit as `mov eax, <magic>; imul <src>; sar edx, <shift>; ...sign fixup`. It
is spelled out here so a script can assert that a particular magic/shift pair
really is "divide by N" rather than taking it on trust.
"""

MAGIC_1000 = 0x10624DD3  # ceil(2**38 / 1000); the shift picks the divisor


def c_div(a: int, b: int) -> int:
    """C's `/` on ints - and x86 `idiv` - i.e. truncation toward zero."""
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def c_mod(a: int, b: int) -> int:
    """C's `%`: sign follows the dividend."""
    return a - b * c_div(a, b)


def sar(x: int, n: int) -> int:
    """x86 `sar` / Python `>>`: arithmetic shift, i.e. floor division by 2**n.

    Present as a named function purely so call sites read as "this is a shift,
    not a divide" - the distinction that c_div exists to make.
    """
    return x >> n


def to_i32(x: int) -> int:
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x & 0x80000000 else x


def msvc_div(x: int, magic: int = MAGIC_1000, shift: int = 6) -> int:
    """Replay MSVC's signed constant division literally.

        mov  eax, magic
        imul src            ; edx:eax = eax * src  (edx = high dword)
        sar  edx, shift
        mov  eax, edx
        shr  eax, 31        ; +1 if the quotient came out negative
        add  edx, eax

    With magic = 0x10624dd3, shift 6 divides by 1000 and shift 4 by 250.
    """
    hi = to_i32((x * magic) >> 32)
    q = hi >> shift
    return q + (1 if q < 0 else 0)


def divisor_of(magic: int, shift: int, lo: int = -(1 << 22), hi: int = 1 << 22) -> int | None:
    """Which constant divisor does this (magic, shift) pair implement?

    The candidate comes from the identity the magic encodes, magic ~
    2**(32+shift) / d, and is then checked against c_div over the whole range,
    so a script can print "shift 4 really is /250" as a verified fact rather
    than as arithmetic the reader has to trust.
    """
    d = round((1 << (32 + shift)) / magic)
    if d == 0:
        return None
    for x in range(lo, hi, 997):
        if msvc_div(x, magic, shift) != c_div(x, d):
            return None
    return d
