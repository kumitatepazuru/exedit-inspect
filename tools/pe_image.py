"""Shared PE/VA plumbing for every script in this project.

Every inspect/ script starts the same way: open data/exedit.auf with pefile,
map its sections into one RVA-indexed buffer, and then read things at *virtual*
addresses because that is what Ghidra/angr print and what the DLL's own
pointers contain. This module holds that boilerplate once.

    from tools.pe_image import PEImage

    img = PEImage(dll_path)
    img.u32(0x100a59f8)          # unsigned dword at a VA
    img.i32(0x100a59f8, )        # signed dword
    img.f64(0x1009a3b0)          # double constant (FP immediates live in .rdata)
    img.cstr(ptr)                # cp932 C string (filter/track names are cp932)
    img.valid(ptr)               # does this VA land inside the mapped image?
    img.code(0x1004e560, 0x200)  # raw bytes for capstone

Nothing here is exedit-specific; tools/filter_table.py builds on it.
"""

import struct

import pefile


class PEImage:
    """A memory-mapped PE, addressed by VA."""

    def __init__(self, dll_path: str):
        self.path = dll_path
        self.pe = pefile.PE(dll_path)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = self.pe.get_memory_mapped_image()

    # -- address helpers ---------------------------------------------------

    def rva(self, va: int) -> int:
        return va - self.image_base

    def valid(self, va: int | None, size: int = 1) -> bool:
        """True when `size` bytes starting at `va` are inside the mapped image.

        Used as a sanity check before dereferencing anything read out of the
        binary: a pointer that fails this is a sign the struct layout being
        assumed is wrong, which is worth catching loudly rather than reading
        garbage.
        """
        if va is None:
            return False
        r = va - self.image_base
        return 0 <= r and r + size <= len(self.data)

    # -- scalar reads ------------------------------------------------------

    def _unpack(self, fmt: str, va: int, size: int):
        if not self.valid(va, size):
            return None
        return struct.unpack_from(fmt, self.data, va - self.image_base)[0]

    def u8(self, va: int):
        return self._unpack("<B", va, 1)

    def i8(self, va: int):
        return self._unpack("<b", va, 1)

    def u16(self, va: int):
        return self._unpack("<H", va, 2)

    def i16(self, va: int):
        return self._unpack("<h", va, 2)

    def u32(self, va: int):
        return self._unpack("<I", va, 4)

    def i32(self, va: int):
        return self._unpack("<i", va, 4)

    def f32(self, va: int):
        return self._unpack("<f", va, 4)

    def f64(self, va: int):
        return self._unpack("<d", va, 8)

    # -- aggregate reads ---------------------------------------------------

    def cstr(self, va: int, max_len: int = 128, encoding: str = "cp932") -> str:
        """NUL-terminated string at a VA. exedit's UI strings are all cp932."""
        if not self.valid(va):
            return ""
        r = va - self.image_base
        end = self.data.find(b"\x00", r, r + max_len)
        return self.data[r:end if end != -1 else r + max_len].decode(encoding, "replace")

    def u32_array(self, va: int, n: int) -> list:
        return [self.u32(va + 4 * i) for i in range(n)]

    def i32_array(self, va: int, n: int) -> list:
        return [self.i32(va + 4 * i) for i in range(n)]

    def str_array(self, va: int, n: int) -> list:
        """Array of `char*`, dereferenced. Entries that do not point into the
        image come back as None instead of raising."""
        out = []
        for i in range(n):
            p = self.u32(va + 4 * i)
            out.append(self.cstr(p) if self.valid(p) else None)
        return out

    def code(self, va: int, size: int) -> bytes:
        r = va - self.image_base
        return self.data[max(r, 0):r + size]
