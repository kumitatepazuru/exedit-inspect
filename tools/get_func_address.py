"""Walk the FILTER_DLL pointer table embedded in exedit.auf and dump every
registered filter's struct address, flags, and func_proc/func_init pointers.

Run through main.py, e.g.:
    uv run main.py tools.get_func_address
    uv run main.py tools.get_func_address --dll-path data/exedit.auf
"""

import struct

import pefile

# from Ghidra label PTR_DAT_100a3e28 (address is embedded in the name)
HEAD_VA = 0x100A3E28

# FILTER_DLL field offsets (see data/filter.h) on 32-bit (4-byte fields/pointers)
FLAG_OFFSET = 0x00
NAME_PTR_OFFSET = 0x0C
FUNC_PROC_OFFSET = 0x30
FUNC_INIT_OFFSET = 0x34


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    pe = pefile.PE(dll_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()  # maps sections into one contiguous buffer indexed by RVA

    def va_to_rva(va):
        return va - image_base

    def read_dword_at_va(va):
        rva = va_to_rva(va)
        if rva < 0 or rva + 4 > len(data):
            return None
        return struct.unpack_from("<I", data, rva)[0]

    def read_cstring_bytes_at_va(va, max_len=128):
        rva = va_to_rva(va)
        if rva < 0 or rva >= len(data):
            return b""
        end = data.find(b"\x00", rva, rva + max_len)
        if end == -1:
            end = rva + max_len
        return data[rva:end]

    def is_plausible_va(va):
        # sanity check: must fall inside the mapped image
        if va is None:
            return False
        rva = va_to_rva(va)
        return 0 <= rva < len(data)

    idx = 0
    ptr_va = HEAD_VA
    while True:
        entry_va = read_dword_at_va(ptr_va)
        if entry_va is None:
            print("STOP: pointer table address out of mapped range at idx=%d (0x%x)" % (idx, ptr_va))
            break
        if entry_va == 0:
            print("STOP: NULL terminator reached at idx=%d" % idx)
            break
        if not is_plausible_va(entry_va):
            print("STOP: entry_va 0x%x looks invalid at idx=%d -- assumption about array format is probably wrong" % (entry_va, idx))
            break

        flag = read_dword_at_va(entry_va + FLAG_OFFSET) or 0
        name_ptr = read_dword_at_va(entry_va + NAME_PTR_OFFSET)
        func_proc = read_dword_at_va(entry_va + FUNC_PROC_OFFSET) or 0
        func_init = read_dword_at_va(entry_va + FUNC_INIT_OFFSET) or 0

        name_bytes = b""
        if is_plausible_va(name_ptr):
            name_bytes = read_cstring_bytes_at_va(name_ptr)
        name_str = name_bytes.decode("cp932", errors="replace")

        print("[%d] struct=0x%08x flag=0x%08x func_proc=0x%08x func_init=0x%08x name=%s" % (
            idx, entry_va, flag, func_proc, func_init, name_str
        ), flush=True)

        idx += 1
        ptr_va += 4

    print("Done. %d entries found." % idx)


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
