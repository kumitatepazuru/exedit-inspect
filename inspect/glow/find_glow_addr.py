"""Locate the 発光 (glow) filter's FILTER_DLL entry in exedit.auf and dump its
full struct: func_proc/func_init addresses plus its trackbar and checkbox
definitions (names, defaults, ranges), so later disassembly/decompilation can
be tied back to the parameters exposed in the AviUtl UI.

Run via main.py:
    uv run main.py inspect/glow/find_glow_addr.py
    uv run main.py inspect/glow/find_glow_addr.py --target-name "ノイズ"   # reusable for other filters
"""

import argparse
import struct

import pefile

HEAD_VA = 0x100A3E28
DEFAULT_TARGET_NAME = "発光"

# FILTER_DLL field offsets, 32-bit (see data/filter.h)
OFF_FLAG = 0x00
OFF_NAME = 0x0C
OFF_TRACK_N = 0x10
OFF_TRACK_NAME = 0x14
OFF_TRACK_DEFAULT = 0x18
OFF_TRACK_S = 0x1C
OFF_TRACK_E = 0x20
OFF_CHECK_N = 0x24
OFF_CHECK_NAME = 0x28
OFF_CHECK_DEFAULT = 0x2C
OFF_FUNC_PROC = 0x30
OFF_FUNC_INIT = 0x34


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-name", default=DEFAULT_TARGET_NAME)
    args = parser.parse_args(argv or [])

    pe = pefile.PE(dll_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()

    def va_to_rva(va):
        return va - image_base

    def read_dword(va):
        rva = va_to_rva(va)
        if rva < 0 or rva + 4 > len(data):
            return None
        return struct.unpack_from("<I", data, rva)[0]

    def read_dword_signed(va):
        rva = va_to_rva(va)
        if rva < 0 or rva + 4 > len(data):
            return None
        return struct.unpack_from("<i", data, rva)[0]

    def read_cstring(va, max_len=128):
        rva = va_to_rva(va)
        if rva < 0 or rva >= len(data):
            return b""
        end = data.find(b"\x00", rva, rva + max_len)
        if end == -1:
            end = rva + max_len
        return data[rva:end]

    def plausible(va):
        if va is None:
            return False
        rva = va_to_rva(va)
        return 0 <= rva < len(data)

    def read_int_array(va, n):
        out = []
        for i in range(n):
            v = read_dword_signed(va + i * 4)
            out.append(v)
        return out

    def read_str_array(va, n):
        out = []
        for i in range(n):
            p = read_dword(va + i * 4)
            if plausible(p):
                out.append(read_cstring(p).decode("cp932", errors="replace"))
            else:
                out.append(None)
        return out

    ptr_va = HEAD_VA
    idx = 0
    found = []
    while True:
        entry_va = read_dword(ptr_va)
        if not plausible(entry_va) or entry_va == 0:
            break

        name_ptr = read_dword(entry_va + OFF_NAME)
        name = read_cstring(name_ptr).decode("cp932", errors="replace") if plausible(name_ptr) else ""

        if name == args.target_name:
            flag = read_dword(entry_va + OFF_FLAG)
            func_proc = read_dword(entry_va + OFF_FUNC_PROC)
            func_init = read_dword(entry_va + OFF_FUNC_INIT)
            track_n = read_dword(entry_va + OFF_TRACK_N) or 0
            check_n = read_dword(entry_va + OFF_CHECK_N) or 0

            track_name_ptr = read_dword(entry_va + OFF_TRACK_NAME)
            track_default_ptr = read_dword(entry_va + OFF_TRACK_DEFAULT)
            track_s_ptr = read_dword(entry_va + OFF_TRACK_S)
            track_e_ptr = read_dword(entry_va + OFF_TRACK_E)
            check_name_ptr = read_dword(entry_va + OFF_CHECK_NAME)
            check_default_ptr = read_dword(entry_va + OFF_CHECK_DEFAULT)

            track_names = read_str_array(track_name_ptr, track_n) if plausible(track_name_ptr) else []
            track_defaults = read_int_array(track_default_ptr, track_n) if plausible(track_default_ptr) else []
            track_s = read_int_array(track_s_ptr, track_n) if plausible(track_s_ptr) else []
            track_e = read_int_array(track_e_ptr, track_n) if plausible(track_e_ptr) else []
            check_names = read_str_array(check_name_ptr, check_n) if plausible(check_name_ptr) else []
            check_defaults = read_int_array(check_default_ptr, check_n) if plausible(check_default_ptr) else []

            found.append({
                "idx": idx,
                "struct_va": entry_va,
                "flag": flag,
                "func_proc": func_proc,
                "func_init": func_init,
                "track_n": track_n,
                "check_n": check_n,
                "track_names": track_names,
                "track_defaults": track_defaults,
                "track_s": track_s,
                "track_e": track_e,
                "check_names": check_names,
                "check_defaults": check_defaults,
            })

        idx += 1
        ptr_va += 4

    if not found:
        print(f"no filter named {args.target_name!r} found")
        return

    for f in found:
        print("=" * 60)
        print(f"[{f['idx']}] struct=0x{f['struct_va']:08x} flag=0x{f['flag']:08x}")
        print(f"  func_proc = 0x{f['func_proc']:08x}")
        print(f"  func_init = 0x{f['func_init']:08x}")
        print(f"  track_n={f['track_n']} check_n={f['check_n']}")
        for i in range(f["track_n"]):
            name = f["track_names"][i] if i < len(f["track_names"]) else None
            default = f["track_defaults"][i] if i < len(f["track_defaults"]) else None
            s = f["track_s"][i] if i < len(f["track_s"]) else None
            e = f["track_e"][i] if i < len(f["track_e"]) else None
            print(f"    track[{i}] name={name!r} default={default} range=[{s},{e}]")
        for i in range(f["check_n"]):
            name = f["check_names"][i] if i < len(f["check_names"]) else None
            default = f["check_defaults"][i] if i < len(f["check_defaults"]) else None
            print(f"    check[{i}] name={name!r} default={default}")


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
