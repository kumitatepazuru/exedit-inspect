"""Locate the 境界ぼかし (boundary blur) filter's FILTER_DLL entry in exedit.auf
and dump its full struct: func_proc address plus its trackbar and checkbox
definitions (names, defaults, ranges), so later disassembly/decompilation can
be tied back to the parameters exposed in the AviUtl UI.

Unlike ぼかし/発光 (see inspect/blur, inspect/glow), 境界ぼかし is registered
only ONCE - as an object effect (flag & 0x20), with no frame(video)-filter
sibling. This script prints how many registrations it finds so that fact
stays checked instead of assumed.

Run via main.py:
    uv run main.py inspect/boundary_blur/find_boundary_blur_addr.py
"""

import argparse
import struct

import pefile

HEAD_VA = 0x100A3E28
DEFAULT_TARGET_NAME = "境界ぼかし"

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

    def read_dword(va, signed=False):
        rva = va - image_base
        if rva < 0 or rva + 4 > len(data):
            return None
        return struct.unpack_from("<i" if signed else "<I", data, rva)[0]

    def plausible(va):
        return va is not None and 0 <= va - image_base < len(data)

    def read_cstring(va, max_len=128):
        rva = va - image_base
        if rva < 0 or rva >= len(data):
            return ""
        end = data.find(b"\x00", rva, rva + max_len)
        if end == -1:
            end = rva + max_len
        return data[rva:end].decode("cp932", errors="replace")

    def read_array(va, n, as_str):
        out = []
        for i in range(n):
            if as_str:
                p = read_dword(va + i * 4)
                out.append(read_cstring(p) if plausible(p) else None)
            else:
                out.append(read_dword(va + i * 4, signed=True))
        return out

    found = []
    idx, ptr_va = 0, HEAD_VA
    while True:
        entry_va = read_dword(ptr_va)
        if not plausible(entry_va) or entry_va == 0:
            break
        name_ptr = read_dword(entry_va + OFF_NAME)
        if plausible(name_ptr) and read_cstring(name_ptr) == args.target_name:
            track_n = read_dword(entry_va + OFF_TRACK_N) or 0
            check_n = read_dword(entry_va + OFF_CHECK_N) or 0

            def field(off, n, as_str):
                p = read_dword(entry_va + off)
                return read_array(p, n, as_str) if plausible(p) else []

            found.append({
                "idx": idx,
                "struct_va": entry_va,
                "flag": read_dword(entry_va + OFF_FLAG),
                "func_proc": read_dword(entry_va + OFF_FUNC_PROC),
                "func_init": read_dword(entry_va + OFF_FUNC_INIT),
                "track_n": track_n,
                "check_n": check_n,
                "track_names": field(OFF_TRACK_NAME, track_n, True),
                "track_defaults": field(OFF_TRACK_DEFAULT, track_n, False),
                "track_s": field(OFF_TRACK_S, track_n, False),
                "track_e": field(OFF_TRACK_E, track_n, False),
                "check_names": field(OFF_CHECK_NAME, check_n, True),
                "check_defaults": field(OFF_CHECK_DEFAULT, check_n, False),
            })
        idx += 1
        ptr_va += 4

    if not found:
        print(f"no filter named {args.target_name!r} found")
        return

    for f in found:
        role = "object effect" if f["flag"] & 0x20 else "frame (video) filter"
        print("=" * 66)
        print(f"[{f['idx']}] struct=0x{f['struct_va']:08x} flag=0x{f['flag']:08x}  -> {role}")
        print(f"  func_proc = 0x{f['func_proc']:08x}   func_init = 0x{f['func_init']:08x}")
        for i in range(f["track_n"]):
            print(f"    track[{i}] name={f['track_names'][i]!r} "
                  f"default={f['track_defaults'][i]} "
                  f"range=[{f['track_s'][i]},{f['track_e'][i]}]")
        for i in range(f["check_n"]):
            print(f"    check[{i}] name={f['check_names'][i]!r} default={f['check_defaults'][i]}")

    print("\n" + "=" * 66)
    print(f"{len(found)} registration(s) found for {args.target_name!r} "
          f"(ぼかし/発光 each have 2 - object effect + frame filter; "
          f"境界ぼかし has only {len(found)}).")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
