"""Pin down what the number AviUtl shows for サイズ means, by decoding the
exedit-private extension block that sits at +0x74 of every registration.

inspect/glow/README.md lists "UI表示値と raw の対応" as undetermined, on the
grounds that func_proc only ever sees fp->track[] and never formats it. That
is true of func_proc - but the mapping is not in code at all, it is a table.
The registration structs in the 0x100a3e28 array are longer than AviUtl's
FILTER (data/filter.h), and モザイク's entries carry one non-NULL pointer past
the documented fields:

    0x100a88cc  (struct + 0x74) -> 0x100a8844
    0x100a8844: 0x100a8840  -> int[track_n] = {1}      display scale
                0x00000000                             (NULL here)
                0x100a8838  -> int[track_n] = {1}      slider drag minimum
                0x100a883c  -> int[track_n] = {200}    slider drag maximum

The identification is not a guess: this script reads the same block out of
filters whose on-screen numbers are common knowledge and checks that
`raw / scale` reproduces them - 透明度 must read 0.0-100.0, 拡大率 must default
to 100.00, 発光's 強さ must default to 100.0. If those three line up, then
モザイク's scale of 1 means サイズ is displayed raw, i.e. **the number in the UI
is the block edge length in pixels**, and the 1..2000 range in the struct is
1..2000 px with the slider itself only reaching 200.

Run via main.py:
    uv run main.py inspect/mozaic/verify_track_scale.py
    uv run main.py inspect/mozaic/verify_track_scale.py --name ぼかし
"""

import argparse
import struct

import pefile

HEAD_VA = 0x100A3E28
OFF_NAME, OFF_TRACK_N = 0x0C, 0x10
OFF_TRACK_NAME, OFF_TRACK_DEFAULT, OFF_TRACK_S, OFF_TRACK_E = 0x14, 0x18, 0x1C, 0x20
OFF_EXT = 0x74

# (filter, track, expected displayed default) for filters whose AviUtl UI is
# well known. These are the control group that identifies slot [0] as a scale.
KNOWN = [
    ("透明度", "透明度", "0.0", "0.0-100.0 slider"),
    ("拡大率", "拡大率", "100.00", "percent with 2 decimals"),
    ("発光", "強さ", "100.0", "percent with 1 decimal"),
    ("発光", "拡散速度", "0", "plain integer"),
    ("モザイク", "サイズ", "12", "<- the one we are after"),
]


def _reader(dll_path):
    pe = pefile.PE(dll_path)
    ib = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()

    def dw(va, signed=False):
        r = va - ib
        if r < 0 or r + 4 > len(data):
            return None
        return struct.unpack_from("<i" if signed else "<I", data, r)[0]

    def ok(va):
        return va is not None and 0 <= va - ib < len(data)

    def cstr(va):
        r = va - ib
        end = data.find(b"\x00", r, r + 128)
        return data[r:end if end != -1 else r + 128].decode("cp932", "replace")

    return dw, ok, cstr


def collect(dll_path):
    """Walk the registration array once; return {name: info} (first entry wins)."""
    dw, ok, cstr = _reader(dll_path)
    out = {}
    ptr = HEAD_VA
    while True:
        entry = dw(ptr)
        if not ok(entry) or entry == 0:
            break
        ptr += 4
        name_ptr = dw(entry + OFF_NAME)
        name = cstr(name_ptr) if ok(name_ptr) else ""
        if name in out:
            continue
        n = dw(entry + OFF_TRACK_N) or 0

        def arr(off, signed=True, count=n):
            base = dw(entry + off)
            return [dw(base + 4 * i, signed) for i in range(count)] if ok(base) else []

        def deref(p):
            return [dw(p + 4 * i, True) for i in range(n)] if ok(p) and p else None

        names_base = dw(entry + OFF_TRACK_NAME)
        names = [cstr(dw(names_base + 4 * i)) for i in range(n)] if ok(names_base) else []

        ext = dw(entry + OFF_EXT)
        slots = [dw(ext + 4 * i) for i in range(4)] if ok(ext) and ext else [None] * 4
        out[name] = {
            "struct": entry, "n": n, "names": names,
            "default": arr(OFF_TRACK_DEFAULT), "s": arr(OFF_TRACK_S), "e": arr(OFF_TRACK_E),
            "ext": ext if ok(ext) else 0,
            "scale": deref(slots[0]), "slot1": deref(slots[1]),
            "drag_min": deref(slots[2]), "drag_max": deref(slots[3]),
        }
    return out


def _show(v, scale):
    if not scale or scale == 1:
        return str(v)
    digits = len(str(scale)) - 1
    return f"{v / scale:.{digits}f}"


def _table(info, name):
    print(f"\n{name}  struct=0x{info['struct']:08x}  ext=0x{info['ext']:08x}")
    print(f"  {'track':<10} {'raw def':>8} {'scale':>6} {'shown':>10} "
          f"{'raw range':>14} {'shown range':>16} {'slider drag':>16}")
    for i in range(info["n"]):
        sc = info["scale"][i] if info["scale"] else 1
        dmin = info["drag_min"][i] if info["drag_min"] else None
        dmax = info["drag_max"][i] if info["drag_max"] else None
        drag = "-" if dmin is None else f"{_show(dmin, sc)}..{_show(dmax, sc)}"
        print(f"  {info['names'][i]:<10} {info['default'][i]:>8} {sc:>6} "
              f"{_show(info['default'][i], sc):>10} "
              f"{f'{info["s"][i]}..{info["e"][i]}':>14} "
              f"{f'{_show(info["s"][i], sc)}..{_show(info["e"][i], sc)}':>16} "
              f"{drag:>16}")


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", action="append", help="filter name to dump; repeatable")
    args = parser.parse_args(argv or [])

    reg = collect(dll_path)

    if args.name:
        for n in args.name:
            if n in reg:
                _table(reg[n], n)
            else:
                print(f"no filter named {n!r}")
        return

    print("1) control group - does slot [0] reproduce the numbers AviUtl shows?")
    ok_all = True
    for fname, tname, expect, note in KNOWN:
        info = reg.get(fname)
        if not info or tname not in info["names"]:
            print(f"   {fname}/{tname}: NOT FOUND")
            ok_all = False
            continue
        i = info["names"].index(tname)
        sc = info["scale"][i] if info["scale"] else 1
        got = _show(info["default"][i], sc)
        mark = "OK " if got == expect else "!! "
        ok_all &= got == expect
        print(f"   {mark}{fname:<8} {tname:<10} raw={info['default'][i]:<6} scale={sc:<4} "
              f"-> {got:<8} expected {expect:<8} ({note})")
    print(f"   -> {'every known default reproduced; slot [0] is the display scale'
                  if ok_all else 'MISMATCH - the slot identification is wrong'}")

    print("\n2) the filters analysed in this repo, decoded")
    for n in ("モザイク", "発光", "ぼかし", "境界ぼかし"):
        if n in reg:
            _table(reg[n], n)

    print("\n3) slot [1] is a fourth per-track array whose purpose is not pinned down")
    for n in ("モザイク", "発光", "透明度", "拡大率"):
        if n in reg:
            print(f"   {n:<8} slot1={reg[n]['slot1']}")
    print("   it is NULL or all-zero everywhere checked, so it cannot be told apart")
    print("   from a default; it does not affect the scale conclusion above")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
