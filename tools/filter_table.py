"""exedit's own effect-registration table, decoded.

exedit.auf registers itself with AviUtl as a *single* filter and then
dispatches ~100 effects of its own from a NULL-terminated pointer array at
`0x100a3e28` (the Ghidra label `PTR_DAT_100a3e28`). Each entry points at a
struct that starts out as AviUtl's `FILTER` (data/filter.h) - flag, name,
trackbar/checkbox definitions, func_proc/func_init/func_WndProc - but is
*longer* than the documented struct: `+0x74` holds a pointer to an
exedit-private block of four per-track arrays that control how AviUtl renders
the numbers (see `ext`/`scale` below and tools/track_scale.py).

Every inspect/<filter>/ directory needs the same first step - "find my
filter's registration and print what the UI actually exposes" - so it lives
here instead of being copy-pasted per filter.

As a library:

    from tools.filter_table import walk, find
    regs = find(PEImage(dll_path), "閃光")     # every registration of that name

As a script:

    uv run main.py tools.filter_table --name 閃光
    uv run main.py tools.filter_table --name ぼかし --name 発光
    uv run main.py tools.filter_table --list          # one line per effect
"""

import argparse
import struct
from dataclasses import dataclass, field

from tools.pe_image import PEImage

# NULL-terminated array of FILTER* - the head of exedit's effect table.
HEAD_VA = 0x100A3E28

# FILTER field offsets, 32-bit (data/filter.h)
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
OFF_FUNC_EXIT = 0x38
OFF_FUNC_UPDATE = 0x3C
OFF_FUNC_WNDPROC = 0x40
OFF_TRACK = 0x44
OFF_CHECK = 0x48
OFF_EX_DATA_PTR = 0x4C
OFF_EX_DATA_SIZE = 0x50
OFF_INFORMATION = 0x54
# +0x6C is FILTER::ex_data_def - the initial ex_data a newly added effect gets.
# Unlike ex_data_ptr (filled in at runtime) this one is in the file, so the
# defaults of colour pickers / dropdowns are readable statically.
OFF_EX_DATA_DEF = 0x6C

# exedit-private extension block reached through struct+0x74; four pointers,
# each to an int[track_n]. Slot 1's purpose is not pinned down (it is NULL or
# all-zero on every filter checked so far).
OFF_EXT = 0x74

FLAG_INPUT = 0x01
FLAG_OUTPUT = 0x02
FLAG_EX_DATA = 0x400
FLAG_VIDEO_FILTER = 0x10000000
# exedit reuses AviUtl's FILTER.flag bit 0x20 (FILTER_FLAG_ALWAYS_ACTIVE) to
# mean "this registration is the object-effect variant"; effects registered
# twice differ in this bit alone (see inspect/glow, inspect/blur, inspect/mozaic).
FLAG_OBJECT_EFFECT = 0x20


@dataclass
class Registration:
    """One entry of the 0x100a3e28 table."""

    index: int
    struct_va: int
    flag: int
    name: str
    track_n: int
    check_n: int
    track_names: list = field(default_factory=list)
    track_defaults: list = field(default_factory=list)
    track_s: list = field(default_factory=list)
    track_e: list = field(default_factory=list)
    check_names: list = field(default_factory=list)
    check_defaults: list = field(default_factory=list)
    func_proc: int = 0
    func_init: int = 0
    func_exit: int = 0
    func_update: int = 0
    func_wndproc: int = 0
    ex_data_ptr: int = 0
    ex_data_size: int = 0
    ex_data_def: int = 0
    ex_data_def_bytes: bytes = b""
    information: str = ""
    ext_va: int = 0
    scale: list | None = None
    slot1: list | None = None
    drag_min: list | None = None
    drag_max: list | None = None

    @property
    def role(self) -> str:
        return "object effect" if self.flag & FLAG_OBJECT_EFFECT else "frame (video) filter"

    def track_scale(self, i: int) -> int:
        """Divisor AviUtl applies before showing track[i]; 1 means "shown raw"."""
        if not self.scale or i >= len(self.scale) or not self.scale[i]:
            return 1
        return self.scale[i]

    def shown(self, i: int, raw: int | None) -> str:
        """Format a raw track value the way the AviUtl UI shows it."""
        if raw is None:
            return "-"
        sc = self.track_scale(i)
        if sc == 1:
            return str(raw)
        return f"{raw / sc:.{len(str(sc)) - 1}f}"

    def is_button(self, i: int) -> bool:
        """A checkbox with a negative default is really a button (filter.h)."""
        d = self.check_defaults[i] if i < len(self.check_defaults) else 0
        return (d or 0) < 0


def walk(img: PEImage, head_va: int = HEAD_VA) -> list[Registration]:
    """Read the whole effect table in order."""
    regs = []
    ptr, idx = head_va, 0
    while True:
        entry = img.u32(ptr)
        if entry is None or entry == 0 or not img.valid(entry):
            break
        regs.append(_read_entry(img, idx, entry))
        ptr += 4
        idx += 1
    return regs


def find(img: PEImage, name: str, head_va: int = HEAD_VA) -> list[Registration]:
    """Every registration whose name matches exactly. Effects that exist both
    as an object effect and as a frame filter return two entries."""
    return [r for r in walk(img, head_va) if r.name == name]


def read_entry(img: PEImage, entry: int, idx: int = -1) -> Registration:
    """Decode one registration struct at a known address.

    Public because a struct does not have to be *in* the table to be worth
    decoding - inspect/glint finds an unregistered one lying in .data.
    idx defaults to -1 to mark "not from the table".
    """
    return _read_entry(img, idx, entry)


def _read_entry(img: PEImage, idx: int, entry: int) -> Registration:
    def arr(off, n, as_str=False):
        p = img.u32(entry + off)
        if not img.valid(p) or n <= 0:
            return []
        return img.str_array(p, n) if as_str else img.i32_array(p, n)

    track_n = img.u32(entry + OFF_TRACK_N) or 0
    check_n = img.u32(entry + OFF_CHECK_N) or 0

    ext = img.u32(entry + OFF_EXT) or 0
    slots = img.u32_array(ext, 4) if img.valid(ext) and ext else [0] * 4

    def ext_slot(p):
        return img.i32_array(p, track_n) if p and img.valid(p) and track_n else None

    info_ptr = img.u32(entry + OFF_INFORMATION)
    ex_size = img.u32(entry + OFF_EX_DATA_SIZE) or 0
    ex_def = img.u32(entry + OFF_EX_DATA_DEF) or 0
    ex_def_bytes = img.code(ex_def, ex_size) if ex_def and img.valid(ex_def, ex_size) else b""

    return Registration(
        index=idx,
        struct_va=entry,
        flag=img.u32(entry + OFF_FLAG) or 0,
        name=img.cstr(img.u32(entry + OFF_NAME)),
        track_n=track_n,
        check_n=check_n,
        track_names=arr(OFF_TRACK_NAME, track_n, as_str=True),
        track_defaults=arr(OFF_TRACK_DEFAULT, track_n),
        track_s=arr(OFF_TRACK_S, track_n),
        track_e=arr(OFF_TRACK_E, track_n),
        check_names=arr(OFF_CHECK_NAME, check_n, as_str=True),
        check_defaults=arr(OFF_CHECK_DEFAULT, check_n),
        func_proc=img.u32(entry + OFF_FUNC_PROC) or 0,
        func_init=img.u32(entry + OFF_FUNC_INIT) or 0,
        func_exit=img.u32(entry + OFF_FUNC_EXIT) or 0,
        func_update=img.u32(entry + OFF_FUNC_UPDATE) or 0,
        func_wndproc=img.u32(entry + OFF_FUNC_WNDPROC) or 0,
        ex_data_ptr=img.u32(entry + OFF_EX_DATA_PTR) or 0,
        ex_data_size=ex_size,
        ex_data_def=ex_def,
        ex_data_def_bytes=ex_def_bytes,
        information=img.cstr(info_ptr) if img.valid(info_ptr) and info_ptr else "",
        ext_va=ext,
        scale=ext_slot(slots[0]),
        slot1=ext_slot(slots[1]),
        drag_min=ext_slot(slots[2]),
        drag_max=ext_slot(slots[3]),
    )


def dump(r: Registration) -> None:
    """Print one registration in full: everything the AviUtl UI exposes."""
    print("=" * 74)
    print(f"[{r.index}] {r.name}  struct=0x{r.struct_va:08x} flag=0x{r.flag:08x}  -> {r.role}")
    print(f"  func_proc=0x{r.func_proc:08x}  func_init=0x{r.func_init:08x}  "
          f"func_exit=0x{r.func_exit:08x}")
    print(f"  func_update=0x{r.func_update:08x}  func_WndProc=0x{r.func_wndproc:08x}")
    print(f"  ex_data_size={r.ex_data_size}  ex_data_def=0x{r.ex_data_def:08x}  ext=0x{r.ext_va:08x}")
    if r.ex_data_def_bytes:
        words = [f"0x{v:08x}" for v in
                 struct.unpack_from(f"<{len(r.ex_data_def_bytes) // 4}I", r.ex_data_def_bytes)]
        print(f"  ex_data_def bytes = {r.ex_data_def_bytes.hex(' ')}  as dwords = {', '.join(words)}")
    if r.information:
        print(f"  information={r.information!r}")
    print(f"  track_n={r.track_n} check_n={r.check_n}")
    if r.track_n:
        print(f"    {'track':<12}{'raw def':>9}{'raw range':>14}{'scale':>7}"
              f"{'shown def':>11}{'shown range':>18}{'slider drag':>18}")
    for i in range(r.track_n):
        sc = r.track_scale(i)
        dmin = r.drag_min[i] if r.drag_min else None
        dmax = r.drag_max[i] if r.drag_max else None
        drag = "-" if dmin is None else f"{r.shown(i, dmin)}..{r.shown(i, dmax)}"
        print(f"    {str(r.track_names[i]):<12}{r.track_defaults[i]:>9}"
              f"{f'{r.track_s[i]}..{r.track_e[i]}':>14}{sc:>7}"
              f"{r.shown(i, r.track_defaults[i]):>11}"
              f"{f'{r.shown(i, r.track_s[i])}..{r.shown(i, r.track_e[i])}':>18}"
              f"{drag:>18}")
    for i in range(r.check_n):
        kind = "button" if r.is_button(i) else "checkbox"
        print(f"    check[{i}] {str(r.check_names[i])!r} default={r.check_defaults[i]} ({kind})")


def summarize(regs: list[Registration], name: str) -> None:
    """Say out loud whether the registrations of one effect share an
    implementation, and what differs between them - the question every
    inspect/ analysis opens with."""
    print("=" * 74)
    print(f"{len(regs)} registration(s) for {name!r}.")
    procs = sorted({r.func_proc for r in regs})
    print(f"  distinct func_proc: {', '.join('0x%08x' % p for p in procs)}"
          f"  -> {'shared' if len(procs) == 1 else 'separate'} implementation")
    if len(regs) == 2:
        a, b = regs
        for x, y in ((a, b), (b, a)):
            only = [c for c in x.check_names if c and c not in y.check_names]
            print(f"  checkbox only on flag=0x{x.flag:02x} ({x.role}): {only}")
        same = (a.track_names == b.track_names and a.track_defaults == b.track_defaults
                and a.track_s == b.track_s and a.track_e == b.track_e)
        print(f"  trackbar definitions identical: {same}")


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="tools.filter_table")
    parser.add_argument("--name", action="append", help="effect name to dump in full; repeatable")
    parser.add_argument("--list", action="store_true", help="one line per registered effect")
    args = parser.parse_args(argv or [])

    img = PEImage(dll_path)
    regs = walk(img)

    if args.list or not args.name:
        for r in regs:
            print(f"[{r.index:3}] struct=0x{r.struct_va:08x} flag=0x{r.flag:08x} "
                  f"func_proc=0x{r.func_proc:08x} func_init=0x{r.func_init:08x} name={r.name}")
        print(f"Done. {len(regs)} entries found.")
        if not args.name:
            return

    for name in args.name or []:
        hits = [r for r in regs if r.name == name]
        if not hits:
            print(f"no effect named {name!r}")
            continue
        for r in hits:
            dump(r)
        summarize(hits, name)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
