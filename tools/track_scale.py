"""Decode the exedit-private extension block at +0x74 of every registration -
the table that decides what number AviUtl actually shows for a trackbar.

Reading func_proc gets you nowhere here: every filter in this repo consumes
fp->track[] raw and none of them format it for display. The mapping is not in
code at all, it is a table. The registration structs in the 0x100a3e28 array
are longer than AviUtl's FILTER (data/filter.h), and carry one extra pointer
past the documented fields. モザイク's, for example:

    0x100a88cc  (struct + 0x74) -> 0x100a8844
    0x100a8844: 0x100a8840  -> int[track_n] = {1}      display scale
                0x00000000                             (slot 1, see below)
                0x100a8838  -> int[track_n] = {1}      slider drag minimum
                0x100a883c  -> int[track_n] = {200}    slider drag maximum

Slot 0 (the display scale) is not a guess: this script reads it out of filters
whose on-screen numbers are common knowledge and checks that `raw / scale`
reproduces them - 透明度 must read 0.0-100.0, 拡大率 must default to 100.00,
発光's 強さ must default to 100.0. If those line up, then モザイク's scale of 1
means サイズ is displayed raw, i.e. the number in the UI is the block edge
length in pixels.

Slot 1 is a per-track *grouping* marker, identified here by the company it
keeps: it is non-zero only on trackbars that belong to a multi-component
control, and the pattern is always +1 on every member but the last and
-(n-1) on the last one. (X, Y) pairs carry (1, -1); (X, Y, Z) triples and
拡張色設定's (R, G, B) carry (1, 1, -2). It is zero on every standalone
trackbar. --groups prints the evidence.

Run via main.py:
    uv run main.py tools.track_scale
    uv run main.py tools.track_scale --name ぼかし --name 閃光
    uv run main.py tools.track_scale --groups
"""

import argparse

from tools.filter_table import walk
from tools.pe_image import PEImage

# (filter, track, expected displayed default) for filters whose AviUtl UI is
# well known. These are the control group that identifies slot [0] as a scale.
KNOWN = [
    ("透明度", "透明度", "0.0", "0.0-100.0 slider"),
    ("拡大率", "拡大率", "100.00", "percent with 2 decimals"),
    ("発光", "強さ", "100.0", "percent with 1 decimal"),
    ("発光", "拡散速度", "0", "plain integer"),
    ("モザイク", "サイズ", "12", "displayed raw -> pixels"),
    ("閃光", "X", "0", "displayed raw -> pixels"),
]

# Filters analysed in this repo, dumped in full by default.
ANALYSED = ("モザイク", "発光", "ぼかし", "境界ぼかし", "閃光", "拡散光")


def _table(r) -> None:
    print(f"\n{r.name}  struct=0x{r.struct_va:08x}  ext=0x{r.ext_va:08x}  ({r.role})")
    print(f"  {'track':<10} {'raw def':>8} {'scale':>6} {'shown':>10} "
          f"{'raw range':>14} {'shown range':>16} {'slider drag':>16} {'group':>6}")
    for i in range(r.track_n):
        sc = r.track_scale(i)
        dmin = r.drag_min[i] if r.drag_min else None
        dmax = r.drag_max[i] if r.drag_max else None
        drag = "-" if dmin is None else f"{r.shown(i, dmin)}..{r.shown(i, dmax)}"
        grp = r.slot1[i] if r.slot1 else 0
        print(f"  {str(r.track_names[i]):<10} {r.track_defaults[i]:>8} {sc:>6} "
              f"{r.shown(i, r.track_defaults[i]):>10} "
              f"{f'{r.track_s[i]}..{r.track_e[i]}':>14} "
              f"{f'{r.shown(i, r.track_s[i])}..{r.shown(i, r.track_e[i])}':>16} "
              f"{drag:>16} {grp:>6}")


def _control_group(regs) -> bool:
    print("1) control group - does slot [0] reproduce the numbers AviUtl shows?")
    ok_all = True
    for fname, tname, expect, note in KNOWN:
        hits = [r for r in regs if r.name == fname and tname in r.track_names]
        if not hits:
            print(f"   !! {fname}/{tname}: NOT FOUND")
            ok_all = False
            continue
        r = hits[0]
        i = r.track_names.index(tname)
        got = r.shown(i, r.track_defaults[i])
        ok = got == expect
        ok_all &= ok
        print(f"   {'OK ' if ok else '!! '}{fname:<8} {tname:<10} raw={r.track_defaults[i]:<6} "
              f"scale={r.track_scale(i):<4} -> {got:<8} expected {expect:<8} ({note})")
    print("   -> " + ("every known default reproduced; slot [0] is the display scale"
                      if ok_all else "MISMATCH - the slot identification is wrong"))
    return ok_all


def _groups(regs) -> bool:
    """Slot 1: show that every non-zero run is a coordinate/colour group of the
    form (+1, ..., +1, -(n-1)), and that it never appears on a lone trackbar."""
    print("slot [1] - per-track grouping marker")
    print(f"  {'filter':<22} {'tracks carrying a marker':<44} shape")
    ok_all = True
    seen = set()
    for r in regs:
        if not r.slot1 or not any(r.slot1) or r.name in seen:
            continue
        seen.add(r.name)
        runs, cur = [], []
        for i, v in enumerate(r.slot1):
            cur.append((str(r.track_names[i]), v))
            if v <= 0:
                if v < 0:
                    runs.append(cur)
                cur = []
        marked = ", ".join(f"{str(r.track_names[i])}={v:+d}"
                           for i, v in enumerate(r.slot1) if v)
        shapes = []
        for run in runs:
            n = len(run)
            good = all(v == 1 for _, v in run[:-1]) and run[-1][1] == -(n - 1)
            ok_all &= good
            shapes.append(f"{n}-tuple{'' if good else ' !!UNEXPECTED'}")
        print(f"  {r.name:<22} {marked[:44]:<44} {', '.join(shapes)}")
    print("   -> " + ("every non-zero run is (+1,..,+1,-(n-1)): a multi-component control"
                      if ok_all else "!! a run did not match the expected shape"))
    return ok_all


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="tools.track_scale")
    parser.add_argument("--name", action="append", help="filter name to dump; repeatable")
    parser.add_argument("--groups", action="store_true", help="only the slot [1] grouping evidence")
    args = parser.parse_args(argv or [])

    regs = walk(PEImage(dll_path))

    if args.name:
        for n in args.name:
            hits = [r for r in regs if r.name == n]
            if not hits:
                print(f"no filter named {n!r}")
            for r in hits:
                _table(r)
        return

    if args.groups:
        _groups(regs)
        return

    _control_group(regs)

    print("\n2) the filters analysed in this repo, decoded")
    for n in ANALYSED:
        for r in regs:
            if r.name == n:
                _table(r)
                break

    print("\n3) ", end="")
    _groups(regs)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
