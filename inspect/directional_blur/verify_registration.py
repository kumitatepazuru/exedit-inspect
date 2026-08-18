"""`方向ブラー` の登録2個 ―― `放射ブラー` と対になる形、ただし細部が違う。

主張:

  1. **登録2個・`func_proc` は別々**(`0x1000c200` / `0x1000c9b0`)。
     [`放射ブラー`](../emission_blur/README.md) と同じ「2登録モデルの例外」だが、
     **トラックバー定義は完全に同一**で、`+0x74` 拡張ブロックまで共有する。
     `放射ブラー` は `範囲` の上限が 750 と 1000 で食い違い、`+0x74` も別々だった。

  2. **`fp+0x78`(描画パラメータ枠 → トラックバー添字)は枠5 = `Z軸回転`**。
     `放射ブラー` が枠0/枠1(= `X`/`Y`)を使うのと対照的で、
     **`角度` が「回転」として登録されている**。

  3. **`func_WndProc` は `放射ブラー` と共有の `0x1001b550`** で、4登録とも同じ。

  4. **エフェクト固有コードは `0x1000c200`-`0x1000ccff` の 2816 バイト・5関数。**
     グローバル7個(`0x100d75cc`-`0x100d75e4`)の参照はすべてその中に閉じている。

  5. **フレーム版は `0x10019160`(共有の描画ルーチン)を呼ばない。**
     `放射ブラー` のフレーム版は同じ `+0x78` を持ちながら呼ぶ ―― つまり
     「`+0x78` があるから呼ぶ」ではない、という反例になっている。
     直接呼び出しは `_ftol` 1本だけ。

Run via main.py:
    uv run main.py inspect/directional_blur/verify_registration.py
"""

import struct

from tools.disasm import function_body
from tools.filter_table import find, walk
from tools.pe_image import PEImage
from tools.xrefs import function_owners, nearest_owner, scan

NAME = "方向ブラー"
FUNCS = (0x1000C200, 0x1000C4A0, 0x1000C720, 0x1000C9B0, 0x1000CB10)
SPAN_LO, SPAN_HI = 0x1000C200, 0x1000CD00

GLOBALS = {
    0x100D75CC: "vx = trunc(sin(θ)·(-65536))",
    0x100D75D0: "vy = trunc(cos(θ)·65536)",
    0x100D75D4: "x1 = w + 範囲",
    0x100D75D8: "y1 = h + 範囲",
    0x100D75DC: "x0 = -範囲",
    0x100D75E0: "N(片側のサンプル数)",
    0x100D75E4: "y0 = -範囲",
}

FTOL = 0x10091AD8
DRAW = 0x10019160
SHARED_WNDPROC = 0x1001B550
DRAW_SLOTS = ["X", "Y", "Z", "X軸回転", "Y軸回転", "Z軸回転",
              "中心X", "中心Y", "中心Z", "拡大率", "縦横比", "透明度"]


def relative_branch_targets(img: PEImage) -> dict:
    out = {}
    for s in img.pe.sections:
        if s.Name.rstrip(b"\x00") != b".text":
            continue
        base = img.image_base + s.VirtualAddress
        size = max(s.Misc_VirtualSize, s.SizeOfRawData)
        data = img.data[s.VirtualAddress:s.VirtualAddress + size]
        for i in range(len(data) - 5):
            if data[i] in (0xE8, 0xE9):
                rel = struct.unpack_from("<i", data, i + 1)[0]
                out.setdefault(base + i + 5 + rel, []).append(base + i)
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)
    owners = function_owners(img)
    regs = find(img, NAME)
    obj, frm = regs

    print("--- 1. 登録2個 ---")
    for r in regs:
        print(f"  [{r.index:>3}] struct=0x{r.struct_va:08x} flag=0x{r.flag:08x} "
              f"func_proc=0x{r.func_proc:08x} ext(+0x74)=0x{r.ext_va:08x} "
              f"-> {r.role}")
        print("        track: " + ", ".join(
            f"{nm}({r.track_defaults[i]}, {r.track_s[i]}..{r.track_e[i]}, "
            f"scale {r.track_scale(i)}, drag "
            f"{r.drag_min[i] if r.drag_min else '-'}.."
            f"{r.drag_max[i] if r.drag_max else '-'})"
            for i, nm in enumerate(r.track_names)))
        for i in range(r.check_n):
            print(f"        check[{i}] {r.check_names[i]!r} default={r.check_defaults[i]}")
    check("func_proc が別の関数", obj.func_proc != frm.func_proc,
          f"0x{obj.func_proc:08x} / 0x{frm.func_proc:08x}")
    check("オブジェクト側 flag=0x20 / フレーム側 flag=0x40000000",
          obj.flag == 0x20 and frm.flag == 0x40000000)
    check("トラックバー定義は完全に同一(放射ブラーとの違い)",
          (list(obj.track_names), list(obj.track_defaults),
           list(obj.track_s), list(obj.track_e))
          == (list(frm.track_names), list(frm.track_defaults),
              list(frm.track_s), list(frm.track_e)))
    check("+0x74 拡張ブロックまで共有(放射ブラーは別々だった)",
          obj.ext_va == frm.ext_va)
    emis = find(img, "放射ブラー")
    check("参考: 放射ブラーの +0x74 は2登録で別々",
          emis[0].ext_va != emis[1].ext_va,
          f"0x{emis[0].ext_va:08x} / 0x{emis[1].ext_va:08x}")
    check("サイズ固定 はオブジェクト側だけ",
          obj.check_n == 1 and obj.check_names[0] == "サイズ固定" and frm.check_n == 0)
    check("角度 の生値範囲は ±36000(斜めクリッピング / 色ずれ / グラデーションと同じ)",
          (obj.track_s[1], obj.track_e[1]) == (-36000, 36000))

    print("\n--- 2. fp+0x78 の描画パラメータ枠 ---")
    for r, label in ((obj, "方向ブラー"), (emis[0], "放射ブラー")):
        ext = img.u32(r.struct_va + 0x78)
        slots = img.i32_array(ext, 12)
        used = [(i, DRAW_SLOTS[i], v, r.track_names[v]) for i, v in enumerate(slots) if v >= 0]
        print(f"  {label:<10} +0x78=0x{ext:08x}  {slots}")
        for i, nm, v, tn in used:
            print(f"      枠[{i:>2}] {nm:<8} -> track[{v}] = {tn}")
    slots = img.i32_array(img.u32(obj.struct_va + 0x78), 12)
    check("方向ブラーは枠5(Z軸回転) = track[1](角度)だけ",
          slots[5] == 1 and all(v < 0 for i, v in enumerate(slots) if i != 5))
    check("2登録で同じブロックを共有",
          img.u32(obj.struct_va + 0x78) == img.u32(frm.struct_va + 0x78))
    check("+0x78 + 0x30 が track_name 配列の先頭",
          img.u32(obj.struct_va + 0x78) + 0x30 == img.u32(obj.struct_va + 0x14))

    print("\n--- 3. 共有 func_WndProc ---")
    wnd = [r for r in walk(img) if r.func_wndproc == SHARED_WNDPROC]
    print(f"  0x{SHARED_WNDPROC:08x} を持つ登録: "
          f"{[(r.name, hex(r.flag)) for r in wnd]}")
    check("放射ブラー×2 と 方向ブラー×2 の4登録だけ",
          sorted(r.name for r in wnd) == ["放射ブラー"] * 2 + ["方向ブラー"] * 2)

    print("\n--- 4. 2816バイト・5関数 ---")
    total = 0
    for addr in FUNCS:
        body = [i for i in function_body(img, addr, limit=0x400) if i.address < SPAN_HI]
        end = body[-1].address + body[-1].size
        total += end - addr
        print(f"  0x{addr:08x}-0x{end - 1:08x}  {end - addr:>4} バイト  "
              f"{len(body):>3} 命令")
    span = SPAN_HI - SPAN_LO
    print(f"  連続領域 0x{SPAN_LO:08x}-0x{SPAN_HI - 1:08x} = {span} バイト "
          f"(うち命令 {total}、残り {span - total} バイトは nop パディング)")
    check("5関数が隙間なく並んでいる", 0 <= span - total < 5 * 16,
          f"パディング {span - total} バイト")

    branches = relative_branch_targets(img)
    check("5本とも直接 call/jmp されない(関数ポインタ経由だけ)",
          not any(branches.get(a) for a in FUNCS),
          f"{ {hex(a): [hex(v) for v in branches.get(a, [])] for a in FUNCS if branches.get(a)} }")

    outside = []
    for va, what in GLOBALS.items():
        codes = [v for v in scan(img, va)
                 if img.pe.get_section_by_rva(v - img.image_base)
                 and img.pe.get_section_by_rva(v - img.image_base).Name.rstrip(b"\x00") == b".text"]
        outside += [v for v in codes if not (SPAN_LO <= v < SPAN_HI)]
        print(f"  0x{va:08x}  {what:<30} .text 参照 {len(codes)} 箇所 "
              f"({nearest_owner(owners, codes[0]).split(' +')[0]} ほか)")
    check("グローバル7個の参照はすべて 2816 バイトの中", not outside,
          f"外の参照 {[hex(v) for v in outside]}")

    print("\n--- 5. 外へ出る呼び出し ---")
    calls = set()
    for addr in FUNCS:
        for insn in function_body(img, addr, limit=0x400):
            if insn.address >= SPAN_HI:
                break
            if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
                calls.add(int(insn.op_str, 16))
    print(f"  直接呼び出し先: {[hex(t) for t in sorted(calls)]}")
    check("_ftol (0x10091ad8) だけ", sorted(calls) == [FTOL])
    drawers = sorted({nearest_owner(owners, v).split(".")[0]
                      for v in branches.get(DRAW, [])})
    print(f"  0x{DRAW:08x}(共有の描画ルーチン)を呼ぶのは {drawers}")
    check("方向ブラーはその中にいない ―― 放射ブラーのフレーム版との差",
          NAME not in drawers and "放射ブラー" in drawers)

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
