"""`放射ブラー` の登録2個 ―― **`func_proc` を共有しない**2登録モデル。

主張:

  1. **登録は2個で、`func_proc` が別々**(`0x1000b310` / `0x1000ba10`)。
     [`filter_registration.md` §2](../common/filter_registration.md) が
     並べている2登録エフェクトは全部「同じ `func_proc` を `fp->flag & 0x20`
     で分岐」なのに対し、`放射ブラー` と `方向ブラー` だけは**関数そのものが
     2本**ある。トラックバーの定義まで違う(`範囲` の上限が 750 と 1000)。

  2. **フレーム側の `flag` は `0x40000000`** ―― 他のフレームフィルタが
     `0x00` なのに対し bit30 が立っている12エントリのうちの1つ。

  3. **`func_WndProc` が NULL でなく、`標準描画` などと共有の `0x1001b550`**。
     これが `fp+0x78` を読む ―― SDK にも本プロジェクトの既存ドキュメントにも
     無い5つ目の拡張フィールドで、`+0x78` を持つ登録は exedit 全100個のうち
     10個しかない。中身は **`int[12]`(48バイト)の「描画パラメータ枠 →
     トラックバー添字」対応表**で、`+0x78 + 0x30` がちょうど `track_name`
     配列の先頭になる(10個すべてで成立)。`拡張描画` は12枠すべてを埋めて
     いるので、そのトラック名がそのまま枠の意味になる(§3 で全部デコードする)。

  4. **エフェクト固有コードは `0x1000b310`-`0x1000c1ff` の 3824 バイト・
     6関数**で、間は 16 バイト境界合わせの `nop` だけ。6本目
     (`0x1000c0f0`)は **`func_proc` からは呼ばれない第2の入口**で、
     `FILTER_PROC_INFO` をスタック上に組み立ててフレーム版ワーカー
     `0x1000bb90` を直接走らせる。呼ぶのは `シーンチェンジ` の遷移ハンドラ表
     (`.data` の NULL 終端配列)に載っている `0x10084ac0` である。

  5. **グローバル8個の参照はすべてその中に閉じている。** 外へ出る直接
     呼び出しは `_ftol` と描画ルーチン `0x10019160` の2本だけ。

Run via main.py:
    uv run main.py inspect/emission_blur/verify_registration.py
"""

import struct

from tools.disasm import function_body
from tools.filter_table import find, walk
from tools.pe_image import PEImage
from tools.xrefs import function_owners, nearest_owner, scan

NAME = "放射ブラー"
FUNCS = (0x1000B310, 0x1000B660, 0x1000BA10, 0x1000BB90, 0x1000BE30, 0x1000C0F0)
SIDE_ENTRY = 0x1000C0F0
SCENE_CHANGE_WRAPPER = 0x10084AC0
SPAN_LO, SPAN_HI = 0x1000B310, 0x1000C200

GLOBALS = {
    0x100D75A8: "cx = w/2 + X",
    0x100D75AC: "cy = h/2 + Y",
    0x100D75B0: "x1",
    0x100D75B4: "y1",
    0x100D75B8: "R'(サンプル数の基準)",
    0x100D75BC: "x0",
    0x100D75C0: "範囲 の生値",
    0x100D75C4: "y0",
}

FTOL = 0x10091AD8
DRAW = 0x10019160
SHARED_WNDPROC = 0x1001B550

# fp+0x78 の先頭12枠。標準描画(6本)と拡張描画(12本)の名前配列から読み取れる
# 並び ―― 拡張描画は12枠すべてが埋まっているので、そのまま枠の意味になる。
DRAW_SLOTS = ["X", "Y", "Z", "X軸回転", "Y軸回転", "Z軸回転",
              "中心X", "中心Y", "中心Z", "拡大率", "縦横比", "透明度"]


def relative_branch_targets(img: PEImage) -> dict:
    """.text 全域の `call rel32` / `jmp rel32` を {target: [起点...]} で返す。"""
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


def dump_ext78(img: PEImage, r) -> list:
    """fp+0x78 のブロック(int[12])をデコードして表示する。

    値はトラックバーの添字で、-1 は「この枠は使わない」。枠の並びは
    `拡張描画`(12枠すべて非 -1)のトラック名から読める。
    """
    ext = img.u32(r.struct_va + 0x78)
    slots = img.i32_array(ext, 12)
    print(f"  fp+0x78 = 0x{ext:08x}  int[12] = {slots}")
    for i, v in enumerate(slots):
        if v >= 0:
            nm = r.track_names[v] if v < len(r.track_names) else "?"
            print(f"    枠[{i:>2}] {DRAW_SLOTS[i]:<8} -> track[{v}] = {nm}")
    return slots


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)
    owners = function_owners(img)
    regs = find(img, NAME)
    all_regs = walk(img)

    print("--- 1. 登録2個、func_proc は別々 ---")
    check("登録は2個", len(regs) == 2, f"{len(regs)} 個")
    for r in regs:
        print(f"  [{r.index:>3}] struct=0x{r.struct_va:08x} flag=0x{r.flag:08x} "
              f"func_proc=0x{r.func_proc:08x} WndProc=0x{r.func_wndproc:08x} "
              f"-> {r.role}")
        print(f"        track: " + ", ".join(
            f"{nm}({r.track_defaults[i]}, {r.track_s[i]}..{r.track_e[i]}, "
            f"scale {r.track_scale(i)})" for i, nm in enumerate(r.track_names)))
        for i in range(r.check_n):
            print(f"        check[{i}] {r.check_names[i]!r} default={r.check_defaults[i]}")
    obj, frm = regs
    check("オブジェクト側 flag=0x20 / フレーム側 flag=0x40000000",
          obj.flag == 0x20 and frm.flag == 0x40000000)
    check("func_proc が別の関数(2登録モデルの例外)",
          obj.func_proc != frm.func_proc,
          f"0x{obj.func_proc:08x} / 0x{frm.func_proc:08x}")
    check("トラックバー定義も同一ではない ―― 範囲 の上限が 750 / 1000",
          obj.track_e[0] == 750 and frm.track_e[0] == 1000)
    check("サイズ固定 はオブジェクト側だけ",
          obj.check_n == 1 and obj.check_names[0] == "サイズ固定" and frm.check_n == 0)
    check("ex_data も func_init/exit/update も無い",
          all(not (x.ex_data_size or x.func_init or x.func_exit or x.func_update)
              for x in regs))

    shared = [r for r in all_regs
              if r.func_proc == obj.func_proc or r.func_proc == frm.func_proc]
    check("2つの func_proc を他のエフェクトが使い回してはいない",
          len(shared) == 2)

    print("\n  参考: 同じ「func_proc が2本」の形をしているエフェクト")
    by_name = {}
    for r in all_regs:
        by_name.setdefault(r.name, []).append(r)
    split = [n for n, rs in by_name.items()
             if len(rs) == 2 and rs[0].func_proc != rs[1].func_proc]
    print(f"    {split}")
    check("放射ブラー・方向ブラー・ラスター・画像ループ の4つだけ", set(split) ==
          {"放射ブラー", "方向ブラー", "ラスター", "画像ループ"}, f"{split}")

    print("\n--- 2. flag bit30 と 共有 func_WndProc ---")
    bit30 = [r for r in all_regs if r.flag & 0x40000000]
    print(f"  bit30 が立つ登録 {len(bit30)} 個: {[r.name for r in bit30]}")
    check("フレーム側はその中の1つ", frm in bit30)
    wnd = [r for r in all_regs if r.func_wndproc == SHARED_WNDPROC]
    print(f"  func_WndProc = 0x{SHARED_WNDPROC:08x} を共有する登録 {len(wnd)} 個: "
          f"{sorted({r.name for r in wnd})}")
    check("放射ブラーの2登録ともこの共有 WndProc を持つ",
          all(r.func_wndproc == SHARED_WNDPROC for r in regs))

    print("\n--- 3. fp+0x78 ―― 描画パラメータ枠の対応表(SDK にも既存ドキュメントにも無い) ---")
    have78 = [r for r in all_regs if img.u32(r.struct_va + 0x78)]
    print(f"  +0x78 が非 NULL な登録 {len(have78)} 個:")
    for r in have78:
        print(f"    [{r.index:>3}] {r.name:<14} flag=0x{r.flag:08x} "
              f"+0x78=0x{img.u32(r.struct_va + 0x78):08x} "
              f"WndProc=0x{r.func_wndproc:08x}")
    bit30_names = {r.name for r in all_regs if r.flag & 0x40000000}
    check("+0x78 を持つのは「bit30 の登録を1つ以上持つエフェクト」の登録だけ",
          all(r.name in bit30_names for r in have78),
          f"{sorted({r.name for r in have78} - bit30_names)}")
    print("    (放射ブラー/方向ブラーは bit30 の付かないオブジェクト側の登録も"
          "同じブロックを共有している)")
    check("+0x78 + 0x30 が track_name 配列の先頭になる(= int[12] の48バイト)",
          all(img.u32(r.struct_va + 0x78) + 0x30 == img.u32(r.struct_va + 0x14)
              for r in have78))
    check("放射ブラーの2登録は同じブロックを共有",
          img.u32(obj.struct_va + 0x78) == img.u32(frm.struct_va + 0x78))
    drawers = sorted({nearest_owner(owners, v).split(".")[0]
                      for v in relative_branch_targets(img).get(DRAW, [])})
    print(f"  比較: 0x{DRAW:08x}(描画ルーチン)を呼ぶのは {drawers}")

    print("\n  拡張描画(12枠すべて埋まっている = 枠の意味そのもの):")
    ext_reg = [r for r in all_regs if r.name == "拡張描画"][0]
    ext_slots = dump_ext78(img, ext_reg)
    check("枠 i がトラック名 DRAW_SLOTS[i] に対応する",
          [ext_reg.track_names[v] for v in ext_slots] == DRAW_SLOTS,
          f"{[ext_reg.track_names[v] for v in ext_slots]}")

    print("\n  放射ブラー:")
    slots = dump_ext78(img, obj)
    check("枠0(X)と枠1(Y)だけが埋まり、track[1]/track[2] を指す",
          slots[:2] == [1, 2] and all(v < 0 for v in slots[2:]))
    print("  → 中心 X/Y が「画面上でドラッグできる位置」として登録されている、"
          "と読める(0x1001b550 が +0x78 の枠0/枠1 を読む)。")

    print("\n--- 4. 3824バイト・6関数 ---")
    total = 0
    for addr in FUNCS:
        # 6本目のうしろは 方向ブラー の func_proc が nop パディング無しで
        # 続くので、function_body の "ret + nop" 終端が効かない。
        body = [i for i in function_body(img, addr, limit=0x400)
                if i.address < SPAN_HI]
        end = body[-1].address + body[-1].size
        total += end - addr
        print(f"  0x{addr:08x}-0x{end - 1:08x}  {end - addr:>4} バイト  "
              f"{len(body):>3} 命令")
    span = SPAN_HI - SPAN_LO
    print(f"  連続領域 0x{SPAN_LO:08x}-0x{SPAN_HI - 1:08x} = {span} バイト "
          f"(うち命令 {total}、残り {span - total} バイトは nop パディング)")
    check("6関数が隙間なく並んでいる", 0 <= span - total < 6 * 16,
          f"パディング {span - total} バイト")

    print("\n--- 5. 参照と外部呼び出し ---")
    branches = relative_branch_targets(img)
    for addr in FUNCS:
        rel = branches.get(addr, [])
        dwords = scan(img, addr)
        inside = [v for v in dwords if SPAN_LO <= v < SPAN_HI]
        outside = [v for v in dwords if not (SPAN_LO <= v < SPAN_HI)]
        print(f"  0x{addr:08x}: rel32 分岐 {len(rel)} "
              f"{[hex(v) for v in rel]} / dword 即値 内 {len(inside)} 外 "
              f"{[hex(v) for v in outside]}")
    check("5本は関数ポインタ経由でしか呼ばれない(直接 call/jmp が0件)",
          not any(branches.get(a) for a in FUNCS if a != SIDE_ENTRY))
    check(f"6本目 0x{SIDE_ENTRY:08x} だけが直接 call される",
          len(branches.get(SIDE_ENTRY, [])) == 2
          and all(nearest_owner(owners, v) for v in branches[SIDE_ENTRY]))
    print(f"    呼び出し元: {[hex(v) for v in branches.get(SIDE_ENTRY, [])]} "
          f"= 0x{SCENE_CHANGE_WRAPPER:08x} の2分岐")
    tbl = scan(img, SCENE_CHANGE_WRAPPER)
    print(f"    その 0x{SCENE_CHANGE_WRAPPER:08x} への参照: "
          f"{[hex(v) for v in tbl]}(.data の関数ポインタ表1個だけ)")
    check("シーンチェンジ側は関数ポインタ表からしか届かない", len(tbl) == 1)

    outside = []
    for va, what in GLOBALS.items():
        codes = [v for v in scan(img, va)
                 if img.pe.get_section_by_rva(v - img.image_base)
                 and img.pe.get_section_by_rva(v - img.image_base).Name.rstrip(b"\x00") == b".text"]
        out = [v for v in codes if not (SPAN_LO <= v < SPAN_HI)]
        outside += out
        print(f"  0x{va:08x}  {what:<24} .text 参照 {len(codes)} 箇所 "
              f"({nearest_owner(owners, codes[0]).split(' +')[0]} ほか)")
    check("グローバル8個の参照はすべて 3824 バイトの中", not outside,
          f"外の参照 {[hex(v) for v in outside]}")

    calls = set()
    for addr in FUNCS:
        for insn in function_body(img, addr, limit=0x400):
            if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
                calls.add(int(insn.op_str, 16))
    print(f"  直接呼び出し先: {[hex(t) for t in sorted(calls)]}")
    check("_ftol と描画ルーチン 0x10019160 の2本だけ",
          sorted(calls) == sorted([FTOL, DRAW]))
    users = sorted({nearest_owner(owners, v).split(".")[0]
                    for v in branches.get(DRAW, [])})
    print(f"  0x{DRAW:08x} を呼ぶエフェクト: {users}")
    check("描画ルーチンは 標準描画 系と共有(放射ブラーはその1つ)",
          NAME in users and len(users) >= 5)

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
