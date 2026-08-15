"""`斜めクリッピング` が何でできているか ―― そして、何でできて **いない** か。

5つの主張:

  1. **登録は1個だけ**(`0x100a7490`, `flag = 0x20` = オブジェクト効果)。
     フレームフィルタ版は存在しない。`func_proc` 以外のコールバックは全部
     NULL、`check_n = 0`、`ex_data_size = 0` ―― [`凸エッジ`](../convex_edge/README.md)
     と同じ「UI 関連のコードが1バイトも無い」形である。exedit の100登録の
     うちこの形は22個あり、その中で**トラックバーが5本あるのは
     斜めクリッピングだけ**(次点は4本)。

  2. **エフェクト固有コードは `0x1005cab0`-`0x1005cea7` の 1016 バイト・
     3関数**で、間は `ret` + `nop` パディングだけで詰まっている。解析済みでは
     `フェード`(342)/`凸エッジ`(846)/`ルミナンスキー`(959)に次いで4番目に小さい。

  3. **ワーカー2本は `func_proc` の `push` 以外からは到達できない。** 3関数の
     アドレスを .text 全域で `call`/`jmp` の rel32 として探しても、
     dword 即値として探してもヒットしない ―― `func_proc` 自身の
     `push 0x1005cb70` / `push 0x1005ccb0` と、登録構造体の中の
     `func_proc` ポインタを除いて。

  4. **グローバルは6個で、参照はすべてこの1016バイトの中に閉じている。**
     `exec_multi_thread_func` に渡せる引数が2つしかない
     ([`filter_registration.md` §6](../common/filter_registration.md))ため、
     パラメータはグローバル経由になる。

  5. **外部を触るのは2箇所だけ** ―― CRT の `_ftol`(`0x10091ad8`)と、
     `ノイズ` の `func_init` が実行時に埋めるイージング表(`0x101dcf78`、
     [`lut_tables.md`](../common/lut_tables.md))。共有ワーカーもキャンバス
     拡張(`table[0x44]` などの矩形転送)も呼ばない。ついでに、その
     `func_init` を呼んでいるのが exedit の効果テーブル初期化ループ
     (`0x100315e6`)であることも命令列で押さえる ―― `lut_tables.md` が
     「呼び出し元は未特定」としていた点。

おまけとして、`+0x74` のグループ化マーカーが**全ゼロ**であること ――
`中心X`/`中心Y` という対になった2本を持ちながら、`波紋` のように
2成分コントロールとしてまとめられてはいないこと ―― も確認する。

Run via main.py:
    uv run main.py inspect/diagonal_clipping/verify_registration.py
"""

import struct

from tools.disasm import disasm_range, function_body
from tools.filter_table import find, walk
from tools.pe_image import PEImage
from tools.xrefs import function_owners, nearest_owner, scan

NAME = "斜めクリッピング"
FUNC_PROC = 0x1005CAB0
WORKER_HALFPLANE = 0x1005CB70
WORKER_BAND = 0x1005CCB0
FUNCS = (FUNC_PROC, WORKER_HALFPLANE, WORKER_BAND)

GLOBALS = {
    0x101B20C4: "幅 << 15 (Q16 の半値幅)",
    0x101B20C8: "w/2 + 中心X",
    0x101B20CC: "h/2 + 中心Y",
    0x101B20D0: "vx = trunc(sin(θ)·65536)",
    0x101B20D4: "vy = trunc(cos(θ)·(-65536))",
    0x101B20D8: "ぼかし + 1",
}

FTOL = 0x10091AD8
EASE_TABLE = 0x101DCF78

# 他エフェクトの README が確定させているサイズ(比較用)
KNOWN_SIZES = {"フェード": 342, "凸エッジ": 846, "ルミナンスキー": 959}


def relative_branch_targets(img: PEImage) -> dict:
    """.text 全域の `call rel32` / `jmp rel32` を {target: [起点...]} で返す。

    tools.xrefs は dword 即値しか見ないので、rel32 で符号化される直接呼び出しは
    原理的に拾えない。「このワーカーは関数ポインタ経由でしか呼ばれない」を
    言うにはこちらが要る。
    """
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

    print("--- 1. 登録エントリ ---")
    check("登録は1個だけ(フレームフィルタ版が無い)", len(regs) == 1, f"{len(regs)} 個")
    r = regs[0]
    print(f"  struct=0x{r.struct_va:08x}  flag=0x{r.flag:08x} -> {r.role}")
    print(f"  func_proc=0x{r.func_proc:08x}  他のコールバック: "
          f"init=0x{r.func_init:08x} exit=0x{r.func_exit:08x} "
          f"update=0x{r.func_update:08x} WndProc=0x{r.func_wndproc:08x}")
    check("flag bit5 が立っている = オブジェクト効果", bool(r.flag & 0x20))
    check("func_proc は 0x1005cab0", r.func_proc == FUNC_PROC)
    check("func_init / func_exit / func_update / func_WndProc は全部 NULL",
          not (r.func_init or r.func_exit or r.func_update or r.func_wndproc))
    check("チェックボックスもコンボもボタンも0個", r.check_n == 0)
    check("ex_data も ex_data_def も無い",
          r.ex_data_size == 0 and r.ex_data_def == 0)
    check("トラックバーは5本", r.track_n == 5)
    print(f"  {'track':<8}{'raw def':>9}{'raw range':>16}{'scale':>7}{'shown def':>12}"
          f"{'drag':>18}{'group':>7}")
    for i, nm in enumerate(r.track_names):
        drag = "-"
        if r.drag_min and r.drag_max:
            drag = f"{r.drag_min[i]}..{r.drag_max[i]}"
        grp = r.slot1[i] if r.slot1 else 0
        print(f"  {nm:<8}{r.track_defaults[i]:>9}"
              f"{f'{r.track_s[i]}..{r.track_e[i]}':>16}{r.track_scale(i):>7}"
              f"{r.shown(i, r.track_defaults[i]):>12}{drag:>18}{grp:>7}")
    check("角度だけが表示スケール10(= 1/10度単位の生値)、他は生値そのまま",
          [r.track_scale(i) for i in range(5)] == [1, 1, 10, 1, 1])
    check("既定値は 中心X=0 中心Y=0 角度=0 ぼかし=1 幅=0",
          list(r.track_defaults) == [0, 0, 0, 1, 0])
    print("  ぼかし の既定が 0 ではなく 1 なのは、func_proc が使うのが常に")
    print("  ぼかし+1 だから(verify_edge_ramp.py §1)。0 でも 1画素の階調は残る。")

    print("\n  同型の登録(check_n=0, ex_data_size=0, コールバック全NULL):")
    same = [x for x in walk(img)
            if x.check_n == 0 and x.ex_data_size == 0
            and not (x.func_init or x.func_exit or x.func_update or x.func_wndproc)]
    for x in sorted(same, key=lambda x: -x.track_n)[:4]:
        print(f"    [{x.index:>3}] {x.name:<16} track_n={x.track_n}")
    check(f"その形は全{len(walk(img))}登録中 {len(same)} 個あり、"
          f"トラックバー5本は斜めクリッピングだけ",
          max(x.track_n for x in same if x.name != NAME) < 5
          and max(x.track_n for x in same) == 5)

    print("\n  グループ化マーカー(+0x74 スロット[1], param_scaling.md §1):")
    check("斜めクリッピングは全ゼロ ―― 中心X/中心Y は2成分コントロールでは無い",
          not r.slot1 or not any(r.slot1))
    ripple = find(img, "波紋")[0]
    print(f"    波紋            slot[1] = {ripple.slot1}  ({ripple.track_names[:2]} が2成分)")
    print(f"    斜めクリッピング slot[1] = {r.slot1}")
    check("同じ 中心X/中心Y という名前でも、波紋 のほうはまとめられている",
          ripple.slot1 and any(ripple.slot1))

    print("\n--- 2. 1016バイト・3関数で全部 ---")
    total = 0
    for addr in FUNCS:
        body = function_body(img, addr, limit=0x400)
        end = body[-1].address + body[-1].size
        total += end - addr
        print(f"  0x{addr:08x}-0x{end - 1:08x}  {end - addr:>4} バイト  "
              f"{len(body):>3} 命令  (末尾 {body[-1].mnemonic})")
    body = function_body(img, WORKER_BAND, limit=0x400)
    span_end = body[-1].address + body[-1].size
    span = span_end - FUNC_PROC
    print(f"  連続領域 0x{FUNC_PROC:08x}-0x{span_end - 1:08x} = {span} バイト "
          f"(うち命令 {total}、残り {span - total} バイトは nop パディング)")
    check("3関数が隙間なく並んでいる(パディングは16バイト境界合わせの範囲)",
          0 <= span - total < 3 * 16, f"パディング {span - total} バイト")
    check("エフェクト固有コードは 1016 バイト", span == 1016, f"{span}")
    ranking = sorted(list(KNOWN_SIZES.items()) + [(NAME, span)], key=lambda kv: kv[1])
    print("  解析済みの小さいエフェクト: "
          + " < ".join(f"{n}({s})" for n, s in ranking))
    check("フェード/凸エッジ/ルミナンスキー に次ぐ4番目",
          [n for n, _ in ranking].index(NAME) == 3)

    print("\n--- 3. 3関数への参照 ---")
    branches = relative_branch_targets(img)
    for addr, label in ((FUNC_PROC, "func_proc"), (WORKER_HALFPLANE, "worker 幅==0"),
                        (WORKER_BAND, "worker 幅!=0")):
        rel = branches.get(addr, [])
        dwords = scan(img, addr)
        where = [f"0x{v:08x}[{'code' if FUNC_PROC <= v < span_end else 'data'}]" for v in dwords]
        print(f"  0x{addr:08x} {label:<14} rel32 分岐: {len(rel)}   dword 即値: {where}")
        check(f"{label}: 直接 call/jmp する命令は1つも無い", not rel,
              f"{[hex(v) for v in rel]}")
    check("func_proc の参照は登録構造体の1個だけ",
          len(scan(img, FUNC_PROC)) == 1
          and not (FUNC_PROC <= scan(img, FUNC_PROC)[0] < span_end))
    check("2つのワーカーの参照は func_proc の push 各1個だけ",
          all(len(scan(img, a)) == 1 and FUNC_PROC <= scan(img, a)[0] < span_end
              for a in (WORKER_HALFPLANE, WORKER_BAND)))
    print("  → ワーカーは exec_multi_thread_func に関数ポインタとして渡される")
    print("    以外の入口を持たない。他エフェクトからの流用も無い。")

    print("\n--- 4. グローバル6個 ---")
    outside = []
    for va, what in GLOBALS.items():
        hits = scan(img, va)
        codes = [v for v in hits if img.pe.get_section_by_rva(v - img.image_base)
                 and img.pe.get_section_by_rva(v - img.image_base).Name.rstrip(b"\x00") == b".text"]
        out = [v for v in codes if not (FUNC_PROC <= v < span_end)]
        outside += out
        print(f"  0x{va:08x}  {what:<26} 参照 {len(hits)} 箇所 "
              f"({nearest_owner(owners, codes[0]).split(' +')[0]} ほか)")
    check("6個とも、参照は 0x1005cab0-0x1005cea7 の中だけ", not outside,
          f"外の参照 {[hex(v) for v in outside]}")
    check("6個とも .data の連続領域 0x101b20c4-0x101b20d8 に並ぶ",
          sorted(GLOBALS) == list(range(0x101B20C4, 0x101B20DC, 4)))

    print("\n--- 5. 外に出るのは _ftol とイージング表だけ ---")
    calls, jumps = set(), set()
    for addr in FUNCS:
        for insn in function_body(img, addr, limit=0x400):
            if insn.op_str.startswith("0x") and insn.mnemonic in ("call", "jmp"):
                (calls if insn.mnemonic == "call" else jumps).add(int(insn.op_str, 16))
            elif insn.op_str.startswith("0x") and insn.mnemonic.startswith("j"):
                jumps.add(int(insn.op_str, 16))
    print(f"  直接呼び出し先: {[hex(t) for t in sorted(calls)]}")
    check("直接呼ぶのは _ftol (0x10091ad8) だけ", sorted(calls) == [FTOL],
          f"{[hex(t) for t in sorted(calls)]}")
    check("分岐先はすべて 1016 バイトの中(尾呼び出しで他へ飛ぶ経路も無い)",
          all(FUNC_PROC <= t < span_end for t in jumps),
          f"{[hex(t) for t in sorted(jumps) if not FUNC_PROC <= t < span_end]}")
    indirect = [insn.address for addr in FUNCS
                for insn in function_body(img, addr, limit=0x400)
                if insn.mnemonic == "call" and not insn.op_str.startswith("0x")]
    print(f"  間接呼び出し: {[hex(a) for a in indirect]} "
          f"(= [fp+0x60]+0xCC の exec_multi_thread_func、func_proc の2箇所)")
    check("間接呼び出しは func_proc の2箇所だけで、ワーカーには1つも無い",
          len(indirect) == 2 and all(a < WORKER_HALFPLANE for a in indirect))
    table_hits = [v for v in scan(img, EASE_TABLE) if FUNC_PROC <= v < span_end]
    check("イージング表 0x101dcf78 を3箇所で引く(半平面1 + 帯2)",
          len(table_hits) == 3, f"{[hex(v) for v in table_hits]}")
    noise = [x for x in walk(img) if x.func_init == 0x1006C680]
    check("その表を実行時に埋めるのは ノイズ の func_init (0x1006c680)",
          [x.name for x in noise] == ["ノイズ"],
          f"{[x.name for x in noise]}")
    print("  lut_tables.md が「呼び出し元は未特定」としていた生成ルーチンは、")
    print("  FILTER_DLL 配列の中に func_init として登録されている。呼ぶのは")
    print("  AviUtl ではなく(この配列は AviUtl に登録されない)、exedit 自身の")
    print("  効果テーブル初期化ループである:")
    seq = [(0x100315DE, "mov", "eax, dword ptr [esi + 0x34]"),   # fp->func_init
           (0x100315E1, "test", "eax, eax"),
           (0x100315E3, "je", "0x100315eb"),
           (0x100315E5, "push", "esi"),
           (0x100315E6, "call", "eax")]
    init_loop = {i.address: i for i, _ in disasm_range(img, 0x10031570, 0xA0, resolve=False)}
    for va, mnem, ops in seq:
        insn = init_loop.get(va)
        got = f"{insn.mnemonic} {insn.op_str}" if insn else "<命令境界に乗らない>"
        print(f"    0x{va:08x}: {got}")
        checks.append(insn is not None and insn.mnemonic == mnem and insn.op_str == ops)
    check("+0x60/+0x64 を書くのと同じ周回で func_init を呼んでいる", all(checks[-5:]))
    print("  → ノイズを一度も使わなくても、exedit が読み込まれた時点で表は埋まる。")

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
