"""`モーションブラー` の登録2個と、外部に依存している6本のルーチン。

主張:

  1. **登録2個・`func_proc` は共有**(`0x1006bd30`)。オブジェクト側だけ
     チェックボックスが3個、フレーム側は1個。フレーム側は
     [`filter_registration.md` §2](../common/filter_registration.md) の
     「オブジェクト側の配列の途中を指す」手口**ではなく**、自前の1要素
     `check_name` 配列(`0x100a8af8`、オブジェクト側の配列のすぐ手前)を
     持ち、同じ文字列 `'出力時に分解能を上げる'` を指している。
     `check_default` に至っては `.rdata` ではなく**書き換え可能な `.data` の
     ゼロ dword**(`0x101bad44`、このエフェクトのグローバル群の隣)を
     指している。

  2. **トラックバーに `+0x74` のドラッグ範囲が無い。** `slot[2]`/`slot[3]` が
     NULL なので、スライダーは生値の範囲そのままで動く ―― 解析済みの
     エフェクトでこの形は珍しい。

  3. **エフェクト固有コードは `0x1006bd30`-`0x1006c64f` の 2336 バイト・
     4関数**(`func_proc` + ワーカー3本)。

  4. **画素を触るコードより、exedit のコア側を呼ぶコードのほうが目立つ。**
     直接呼び出しは6本 ―― 名前付きキャッシュ `0x1004d7d0`、別オブジェクト
     として描画 `0x1004b200`、指定時刻のフレーム描画 `0x1004ccf0`、
     オブジェクト添字の解決 `0x1002b0d0`、1画素の「下に合成」`0x1000ad80`、
     そして間接呼び出しのオフスクリーン描画 `[0x100b8c60]`。

  5. **`0x1000ad80`(1画素を下に合成)は `モーションブラー` 専用**で、
     ブレンド関数テーブル `0x1009fbb0`([`blend_modes.md` §3](../common/blend_modes.md))
     には載っていない。式は「転送先を転送元の**上**に置く」通常合成の
     引数を入れ替えた形。

  6. **`0x1004b200` を呼ぶ7エフェクトのうち、`fpip` の時刻を動かしてから
     呼ぶのは `モーションブラー` だけ**([`object_time.md` §7](../common/object_time.md))。

  7. **再帰を止める仕掛けは1つではなく、描き直しの経路3本それぞれに別々に
     ある。** 冒頭の再入ガード(`g_101bad48`)は `fp->flag & 0x20` と
     `check[1]`(`オフスクリーン描画`)の**両方**が真のときしか使われない。
     残る2経路はガードを持たず、代わりに `fp->0xE4`(= エフェクト列内での
     自分の位置)を描画ルーチンへ渡している:

         0x1006bfc1  0x1004b200(objID, fpip, 0)          + g_101bad48 = 1
         0x1006bfe4  0x1004b200(objID, fpip, fp->0xE4)   ガード無し
         0x1006c06b  0x1004ccf0(fp->0xE4, fpip, ...)     ガード無し

     `fp->0xE4` は `0x1006bf16` で読んで `0x1006bf1d` の
     `mov [esp+0x18], eax` で退避される。この時点の `esp` は直前の
     `push ecx`(`0x1006bf1c`)ぶん 4 だけ低いので、`add esp, 4` 後の
     ループ本体からは **`[esp+0x14]`** として見える ―― 経路2・経路3が
     読んでいるのはこのスロットである。

Run via main.py:
    uv run main.py inspect/motion_blur/verify_registration.py
"""

import struct

from tools.disasm import disasm_range, function_body
from tools.filter_table import find, walk
from tools.pe_image import PEImage
from tools.xrefs import function_owners, nearest_owner, scan

NAME = "モーションブラー"
FUNCS = (0x1006BD30, 0x1006C0D0, 0x1006C2E0, 0x1006C500)
SPAN_LO, SPAN_HI = 0x1006BD30, 0x1006C650

HELPERS = {
    0x1004D7D0: "名前付きキャッシュ",
    0x1004B200: "別オブジェクトとして描画",
    0x1004CCF0: "指定時刻のフレームを描く",
    0x1002B0D0: "オブジェクト添字の解決",
    0x1000AD80: "1画素を「下に」合成",
    0x10091AD8: "CRT _ftol",
}
OFFSCREEN_PTR = 0x100B8C60
BLEND_TABLE = 0x1009FBB0
REENTRY = 0x101BAD48
GUARD_SKIP = 0x1006BD8B      # 再入ガードを飛ばした先
ID_SLOT = "dword ptr [esp + 0x14]"   # fp->0xE4 を退避したスロット(docstring §7)


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
              f"func_proc=0x{r.func_proc:08x} -> {r.role}")
        print("        track: " + ", ".join(
            f"{nm}({r.track_defaults[i]}, {r.track_s[i]}..{r.track_e[i]})"
            for i, nm in enumerate(r.track_names)))
        print(f"        check: {list(r.check_names)}  default={list(r.check_defaults)}")
    check("func_proc を共有", obj.func_proc == frm.func_proc)
    check("オブジェクト側 check_n=3 / フレーム側 check_n=1",
          obj.check_n == 3 and frm.check_n == 1)
    ocn = img.u32(obj.struct_va + 0x28)
    fcn = img.u32(frm.struct_va + 0x28)
    ocd = img.u32(obj.struct_va + 0x2C)
    fcd = img.u32(frm.struct_va + 0x2C)
    print(f"  check_name  オブジェクト 0x{ocn:08x} / フレーム 0x{fcn:08x}  差 {fcn - ocn}")
    print(f"  check_default オブジェクト 0x{ocd:08x} / フレーム 0x{fcd:08x}  差 {fcd - ocd}")
    print(f"    オブジェクト側 check_name[] = "
          f"{[img.cstr(img.u32(ocn + 4 * i)) for i in range(3)]}")
    print(f"    フレーム側     check_name[] = {[img.cstr(img.u32(fcn))]}")
    check("フレーム側は自前の1要素配列を持つ(途中を指すのではない)",
          fcn + 4 == ocn and img.u32(fcn) == img.u32(ocn + 8))
    check("同じ文字列を指す", img.u32(fcn) == img.u32(ocn + 8))
    check("フレーム側の check_default は .data 側のゼロ dword",
          img.u32(frm.struct_va + 0x2C) == 0x101BAD44 and img.u32(0x101BAD44) == 0)
    check("残る1個は 出力時に分解能を上げる",
          frm.check_names[0] == "出力時に分解能を上げる"
          and obj.check_names[2] == "出力時に分解能を上げる")
    check("ex_data も func_WndProc も +0x78 も無い",
          not any(r.ex_data_size or r.func_wndproc or img.u32(r.struct_va + 0x78)
                  for r in regs))

    print("\n--- 2. ドラッグ範囲を持たない ---")
    print(f"  +0x74 = 0x{obj.ext_va:08x}  slot: scale={obj.scale} "
          f"group={obj.slot1} drag_min={obj.drag_min} drag_max={obj.drag_max}")
    check("ドラッグ範囲(slot[2]/slot[3])が NULL",
          obj.drag_min is None and obj.drag_max is None)
    nodrag = [r.name for r in walk(img) if r.track_n and r.ext_va and r.drag_min is None]
    print(f"  同じ形の登録: {sorted(set(nodrag))}")
    check("モーションブラーがその中にいる", NAME in nodrag)
    check("表示スケールは2本とも 1(生値がそのまま UI の数値)",
          [obj.track_scale(i) for i in range(2)] == [1, 1])

    print("\n--- 3. 2336バイト・4関数 ---")
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
    check("4関数が隙間なく並んでいる", 0 <= span - total < 4 * 16,
          f"パディング {span - total} バイト")

    print("\n--- 4. 外へ出る呼び出し ---")
    calls, indirect = set(), []
    for addr in FUNCS:
        for insn in function_body(img, addr, limit=0x400):
            if insn.address >= SPAN_HI:
                break
            if insn.mnemonic == "call":
                if insn.op_str.startswith("0x"):
                    calls.add(int(insn.op_str, 16))
                else:
                    indirect.append((insn.address, insn.op_str))
    print(f"  直接呼び出し: {[hex(t) for t in sorted(calls)]}")
    for t in sorted(calls):
        print(f"    0x{t:08x}  {HELPERS.get(t, '?')}")
    check("6本の直接呼び出しはすべて既知のヘルパー",
          set(calls) <= set(HELPERS),
          f"{[hex(t) for t in sorted(set(calls) - set(HELPERS))]}")
    print(f"  間接呼び出し: {[(hex(a), o) for a, o in indirect]}")
    check("オフスクリーン描画 [0x100b8c60] を2箇所から呼ぶ",
          sum(1 for _, o in indirect if hex(OFFSCREEN_PTR)[2:] in o) == 2)
    print(f"  [0x{OFFSCREEN_PTR:08x}] が指すのは "
          f"0x{img.u32(OFFSCREEN_PTR):08x} = オフスクリーン描画の func_proc")
    off = [r for r in walk(img) if r.name == "オフスクリーン描画"][0]
    check("その値は オフスクリーン描画 の func_proc と一致",
          img.u32(OFFSCREEN_PTR) == off.func_proc,
          f"0x{off.func_proc:08x}")

    print("\n--- 5. 0x1000ad80 ―― 合成モード表の 0x12 番 ---")
    branches = relative_branch_targets(img)
    users = sorted({nearest_owner(owners, v).split(".")[0]
                    for v in branches.get(0x1000AD80, [])})
    print(f"  直接呼ぶのは {users}(呼び出し {len(branches.get(0x1000AD80, []))} 箇所)")
    check("直接呼び出しはモーションブラーの1箇所だけ", users == [NAME])
    tbl = img.u32_array(BLEND_TABLE, 32)
    idx = [i for i, v in enumerate(tbl) if v == 0x1000AD80]
    print(f"  ブレンド関数テーブル 0x{BLEND_TABLE:08x} での添字: {idx}"
          f"  (0x11 = 加算 0x{tbl[0x11]:08x}、0x13 = 単純コピー 0x{tbl[0x13]:08x} の間)")
    check("合成モード表の 0x12 番 = モード語 0x12000003 に相当", idx == [0x12])
    print("  → blend_modes.md §3 が読んでいた 0x00 / 0x11 / 0x13 / 0x02 に続く")
    print("    5本目。式は 0x10007df0(通常合成)の src/dst を入れ替えた形で、")
    print("    「引数の画素を転送先の**下**に置く」になる。")

    print("\n--- 6. 0x1004b200 を呼ぶエフェクト ---")
    callers = {}
    for v in branches.get(0x1004B200, []):
        callers.setdefault(nearest_owner(owners, v).split(".")[0], 0)
        callers[nearest_owner(owners, v).split(".")[0]] += 1
    for k, v in sorted(callers.items()):
        print(f"    {k:<20} {v} 箇所")
    check("モーションブラーは2箇所から呼ぶ", callers.get(NAME) == 2)
    # 呼ぶ直前に fpip の3つの時刻を書き換えているのはここだけ
    pre = [i for i, _ in disasm_range(img, 0x1006BF90, 0x50, resolve=False)]
    writes = [i for i in pre if i.mnemonic == "mov" and i.op_str.startswith("dword ptr [esi + 0x")]
    print("  呼び出し直前の fpip への書き込み: "
          + ", ".join(i.op_str.split(",")[0].strip() for i in writes))
    check("fpip+0x114 / +0x1C / +0xA8 の3本を書いてから呼ぶ",
          {"dword ptr [esi + 0x114]", "dword ptr [esi + 0x1c]",
           "dword ptr [esi + 0xa8]"}
          <= {i.op_str.split(",")[0].strip() for i in writes})

    print("\n--- 7. 再帰を止める仕掛けが経路ごとに別 ---")
    head = {i.address: i for i, _ in disasm_range(img, 0x1006BD30, 0x30, resolve=False)}
    guard = [(0x1006BD3E, "test", "byte ptr [edi], 0x20", "fp->flag & 0x20(オブジェクト効果か)"),
             (0x1006BD41, "je", f"0x{GUARD_SKIP:08x}", "偽ならガードごと飛ばす"),
             (0x1006BD46, "mov", "ecx, dword ptr [eax + 4]", "check[1] = オフスクリーン描画"),
             (0x1006BD4B, "je", f"0x{GUARD_SKIP:08x}", "0 ならガードごと飛ばす"),
             (0x1006BD4D, "mov", "eax, dword ptr [0x101bad48]", "ここで初めて再入フラグを読む")]
    for va, mnem, ops, why in guard:
        insn = head.get(va)
        got = f"{insn.mnemonic} {insn.op_str}" if insn else "<境界に乗らない>"
        ok = insn is not None and insn.mnemonic == mnem and insn.op_str == ops
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] 0x{va:08x}  {got:<32} {why}")
    check("再入ガードは flag&0x20 と check[1] の両方が真のときだけ効く",
          all(checks[-5:]))

    body = {i.address: i for i, _ in disasm_range(img, 0x1006BFC1, 0xC8, resolve=False)}

    def seq(lo, hi):
        return [body[a] for a in sorted(body) if lo <= a < hi]

    path_a = seq(0x1006BFC1, 0x1006BFE4)
    print("  経路1(オブジェクト・オフスクリーン ON):")
    for i in path_a:
        print(f"    0x{i.address:08x}: {i.mnemonic} {i.op_str}")
    check("第3引数は 0(自分の素性を渡さない)",
          [i.op_str for i in path_a if i.mnemonic == "push"] == ["0", "esi", "eax"])
    check("call 0x1004b200 を g_101bad48 = 1 / 0 で挟む",
          [f"{i.mnemonic} {i.op_str}" for i in path_a
           if i.mnemonic == "mov" and hex(REENTRY)[2:] in i.op_str]
          == [f"mov dword ptr [0x{REENTRY:08x}], 1", f"mov dword ptr [0x{REENTRY:08x}], 0"])

    path_b = seq(0x1006BFE4, 0x1006BFF4)
    print("  経路2(オブジェクト・オフスクリーン OFF):")
    for i in path_b:
        print(f"    0x{i.address:08x}: {i.mnemonic} {i.op_str}")
    check("第3引数は fp->0xE4 を退避したスロット",
          any(i.mnemonic == "mov" and i.op_str == f"ecx, {ID_SLOT}" for i in path_b))
    check("この経路は g_101bad48 を一度も触らない",
          not any(hex(REENTRY)[2:] in i.op_str for i in path_b))

    path_c = seq(0x1006C05B, 0x1006C083)
    print("  経路3(フレームフィルタ):")
    for i in path_c:
        print(f"    0x{i.address:08x}: {i.mnemonic} {i.op_str}")
    check("0x1004ccf0 は7引数(add esp, 0x1c)",
          any(i.mnemonic == "add" and i.op_str == "esp, 0x1c" for i in path_c)
          and sum(1 for i in path_c if i.mnemonic == "push") == 7)
    # 直前に push が3つあるので、同じスロットが [esp+0x14] ではなく
    # [esp+0x14 + 0xc] = [esp+0x20] として現れる
    check("最後に push する第1引数が fp->0xE4 のスロット([esp+0x20] = 同じ番地)",
          any(i.mnemonic == "mov" and i.op_str == "edx, dword ptr [esp + 0x20]"
              for i in path_c)
          and [i.op_str for i in path_c if i.mnemonic == "push"][-1] == "edx")
    check("この経路も g_101bad48 を一度も触らない",
          not any(hex(REENTRY)[2:] in i.op_str for i in path_c))

    save = {i.address: i for i, _ in disasm_range(img, 0x1006BF10, 0x20, resolve=False)}
    print("  fp->0xE4 を ID_SLOT へ退避するところ:")
    for va in (0x1006BF16, 0x1006BF1C, 0x1006BF1D, 0x1006BF21, 0x1006BF26):
        i = save.get(va)
        print(f"    0x{va:08x}: {i.mnemonic} {i.op_str}" if i else
              f"    0x{va:08x}: <境界に乗らない>")
    check("push 1つを挟むので [esp+0x18] が後から [esp+0x14] に見える",
          save[0x1006BF16].op_str == "eax, dword ptr [edi + 0xe4]"
          and save[0x1006BF1C].mnemonic == "push"
          and save[0x1006BF1D].op_str == "dword ptr [esp + 0x18], eax"
          and save[0x1006BF26].op_str == "esp, 4")
    print("  → 経路2・経路3にはガードが無い。パイプライン側が fp->0xE4 を")
    print("    「ここまでで止めろ」として使っていなければ無限再帰するはずで、")
    print("    そうならない以上そう解釈されていると読める(0x1004b200 /")
    print("    0x1004ccf0 の中身は未読なので直接確認ではない。README §10)。")

    print("\n--- グローバル ---")
    for va, what in ((0x101BAD34, "出力先"), (0x101BAD38, "A"),
                     (0x101BAD3C, "入力元"), (0x101BAD40, "蓄積バッファ"),
                     (0x101BAD48, "再入フラグ")):
        codes = [v for v in scan(img, va)
                 if img.pe.get_section_by_rva(v - img.image_base)
                 and img.pe.get_section_by_rva(v - img.image_base).Name.rstrip(b"\x00") == b".text"]
        out = [v for v in codes if not (SPAN_LO <= v < SPAN_HI)]
        print(f"  0x{va:08x} {what:<14} .text 参照 {len(codes)} 箇所  "
              f"外 {[hex(v) for v in out]}")
        checks.append(not out)
    check("5個とも参照はこの 2336 バイトの中", all(checks[-5:]))

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
