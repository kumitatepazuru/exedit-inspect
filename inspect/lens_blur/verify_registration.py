"""`レンズブラー` の登録2個と、工程を担う9本のヘルパー。

主張:

  1. **登録2個・`func_proc` は共有**(`0x10012420`)。
     `放射ブラー`/`方向ブラー` と違って普通の2登録モデルで、分岐は
     `fp->flag & 0x20` の1点([`filter_registration.md` §2](../common/filter_registration.md))。
     `func_WndProc` も `ex_data` も無い。

  2. **`サイズ固定` の既定が `1`(ON)** ―― exedit の全登録を見ても、
     `サイズ固定` という名前のチェックボックスで既定 ON なのは
     `レンズブラー` だけである。

  3. **`範囲` はスライダーでは 200 までしか動かせない**(生値の上限は 1000)。
     `+0x74` のドラッグ範囲が UI 表示範囲より狭い例
     ([`param_scaling.md` §1](../common/param_scaling.md))。

  4. **輝度カーブのヘルパー4本は `ぼかし` / `発光` と共有**。ただし
     `ぼかし` が `光の強さ > 0` のときだけ呼ぶのに対し、**`レンズブラー` は
     無条件に呼ぶ** ―― ヘルパー側が値を `[1, 100]` にクランプするので、
     `光の強さ = 0` でも `base = 1.001` のカーブを1往復する。

  5. **リサイズ4本(`0x10071420` / `0x100709a0` / `0x10072870` /
     `0x10072000`)は `レンズブラー` だけが呼ぶ。** 画像全体を縮小してから
     ぼかす、という工程を持つエフェクトが他に無い。

  6. **エフェクト固有コードは `0x10012420`-`0x10012dbf` の 2464 バイト・
     3関数。** グローバル4個(`0x1011ec5c`-`0x1011ec68`)の参照はその中に
     閉じている。

Run via main.py:
    uv run main.py inspect/lens_blur/verify_registration.py
"""

import struct

from tools.disasm import function_body
from tools.filter_table import find, walk
from tools.pe_image import PEImage
from tools.xrefs import function_owners, nearest_owner, scan

NAME = "レンズブラー"
FUNCS = (0x10012420, 0x10012880, 0x10012B50)
SPAN_LO, SPAN_HI = 0x10012420, 0x10012DC0

GLOBALS = {
    0x1011EC5C: "内部半径 R",
    0x1011EC60: "外半径² = R² + R",
    0x1011EC64: "2R(境界の階調の分母)",
    0x1011EC68: "内半径² = R² - R",
}

CURVE = {0x10070220: "順変換 8B", 0x100703F0: "逆変換 8B",
         0x10070550: "順変換 6B", 0x10070700: "逆変換 6B"}
RESIZE = {0x10071420: "縮小 8B(カーブ空間)", 0x100709A0: "拡大 8B(線形空間)",
          0x10072870: "縮小 6B", 0x10072000: "拡大 6B"}
RECT_XFER, RECT_CLEAR = 0x10081B40, 0x10081F90


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
    all_regs = walk(img)
    regs = find(img, NAME)
    obj, frm = regs

    print("--- 1. 登録2個・func_proc は共有 ---")
    for r in regs:
        print(f"  [{r.index:>3}] struct=0x{r.struct_va:08x} flag=0x{r.flag:08x} "
              f"func_proc=0x{r.func_proc:08x} WndProc=0x{r.func_wndproc:08x} "
              f"ex_data={r.ex_data_size} -> {r.role}")
        print("        track: " + ", ".join(
            f"{nm}({r.track_defaults[i]}, {r.track_s[i]}..{r.track_e[i]}, drag "
            f"{r.drag_min[i] if r.drag_min else '-'}.."
            f"{r.drag_max[i] if r.drag_max else '-'})"
            for i, nm in enumerate(r.track_names)))
        for i in range(r.check_n):
            print(f"        check[{i}] {r.check_names[i]!r} default={r.check_defaults[i]}")
    check("func_proc を共有(普通の2登録モデル)", obj.func_proc == frm.func_proc)
    check("オブジェクト側 flag=0x20 / フレーム側 flag=0x00",
          obj.flag == 0x20 and frm.flag == 0)
    check("func_WndProc も ex_data も +0x78 も無い",
          not any(r.func_wndproc or r.ex_data_size or img.u32(r.struct_va + 0x78)
                  for r in regs))
    check("トラックバー定義は2登録で同一",
          (list(obj.track_defaults), list(obj.track_s), list(obj.track_e))
          == (list(frm.track_defaults), list(frm.track_s), list(frm.track_e)))

    print("\n--- 2. サイズ固定 の既定が ON ---")
    sizes = [(r.name, r.check_defaults[i])
             for r in all_regs for i in range(r.check_n)
             if r.check_names[i] == "サイズ固定"]
    print(f"  「サイズ固定」を持つ登録と既定値: {sizes}")
    check("既定 1(ON)はレンズブラーだけ",
          [n for n, d in sizes if d == 1] == [NAME], f"{[n for n, d in sizes if d == 1]}")

    print("\n--- 3. スライダーのドラッグ範囲 ---")
    print(f"  範囲: 生値 {obj.track_s[0]}..{obj.track_e[0]}  "
          f"ドラッグ {obj.drag_min[0]}..{obj.drag_max[0]}")
    print(f"  光の強さ: 生値 {obj.track_s[1]}..{obj.track_e[1]}  "
          f"ドラッグ {obj.drag_min[1]}..{obj.drag_max[1]}")
    check("範囲 はスライダーでは 200 まで(数値入力なら 1000)",
          obj.drag_max[0] == 200 and obj.track_e[0] == 1000)
    check("光の強さ は 0..60 でドラッグ範囲も同じ(ぼかし の 光の強さ と同一)",
          (obj.track_s[1], obj.track_e[1], obj.drag_max[1]) == (0, 60, 60))
    blur = find(img, "ぼかし")[0]
    bi = list(blur.track_names).index("光の強さ")
    check("ぼかし の 光の強さ と生値範囲・既定が一致",
          (blur.track_s[bi], blur.track_e[bi]) == (obj.track_s[1], obj.track_e[1]),
          f"ぼかし {blur.track_defaults[bi]} / レンズブラー {obj.track_defaults[1]}")

    print("\n--- 4. 輝度カーブのヘルパー ---")
    branches = relative_branch_targets(img)
    for va, what in CURVE.items():
        callers = sorted({nearest_owner(owners, v).split(".")[0]
                          for v in branches.get(va, [])})
        print(f"  0x{va:08x} {what:<20} 呼ぶのは {callers}")
        checks.append(NAME in callers)
    check("4本とも レンズブラー が呼ぶ", all(checks[-4:]))
    check("8バイト版は ぼかし と、6バイト版は ぼかし・発光 と共有",
          "ぼかし" in {nearest_owner(owners, v).split(".")[0]
                       for v in branches.get(0x10070220, [])}
          and "発光" in {nearest_owner(owners, v).split(".")[0]
                         for v in branches.get(0x10070550, [])})
    # ぼかし は呼び出しの手前に `test eax,eax; jle` のガードを持つ
    guard = {i.address: i for i, _ in
             __import__("tools.disasm", fromlist=["disasm_range"])
             .disasm_range(img, 0x1000E535, 0x40, resolve=False)}
    print("  ぼかし 側のガード:")
    for va in (0x1000E535, 0x1000E539, 0x1000E53B):
        i = guard.get(va)
        print(f"    0x{va:08x}: {i.mnemonic} {i.op_str}")
    check("ぼかし は 光の強さ > 0 のときだけ呼ぶ",
          guard[0x1000E539].mnemonic == "test" and guard[0x1000E53B].mnemonic == "jle")
    lens_calls = [insn for insn, _ in
                  __import__("tools.disasm", fromlist=["disasm_range"])
                  .disasm_range(img, 0x100125BD, 0x40, resolve=False)]
    print("  レンズブラー 側(0x100125bd から):")
    for insn in lens_calls[:12]:
        print(f"    0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    check("レンズブラーには 光の強さ に対する test/jle が無い(無条件に呼ぶ)",
          not any(i.mnemonic in ("test", "cmp") and "eax, eax" in i.op_str
                  for i in lens_calls[:8]))
    clamp = {i.address: i for i, _ in
             __import__("tools.disasm", fromlist=["disasm_range"])
             .disasm_range(img, 0x10070220, 0x20, resolve=False)}
    print("  ヘルパー側のクランプ(0x10070220 の先頭):")
    for va in sorted(clamp)[:6]:
        print(f"    0x{va:08x}: {clamp[va].mnemonic} {clamp[va].op_str}")
    check("ヘルパーが値を [1, 100] にクランプする",
          any(i.op_str.endswith(", 1") for i in clamp.values())
          and any("0x64" in i.op_str for i in clamp.values()))

    print("\n--- 5. リサイズ4本はレンズブラー専用 ---")
    for va, what in RESIZE.items():
        callers = sorted({nearest_owner(owners, v).split(".")[0]
                          for v in branches.get(va, [])})
        n = len(branches.get(va, []))
        print(f"  0x{va:08x} {what:<24} 呼び出し {n} 箇所  {callers}")
        checks.append(callers == [NAME] and n == 1)
    check("4本とも呼び出し元は レンズブラー の1箇所だけ", all(checks[-4:]))

    print("\n--- 6. 2464バイト・3関数 ---")
    total = 0
    for addr in FUNCS:
        body = [i for i in function_body(img, addr, limit=0x500) if i.address < SPAN_HI]
        end = body[-1].address + body[-1].size
        total += end - addr
        print(f"  0x{addr:08x}-0x{end - 1:08x}  {end - addr:>4} バイト  "
              f"{len(body):>3} 命令")
    span = SPAN_HI - SPAN_LO
    print(f"  連続領域 0x{SPAN_LO:08x}-0x{SPAN_HI - 1:08x} = {span} バイト "
          f"(うち命令 {total}、残り {span - total} バイトは nop パディング)")
    check("3関数が隙間なく並んでいる", 0 <= span - total < 3 * 16,
          f"パディング {span - total} バイト")
    check("ワーカー2本は直接 call/jmp されない",
          not any(branches.get(a) for a in FUNCS))

    outside = []
    for va, what in GLOBALS.items():
        codes = [v for v in scan(img, va)
                 if img.pe.get_section_by_rva(v - img.image_base)
                 and img.pe.get_section_by_rva(v - img.image_base).Name.rstrip(b"\x00") == b".text"]
        outside += [v for v in codes if not (SPAN_LO <= v < SPAN_HI)]
        print(f"  0x{va:08x}  {what:<24} .text 参照 {len(codes)} 箇所")
    check("グローバル4個の参照はすべてその中", not outside,
          f"外の参照 {[hex(v) for v in outside]}")

    calls = set()
    for addr in FUNCS:
        for insn in function_body(img, addr, limit=0x500):
            if insn.address >= SPAN_HI:
                break
            if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
                calls.add(int(insn.op_str, 16))
    print(f"  直接呼び出し先: {[hex(t) for t in sorted(calls)]}")
    check("カーブ4本 + リサイズ4本 + _ftol の9本だけ",
          sorted(calls) == sorted(list(CURVE) + list(RESIZE) + [0x10091AD8]),
          f"{[hex(t) for t in sorted(calls)]}")
    print(f"  矩形転送 0x{RECT_XFER:08x} / 矩形クリア 0x{RECT_CLEAR:08x} は "
          "[fp+0x64]+0x44 / +0x48 の間接呼び出し(blend_modes.md)")

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
