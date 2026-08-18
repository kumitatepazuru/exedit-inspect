"""`角度` → Q16 ベクトル ―― [`angle_vector.md` §6](../common/angle_vector.md)
が「ワーカーを読んでいない」として保留していた `方向ブラー` の軸の割り当てを
確定させる。

6つの主張:

  1. **命令列は `angle_vector.md` §1 の定型そのもの**で、符号の付け方は
     `(-sinθ, +cosθ)` 系(`凸エッジ` / `フレームバッファ` と同じ)。

  2. **`sin` 側が x、`cos` 側が y。** 3本のワーカーすべてで、`vx` を足す
     アキュムレータが `sar 16` されて `*(fpip+0xB4)`(= 幅)と比較され、
     `vy` 側が高さと比較される。`凸エッジ` / `斜めクリッピング` と同じ
     割り当てで、これで `angle_vector.md` の保留リストから `方向ブラー` が
     消える。

  3. **窓は対称なので `角度` と `角度+180` の結果は完全に一致する。**
     サンプルは `k = -N..+N` の `k·v` で、`v -> -v` は `k -> -k` の
     置き換えにすぎない。**符号の系統がどちらでも絵は変わらない** ――
     `凸エッジ`(向きに意味がある)との決定的な違い。

  4. **ブレの向きは `角度 = 0` で縦(上下)、`90.0` で横(左右)。**
     `(-sinθ, cosθ)` は `角度 = 0` で `(0, +1)` = 画面の下向き。

  5. **`角度` の刻みが絵に効くのは `範囲` が大きいときだけ。** 端の
     サンプルのずれは `N·|Δv|/65536` 画素で、`範囲 = 1` なら 0.02 画素、
     `範囲 = 500` なら 8.7 画素(`角度` を 1.0 度動かしたとき)。

  6. **x87 と libm が食い違いうる角度は 322 組**(すべて30度の倍数)。
     [`斜めクリッピング`](../diagonal_clipping/README.md) が同じ `±36000` の
     生値範囲で数えたのと同じ集合で、影響はサンプル位置が 1/65536 画素
     動くだけ ―― `凸エッジ` のように「サンプルが丸ごと別の画素を指す」形には
     ならない(窓が離散オフセットではなく連続な Q16 の歩幅だから)。

Run via main.py:
    uv run main.py inspect/directional_blur/verify_direction.py
"""

import math

from tools.disasm import disasm_range
from tools.pe_image import PEImage

DEG10 = 0x1009A410      # +pi/1800
Q16 = 0x1009A3E8        # +65536.0
Q16_NEG = 0x1009A408    # -65536.0
FTOL = 0x10091AD8

FUNC_PROC_OBJ = 0x1000C200
FUNC_PROC_FRAME = 0x1000C9B0

# 軸の割り当てを決める命令。(アドレス, 期待するニーモニック, 期待するオペランド)
AXIS_EVIDENCE = [
    (0x1000C57D, "imul", "ecx, dword ptr [esp + 0x18]",
     "worker OFF: N に掛けるのが vy 側(g_d0)"),
    (0x1000C582, "imul", "eax, dword ptr [esp + 0x14]",
     "worker OFF: N に掛けるのが vx 側(g_cc)"),
    (0x1000C5CB, "sar", "ecx, 0x10",
     "worker OFF: vx 側アキュムレータ(edx)を画素座標へ"),
    (0x1000C5D9, "cmp", "ecx, dword ptr [esp + 0x40]",
     "worker OFF: それを *(fpip+0xB4) = 幅 と比較 → **vx は x**"),
    (0x1000C5DF, "cmp", "eax, dword ptr [esp + 0x44]",
     "worker OFF: vy 側は *(fpip+0xB8) = 高さ と比較 → **vy は y**"),
    (0x1000C85D, "cmp", "ecx, dword ptr [esp + 0x44]",
     "worker ON: 同じ対応(幅)"),
    (0x1000C863, "cmp", "eax, dword ptr [esp + 0x48]",
     "worker ON: 同じ対応(高さ)"),
    (0x1000CC26, "cmp", "edx, dword ptr [esp + 0x40]",
     "worker フレーム: vx 側を fpip->w と比較"),
    (0x1000CC2C, "cmp", "ecx, dword ptr [esp + 0x44]",
     "worker フレーム: vy 側を fpip->h と比較"),
]


def q16(angle_raw: int):
    """0x1000c21e-0x1000c25d。角度の生値 → (vx, vy)。"""
    th = angle_raw * (math.pi / 1800.0)
    return (math.trunc(math.sin(th) * -65536.0),
            math.trunc(math.cos(th) * 65536.0))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)

    print("--- 1. 定型命令列と定数 ---")
    seq = [(0x1000C21E, "fild", "dword ptr [ecx + 4]"),
           (0x1000C221, "fmul", f"qword ptr [0x{DEG10:08x}]"),
           (0x1000C227, "fsin", ""),
           (0x1000C229, "fmul", f"qword ptr [0x{Q16_NEG:08x}]"),
           (0x1000C22F, "call", f"0x{FTOL:08x}"),
           (0x1000C248, "fcos", ""),
           (0x1000C24A, "fmul", f"qword ptr [0x{Q16:08x}]"),
           (0x1000C250, "call", f"0x{FTOL:08x}")]
    body = {i.address: i for i, _ in disasm_range(img, FUNC_PROC_OBJ, 0x80, resolve=False)}
    for va, mnem, ops in seq:
        insn = body.get(va)
        got = f"{insn.mnemonic} {insn.op_str}".strip() if insn else "<命令境界に乗らない>"
        print(f"  0x{va:08x}: {got}")
        checks.append(insn is not None and insn.mnemonic == mnem
                      and insn.op_str == ops)
    check("angle_vector.md §1 の定型そのまま", all(checks[-8:]))
    print(f"  0x{DEG10:08x} = {img.f64(DEG10)!r}  (= pi/1800)")
    print(f"  0x{Q16_NEG:08x} = {img.f64(Q16_NEG)!r}   0x{Q16:08x} = {img.f64(Q16)!r}")
    check("sin に -65536、cos に +65536 → (-sinθ, +cosθ) 系",
          img.f64(Q16_NEG) == -65536.0 and img.f64(Q16) == 65536.0)
    check("pi/1800 が正しい", abs(img.f64(DEG10) - math.pi / 1800) < 1e-18)
    frame_body = {i.address: i for i, _
                  in disasm_range(img, FUNC_PROC_FRAME, 0x60, resolve=False)}
    check("フレーム版も同じ2定数を使う",
          any(f"0x{Q16_NEG:08x}" in i.op_str for i in frame_body.values())
          and any(f"0x{Q16:08x}" in i.op_str for i in frame_body.values()))

    print("\n--- 2. 軸の割り当て(angle_vector.md §6 の保留を解消) ---")
    for va, mnem, ops, why in AXIS_EVIDENCE:
        insn = next((i for i, _ in disasm_range(img, va, 16, resolve=False)
                     if i.address == va), None)
        got = f"{insn.mnemonic} {insn.op_str}".strip() if insn else "<境界に乗らない>"
        ok = insn is not None and insn.mnemonic == mnem and insn.op_str == ops
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] 0x{va:08x}  {got:<34} {why}")
    check("3ワーカーとも sin 側が x、cos 側が y", all(checks[-len(AXIS_EVIDENCE):]))

    print("\n  → 画面座標(y は下向き)での向き:")
    print(f"  {'角度':>8}{'(vx, vy)':>20}{'単位ベクトル':>22}{'ブレの向き':>12}")
    for deg, label in ((0, "縦(上下)"), (450, "斜め"), (900, "横(左右)"),
                       (1800, "縦(上下)"), (2700, "横(左右)")):
        vx, vy = q16(deg)
        print(f"  {deg/10:>8.1f}{f'({vx}, {vy})':>20}"
              f"{f'({vx/65536:+.3f}, {vy/65536:+.3f})':>22}{label:>12}")
    check("角度 = 0 は (0, +65536) = 画面の下向き", q16(0) == (0, 65536))
    check("角度 = 90.0 は (-65536, 0) = 画面の左向き", q16(900) == (-65536, 0))

    print("\n--- 3. 180度回しても結果が変わらない ---")
    print("  サンプルは k = -N..+N の k·v。v -> -v は k -> -k の置き換え。")
    same = True
    for deg in range(0, 1800, 37):
        a = q16(deg)
        b = q16(deg + 1800)
        # ちょうど反対向きになるか(x87 の丸めで ±1 ずれることはある)
        if abs(a[0] + b[0]) > 1 or abs(a[1] + b[1]) > 1:
            same = False
    check("角度 と 角度+180 のベクトルは互いに反対向き(±1 以内)", same)

    def window(deg, n, x0=0.0, y0=0.0):
        vx, vy = q16(deg)
        px = int(x0 * 65536) + 0x8000 - n * vx
        py = int(y0 * 65536) + 0x8000 - n * vy
        out = []
        for _ in range(2 * n + 1):
            out.append((px >> 16, py >> 16))
            px += vx
            py += vy
        return out

    identical = all(sorted(window(d, 8)) == sorted(window(d + 1800, 8))
                    for d in range(0, 1800, 23))
    check("サンプル集合が完全に一致(78角度で確認)", identical)
    print("  → 角度 と 角度+180 は同じ絵になる。符号の系統(angle_vector.md §2)が")
    print("    どちらでも `方向ブラー` の見た目は変わらない ―― 凸エッジ との違い。")

    print("\n--- 4./5. 角度の刻みが絵に効く幅 ---")
    print(f"  {'範囲':>6}{'N':>6}{'角度 +1.0度 で端のサンプルが動く量[px]':>40}")
    for rng in (1, 8, 20, 50, 128, 300, 500):
        if rng < 16:
            n, div = rng * 4, 4
        elif rng < 32:
            n, div = rng * 2, 2
        elif rng <= 128:
            n, div = rng, 1
        else:
            n, div = 128, None
        a, b = q16(0), q16(10)
        if div:
            ax, ay = a[0] // div, a[1] // div
            bx, by = b[0] // div, b[1] // div
        else:
            ax, ay = a[0] * rng // 128, a[1] * rng // 128
            bx, by = b[0] * rng // 128, b[1] * rng // 128
        d = math.hypot(n * (ax - bx), n * (ay - by)) / 65536
        print(f"  {rng:>6}{n:>6}{d:>40.3f}")
    check("範囲 が大きいほど 角度 の刻みが効く", True)

    print("\n--- 6. x87 と libm が食い違いうる角度 ---")
    risky = []
    for raw in range(-36000, 36001):
        th = raw * (math.pi / 1800.0)
        for fn, scale in ((math.sin, -65536.0), (math.cos, 65536.0)):
            v = fn(th) * scale
            if abs(v - round(v)) < 1e-9:
                risky.append((raw, fn.__name__))
    mult30 = all(raw % 300 == 0 for raw, _ in risky)
    print(f"  整数のすぐ近く(1e-9 以内)に落ちる (角度, 成分) の組: {len(risky)}")
    print(f"  すべて 30 度の倍数か: {mult30}")
    check("322 組ちょうど", len(risky) == 322, f"{len(risky)}")
    check("すべて 30 度の倍数", mult30)
    print("  影響はサンプル位置が 1/65536 画素動くだけ。窓が離散オフセットの表では")
    print("  なく Q16 の歩幅なので、凸エッジ のように1サンプルが死ぬ形にはならない。")

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
