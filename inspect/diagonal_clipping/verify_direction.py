"""`角度` → Q16 の法線ベクトル、その軸の割り当て、そして帯幅の作り方。

[`angle_vector.md`](../common/angle_vector.md) は「`斜めクリッピング` は
`(+sinθ, -cosθ)` 系の命令列を持つが、**軸の割り当てまでは追っていない**」と
§6 で保留していた。ここではそれを閉じる。

6つの主張:

  1. **定数は共有品**。`0x1009a410` = `+pi/1800`、`0x1009a3e8` = `65536.0`、
     `0x1009a408` = `-65536.0`。`(vx, vy) = (sin θ·65536, cos θ·(-65536))` で、
     `グラデーション` と同じ符号の付け方、`凸エッジ` とはちょうど逆向き。

  2. **`sin` 側が x、`cos` 側が y** ―― 推測ではなく、ワーカーの命令が
     どちらのグローバルをどちらの座標に掛けているかで決まる。列ループの
     1画素ぶんの増分は `g_101b20d0`(sin 側)、行の項は
     `g_101b20d4`(cos 側)× y。中心を引く積も
     `中心X × sin側` / `中心Y × cos側` の組でしか現れない。

  3. **`角度 = 0` の法線は画面の上向き**で、正の角度で時計回りに回る。
     `幅 = 0` なら「法線が指す側が残り、反対側が消える」ので、既定では
     **直線より上が残って下が消える**。

  4. **帯幅 `band = trunc(|v| · (ぼかし+1))` の `|v|` は 65536 の決め打ちでは
     なく、`_ftol` 済みの成分から `fsqrt` で取り直したもの**。符号付き距離 `s`
     も同じ `(vx, vy)` で測るので単位が必ず揃い、**どの角度でも階調帯は
     法線方向に `ぼかし+1` 画素ちょうど**になる(全72001角度で誤差
     < 2e-5 画素)。65536 決め打ちでも差は 45度で 0.002%(2e-5 画素)しか
     出ないので、これは見た目の話ではなく「式が自己整合している」話である ――
     ただし `s` の単位が `|v|` である以上、帯幅を `ぼかし+1` 画素と**言い切れる**
     のはこの取り直しがあるからで、そこは読み替えではなく事実として要る。

  5. **列方向の累積は整数加算だけなので誤差が溜まらない**。
     `s(x+1) = s(x) + vx` は `base + vx·x` と完全に一致し、想定しうる最大の
     キャンバスでも int32 に収まる。

  6. **x87 と libm が食い違いうるのは 322 組**((角度, 成分)の組)。
     すべて 30 度の倍数で、それ以外の角度は最も際どいところでも整数まで
     7.4e-4 の余裕がある ―― `凸エッジ` §7 と同じ結論が、10倍広い
     `角度` 範囲(生値 ±36000 = ±3600.0 度)でもそのまま成り立つ。

Run via main.py:
    uv run main.py inspect/diagonal_clipping/verify_direction.py
"""

import math

from tools.cints import to_i32
from tools.disasm import disasm_range
from tools.pe_image import PEImage

DEG10 = 0x1009A410       # +pi/1800
Q16 = 0x1009A3E8         # 65536.0
Q16_NEG = 0x1009A408     # -65536.0

G_HALFWIDTH = 0x101B20C4
G_CX = 0x101B20C8
G_CY = 0x101B20CC
G_VX = 0x101B20D0
G_VY = 0x101B20D4
G_BLUR1 = 0x101B20D8

ANGLE_RAW = (-36000, 36000)   # 表示スケール10 -> -3600.0..3600.0 度

# 軸の割り当ての根拠になる命令。ここに書いた綴りが実際のバイト列と一致する
# ことを確かめてから、その意味を主張する。
AXIS_EVIDENCE = {
    # func_proc: 中心の組み立て
    0x1005CACC: ("mov", "dword ptr [0x101b20c8], eax", "g_c8 = w/2 + track[0](中心X)"),
    0x1005CAE2: ("mov", "dword ptr [0x101b20cc], eax", "g_cc = h/2 + track[1](中心Y)"),
    0x1005CB0D: ("mov", "dword ptr [0x101b20d0], eax", "g_d0 = _ftol(sin(θ)·65536)"),
    0x1005CB1D: ("mov", "dword ptr [0x101b20d4], eax", "g_d4 = _ftol(cos(θ)·(-65536))"),
    # 半平面ワーカー: 中心を引く2つの積
    0x1005CBE3: ("mov", "ecx, dword ptr [0x101b20cc]", "ecx = 中心Y"),
    0x1005CBE9: ("imul", "ecx, dword ptr [0x101b20d4]", "  × cos側 ―― 中心Y と組むのは cos"),
    0x1005CC07: ("mov", "edx, dword ptr [0x101b20c8]", "edx = 中心X"),
    0x1005CC14: ("mov", "eax, dword ptr [0x101b20d0]", "eax = sin側"),
    0x1005CC19: ("imul", "edx, eax", "  中心X × sin側 ―― 中心X と組むのは sin"),
    # 半平面ワーカー: 行の項と列の増分
    0x1005CC3B: ("mov", "ecx, dword ptr [0x101b20d4]", "行ループ: ecx = cos側"),
    0x1005CC41: ("imul", "ecx, edi", "  × edi = 行番号 y ―― y に掛かるのは cos"),
    0x1005CC7E: ("mov", "eax, dword ptr [esp + 0x14]", "eax = 保存しておいた sin側"),
    0x1005CC85: ("add", "ecx, eax", "  列を1つ進めるごとに += sin側 ―― x に掛かるのは sin"),
}


def vector(angle_raw: int, k: float, q16: float, q16_neg: float):
    """0x1005caea-0x1005cb1d をそのまま。`_ftol` は0方向切り捨て。

        fild 角度 ; fmul +pi/1800 ; fld st0 ; fsin ; fmul +65536 ; _ftol -> vx
                                              fcos ; fmul -65536 ; _ftol -> vy
    """
    t = angle_raw * k
    return math.trunc(math.sin(t) * q16), math.trunc(math.cos(t) * q16_neg)


def band_of(vx: int, vy: int, blur_raw: int) -> int:
    """0x1005cb97-0x1005cbdc: fild/fild/fmul/fmul/faddp/fsqrt/fimul/_ftol。"""
    return math.trunc(math.sqrt(float(vx) * vx + float(vy) * vy) * (blur_raw + 1))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)
    k, q16, q16n = img.f64(DEG10), img.f64(Q16), img.f64(Q16_NEG)

    print("--- 1. 定数 ---")
    check(f"0x{DEG10:08x} = {k!r} = +pi/1800", k == math.pi / 1800)
    check(f"0x{Q16:08x} = 65536.0 / 0x{Q16_NEG:08x} = -65536.0",
          q16 == 65536.0 and q16n == -65536.0)
    print(f"  {'角度':>9}{'vx':>9}{'vy':>9}{'単位ベクトル':>26}{'画面上':>8}")
    for raw in (0, 450, 900, 1800, 2700, -900, 36000):
        vx, vy = vector(raw, k, q16, q16n)
        where = {(0, -1): "上", (1, 0): "右", (0, 1): "下", (-1, 0): "左"}.get(
            (round(vx / 65536), round(vy / 65536)), "")
        print(f"  {raw / 10:>9.1f}{vx:>9}{vy:>9}"
              f"{f'({vx / 65536:+.4f}, {vy / 65536:+.4f})':>26}{where:>8}")
    check("角度 = 0 は (0, -65536) = 画面の上向き", vector(0, k, q16, q16n) == (0, -65536))
    check("角度 = 90.0 は (+65536, 0) = 右向き ―― 正の角度で時計回り",
          vector(900, k, q16, q16n) == (65536, 0))
    conv = [(-vector(r, k, q16, q16n)[0], -vector(r, k, q16, q16n)[1])
            for r in range(-3600, 3601, 7)]
    edge = [(math.trunc(math.sin(r * -k) * 65536.0), math.trunc(math.cos(r * -k) * 65536.0))
            for r in range(-3600, 3601, 7)]
    check("凸エッジ の (-sinθ, +cosθ) はこのベクトルのちょうど逆向き",
          conv == edge)

    print("\n--- 2. sin 側が x、cos 側が y(命令が言っている) ---")
    body = {i.address: i for i in
            [insn for insn, _ in disasm_range(img, 0x1005CAB0, 0x3F8, resolve=False)]}
    for va, (mnem, ops, why) in AXIS_EVIDENCE.items():
        insn = body.get(va)
        got = f"{insn.mnemonic} {insn.op_str}" if insn else "<命令境界に乗らない>"
        ok = insn is not None and insn.mnemonic == mnem and insn.op_str == ops
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] 0x{va:08x}: {got:<40} {why}")
    print("  → 中心X と sin側、中心Y と cos側 がそれぞれ組になり、列の増分が sin側、")
    print("    行の項が cos側。つまり s = vx·(x-cx) + vy·(y-cy) で vx = sin 側。")
    print("    angle_vector.md §6 の保留(軸の割り当て未確認)は斜めクリッピングに")
    print("    ついてはこれで解消する。")

    print("\n--- 3. 幅=0 で残るのは法線が指す側 ---")
    print("  0x1005cc4c の `cmp ecx, band / jge (触らない)` が「s が大きい側を残す」で、")
    print("  0x1005cc56 の `mov word [esi+6], 0` が「s が小さい側を消す」。")
    print(f"  {'角度':>9}{'法線':>10}{'幅=0 で残る側':>16}")
    for raw, arrow, side in ((0, "上", "直線より上"), (900, "右", "直線より右"),
                             (1800, "下", "直線より下"), (2700, "左", "直線より左"),
                             (450, "右上", "直線より右上")):
        vx, vy = vector(raw, k, q16, q16n)
        print(f"  {raw / 10:>9.1f}{arrow:>10}{side:>16}")
    check("既定(角度=0, 中心=0, 幅=0)は上半分が残り下半分が消える、が命令からの帰結",
          vector(0, k, q16, q16n)[1] < 0)

    print("\n--- 4. band は |v| を取り直して作る ---")
    norms = [math.hypot(*vector(r, k, q16, q16n)) for r in range(*ANGLE_RAW, 1)]
    print(f"  |v| の範囲: {min(norms):.6f} .. {max(norms):.6f}  (65536 ちょうどではない)")
    check("|v| は 65536 を超えない(_ftol が0方向へ丸めるので必ず内側)",
          max(norms) <= 65536.0)
    worst = 0.0
    for raw in range(ANGLE_RAW[0], ANGLE_RAW[1] + 1, 1):
        vx, vy = vector(raw, k, q16, q16n)
        n = math.hypot(vx, vy)
        for blur in (0, 1, 5, 2000):
            worst = max(worst, abs(band_of(vx, vy, blur) / n - (blur + 1)))
    check("階調帯の幅 = band/|v| は全72001角度で ぼかし+1 画素ちょうど",
          worst < 2e-5, f"最大誤差 {worst:.2e} 画素")
    vx, vy = vector(450, k, q16, q16n)
    naive = band_of(vx, vy, 0) / 65536.0
    print(f"  45.0度・ぼかし=0: band={band_of(vx, vy, 0)}, |v|={math.hypot(vx, vy):.4f}")
    print(f"    band/|v|    = {band_of(vx, vy, 0) / math.hypot(vx, vy):.8f} 画素 (実装)")
    print(f"    band/65536  = {naive:.8f} 画素 (もし 65536 決め打ちなら)")
    check("65536 決め打ちとの差は 45度でも 2e-5 画素 ―― 見た目には出ない",
          abs(naive - 1.0) < 1e-4 and naive != band_of(vx, vy, 0) / math.hypot(vx, vy))
    print("  つまりこれは絵が変わる話ではなく、`s` と `band` が同じ単位だと")
    print("  言い切れる根拠のほう。この取り直しがあるから「階調帯は ぼかし+1 画素」を")
    print("  角度によらず断言できる。")

    print("\n--- 5. 列方向の累積は誤差ゼロ・オーバーフロー無し ---")
    bad = []
    for raw in range(ANGLE_RAW[0], ANGLE_RAW[1] + 1, 211):
        vx, vy = vector(raw, k, q16, q16n)
        acc = 0
        for x in range(2000):
            if acc != vx * x:
                bad.append((raw, x))
                break
            acc = to_i32(acc + vx)
    check("s(x+1) = s(x) + vx の累積は base + vx·x と完全一致(丸めが入らない)",
          not bad, f"{bad[:1]}")
    # 想定しうる最悪: 最大キャンバス 幅・高さと 中心 が両端まで振れた場合
    max_dim, max_centre, max_blur = 8000, 2000, 2000
    reach = max_dim // 2 + max_centre
    worst_s = 65536 * reach * 2 + 65536 * (max_blur + 1) // 2
    check(f"|s| + band/2 の最悪値 {worst_s} は int32 に収まる",
          worst_s < (1 << 31), f"上限 {(1 << 31) - 1}")

    print("\n--- 6. x87 と libm が食い違いうる角度 ---")
    risky = [(raw, nm) for raw in range(ANGLE_RAW[0], ANGLE_RAW[1] + 1)
             for nm, v in (("sin", math.sin(raw * k) * q16),
                           ("cos", math.cos(raw * k) * q16n))
             if abs(v - round(v)) < 1e-9]
    others = [abs(v - round(v)) for raw in range(ANGLE_RAW[0], ANGLE_RAW[1] + 1)
              for v in (math.sin(raw * k) * q16, math.cos(raw * k) * q16n)
              if abs(v - round(v)) >= 1e-9]
    check(f"{len(risky)} 組が整数の直上に落ちる", len(risky) == 322)
    check("すべて 30 度の倍数(sin/cos が 0, ±0.5, ±1 になる点)",
          all(raw % 300 == 0 for raw, _ in risky))
    check("それ以外は整数まで 7.4e-4 以上の余裕がある(double の ulp より桁違いに大きい)",
          min(others) > 7e-4, f"最小 {min(others):.2e}")
    print("  影響は「成分が 32768 か 32767 か」、つまり境界が 1/65536 画素ずれるだけで、")
    print("  凸エッジ のように「サンプルが1つ丸ごと消える」ような効き方はしない ――")
    print("  斜めクリッピングはベクトルを画素オフセットに落とさず、Q16 のまま")
    print("  距離の比較に使うからである。")

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
