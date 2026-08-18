"""`範囲` は「何画素ぶれるか」と「何回サンプルするか」を別々に決める。

`func_proc` は `範囲` の生値を見て、Q16 の方向ベクトル `v` と片側サンプル数
`N` を4通りに付け替える(0x1000c2e4-0x1000c358):

    範囲 < 16    v /= 4          N = 範囲·4
    範囲 < 32    v /= 2          N = 範囲·2
    範囲 <= 128  (そのまま)      N = 範囲
    範囲 > 128   v = v·範囲/128  N = 128

7つの主張:

  1. **どの枝でも `N·|v| = 範囲·65536`**、つまり**片側の到達距離は必ず
     `範囲` 画素**。窓は `k = -N..+N` の `2N+1` サンプルなので、
     支持長は `2·範囲 + 1` 画素になる。

  2. **変わるのはサンプル密度だけ。** `範囲 < 16` で 4 サンプル/画素、
     `< 32` で 2、`<= 128` で 1、`> 128` では 1 未満 ―― **`範囲` が 128 を
     超えると1画素あたり1サンプルを割り込む**。

  3. **サンプル数は 4〜257 の間に収まる。** `2N+1` は `範囲 = 1` で 9、
     `範囲 = 8` で 65、`範囲 = 32..128` で `2·範囲+1`、`範囲 > 128` で常に 257。

  4. **`fpip->flag & 0x200` は `N` を 50 に落とす。** `v` は `v·N/50` に
     引き伸ばされるので**到達距離は変わらない** ―― 粗くなるだけ。
     50 という値は `閃光` / `放射ブラー` と共通。

  5. **`N <= 1` の早期 return は到達不能。** 生値 0 は関数の先頭で弾かれ、
     生値 1 でも `N = 4` になるので、この分岐に落ちる入力が存在しない。

  6. **キャンバスは角度によらず四方に `範囲` 画素ずつ広がる。** 横にしか
     ぶれない設定でも上下に `範囲` 画素の透明な余白が付く ―― `グロー` と
     同じ無駄([`canvas_growth.md` §6](../common/canvas_growth.md))。

  7. **削り方は左右(上下)対称**で、`放射ブラー` の「はみ出しが大きい側から」
     とは違う。中心という概念が無いので当然ではある。

Run via main.py:
    uv run main.py inspect/directional_blur/verify_sample_schedule.py
"""

import math

from tools.cints import c_div, divisor_of
from tools.pe_image import PEImage

MAGIC_50_VA = 0x1000C375   # mov eax, 0x51eb851f
MAGIC_50 = 0x51EB851F


def q16(angle_raw: int):
    th = angle_raw * (math.pi / 1800.0)
    return (math.trunc(math.sin(th) * -65536.0),
            math.trunc(math.cos(th) * 65536.0))


def schedule(rng: int, vx: int, vy: int, low_quality: bool = False):
    """0x1000c2e4-0x1000c3ac。戻り値 (vx, vy, N)。"""
    n = rng
    if rng < 16:
        vx, vy, n = c_div(vx, 4), c_div(vy, 4), rng * 4
    elif rng < 32:
        vx, vy, n = c_div(vx, 2), c_div(vy, 2), rng * 2
    elif rng > 128:
        vx, vy, n = c_div(vx * rng, 128), c_div(vy * rng, 128), 128
    if low_quality and n > 50:
        vx, vy, n = c_div(vx * n, 50), c_div(vy * n, 50), 50
    return vx, vy, n


def canvas_rect(w, h, rng, max_w=4000, max_h=4000):
    """0x1000c267-0x1000c2df。角度を一切見ない。"""
    x0, y0, x1, y1 = -rng, -rng, w + rng, h + rng
    while (x1 - x0) > max_w:
        x0 += 1
        x1 -= 1
    while (y1 - y0) > max_h:
        y0 += 1
        y1 -= 1
    return x0, y0, x1, y1


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)

    print("--- 0. 定数 ---")
    got = img.u32(MAGIC_50_VA)
    print(f"  0x{MAGIC_50_VA:08x}: マジック 0x{got:08x}")
    check("(0x51eb851f, sar 4) は /50", got == MAGIC_50 and divisor_of(MAGIC_50, 4) == 50)

    print("\n--- 1./2./3. 到達距離とサンプル密度 ---")
    print(f"  {'範囲':>6}{'N':>6}{'2N+1':>7}{'|v| (Q16)':>12}{'片側到達[px]':>14}"
          f"{'支持長[px]':>12}{'密度[/px]':>11}")
    worst = 0.0
    for rng in (1, 4, 8, 15, 16, 24, 31, 32, 64, 128, 129, 200, 300, 500):
        vx, vy, n = schedule(rng, *q16(900))       # 角度 90.0 = 真横
        mag = math.hypot(vx, vy) / 65536
        reach = n * mag
        worst = max(worst, abs(reach - rng))
        print(f"  {rng:>6}{n:>6}{2*n+1:>7}{math.hypot(vx, vy):>12.1f}"
              f"{reach:>14.3f}{2*reach+1:>12.3f}{1/mag if mag else 0:>11.2f}")
    check("片側の到達距離が 範囲 画素と一致(誤差 < 0.01px)", worst < 0.01,
          f"最大ずれ {worst:.5f}")

    print("\n  全角度で確かめる(範囲 = 1..500、角度 0..3599 の 1/17 サンプル):")
    worst, worst_at = 0.0, None
    for rng in (1, 7, 16, 31, 32, 100, 128, 129, 400, 500):
        for deg in range(0, 3600, 17):
            vx, vy, n = schedule(rng, *q16(deg))
            reach = n * math.hypot(vx, vy) / 65536
            if abs(reach - rng) > worst:
                worst, worst_at = abs(reach - rng), (rng, deg / 10)
    print(f"    最大ずれ {worst:.5f} px  at 範囲={worst_at[0]} 角度={worst_at[1]}")
    check("角度によらず到達距離は 範囲 画素(誤差 < 0.02px)", worst < 0.02)

    dens = {}
    for rng in range(1, 501):
        vx, vy, n = schedule(rng, *q16(900))
        dens[rng] = n / rng
    check("範囲 < 16 は 4 サンプル/画素", all(dens[r] == 4 for r in range(1, 16)))
    check("16 <= 範囲 < 32 は 2 サンプル/画素", all(dens[r] == 2 for r in range(16, 32)))
    check("32 <= 範囲 <= 128 は 1 サンプル/画素", all(dens[r] == 1 for r in range(32, 129)))
    check("範囲 > 128 は 1 未満(縞が出る側)", all(dens[r] < 1 for r in range(129, 501)))
    counts = {2 * schedule(r, *q16(900))[2] + 1 for r in range(1, 501)}
    check("カーネル幅は 9 〜 257 の範囲", min(counts) == 9 and max(counts) == 257,
          f"{min(counts)} 〜 {max(counts)}")

    print("\n--- 4. 描画品質フラグ(flag & 0x200) ---")
    print(f"  {'範囲':>6}{'通常 N':>8}{'低品質 N':>10}{'通常の到達':>12}"
          f"{'低品質の到達':>14}")
    for rng in (30, 60, 128, 300, 500):
        _, _, n0 = schedule(rng, *q16(900))
        vx0, vy0, _ = schedule(rng, *q16(900))
        vx1, vy1, n1 = schedule(rng, *q16(900), low_quality=True)
        r0 = n0 * math.hypot(vx0, vy0) / 65536
        r1 = n1 * math.hypot(vx1, vy1) / 65536
        print(f"  {rng:>6}{n0:>8}{n1:>10}{r0:>12.2f}{r1:>14.2f}")
        checks.append(abs(r0 - r1) < 1.0)
    check("低品質でも到達距離はほぼ同じ(サンプルが粗くなるだけ)", all(checks[-5:]))
    check("低品質の N は 50 で頭打ち",
          all(schedule(r, *q16(900), low_quality=True)[2] <= 50 for r in range(1, 501)))

    print("\n--- 5. N <= 1 の早期 return は到達不能 ---")
    lows = [r for r in range(1, 501) if schedule(r, *q16(900))[2] <= 1]
    print(f"  N <= 1 になる 範囲 の生値: {lows}(生値 0 は関数の先頭で弾かれる)")
    check("生値 1..500 のどれでも N >= 4", not lows)
    check("低品質側でも同じ",
          not [r for r in range(1, 501)
               if schedule(r, *q16(900), low_quality=True)[2] <= 1])

    print("\n--- 6. キャンバスは角度に依存しない ---")
    for rng in (10, 100, 300):
        x0, y0, x1, y1 = canvas_rect(320, 240, rng)
        print(f"  範囲={rng:>4}: ({x0},{y0})-({x1},{y1})  "
              f"{x1-x0}x{y1-y0}  片側 {-x0} 画素")
    check("四方に 範囲 画素ずつ(角度は式に出てこない)",
          canvas_rect(320, 240, 100) == (-100, -100, 420, 340))
    print("  角度 = 90.0(真横にしかぶれない)でも上下に 範囲 画素の余白が付く。")
    print("  → 外接矩形が実際に描かれている範囲より大きくなる。グロー と同じ形")
    print("    (canvas_growth.md §6)。")

    print("\n--- 7. 上限での削り方 ---")
    x0, y0, x1, y1 = canvas_rect(320, 240, 300, max_w=600)
    print(f"  範囲=300、最大キャンバス幅 600: x[{x0},{x1}) 幅 {x1-x0}")
    check("左右対称に削る(放射ブラーの「大きい側から」とは違う)",
          x0 == -(x1 - 320), f"x0={x0} x1={x1}")

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
