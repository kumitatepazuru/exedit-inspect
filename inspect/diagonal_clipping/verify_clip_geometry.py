"""`幅` が作る3つのモードと、そのあいだにある不連続。

`func_proc` は `幅 << 15` の ZF だけを見て2つのワーカーを選び、`幅 != 0` 側は
さらに符号で2変種に割れる。3つとも末端は同じ
(`verify_edge_ramp.py`)ので、違いは符号付き距離 `s = vx·(x-cx) + vy·(y-cy)`
から `m` を作るところに凝縮されている:

    幅 == 0   m = s + band/2          直線の片側を消す(半平面)
    幅 >  0   m = hw - |s|            直線を挟む幅 幅 の帯を「残す」
    幅 <  0   m = |s| + hw            同じ帯を「消す」   (hw = 幅·32768 < 0)

7つの主張:

  1. **分岐は `幅 == 0` ちょうど**。`shl edx, 0xf` の ZF なので、生値の範囲
     (-2000..2000)では `幅 == 0` 以外に半平面へ行く値は無い。

  2. **`hw = 幅 << 15` は Q16 の「半値幅」**。`|v| = 65536` が 1 画素なので
     `hw/65536 = 幅/2` 画素、つまり `幅` は**帯の全幅**である。

  3. **半平面(`幅=0`)の階調帯は直線の上に centered に乗る。** `base` に
     足した `band/2` を引き戻さないのがその理由で、`幅 != 0` 側は行ごとに
     `sub ecx, band/2` で引き戻している(同じ prologue を共有した結果)。

  4. **`幅 > 0` の階調帯は帯の内側、`幅 < 0` は外側**にだけ乗る。したがって
     アルファが 0 になる境目は `幅 > 0` なら `|d| = 幅/2` ちょうど、
     `幅 < 0` なら `|d| = |幅|/2` ちょうど(`d` は法線方向の画素距離)で、
     完全不透明になるのはそこから `ぼかし+1` 画素だけ離れた側。

  5. **半平面の対(角度 θ と θ+180)はアルファがちょうど足して元に戻る**
     ―― `table[i] + table[4096-i] = 4096` だから。**ところが帯の対
     (`幅 = +W` と `幅 = -W`)は戻らない**: 境界の `|d| = W/2` では
     両方とも透明で、`2(ぼかし+1)` 画素幅の切れ目が残る。

  6. **`幅 = 0` の左右で挙動が飛ぶ。** `幅 = +1` は「1画素幅の帯だけ残す」
     = ほぼ全消し、`幅 = -1` は「1画素幅の帯だけ消す」= ほぼ無変化、
     `幅 = 0` はその間の「半分消す」。連続なパラメータではない。

  7. **`幅 < 2(ぼかし+1)` では完全不透明な画素が1つも残らない**(`幅 > 0`
     のとき)。帯が階調帯より細いと、中心線ですら最大でも
     `table[hw·4096/band]` 倍にしかならない。

Run via main.py:
    uv run main.py inspect/diagonal_clipping/verify_clip_geometry.py
"""

import math

from tools.cints import c_div, sar, to_i32
from tools.pe_image import PEImage

EASE_C1 = 0x1009A758
EASE_C2 = 0x1009A4F8
DEG10 = 0x1009A410
Q16 = 0x1009A3E8
Q16_NEG = 0x1009A408

FULL = 0x1000


def make_table(c1: float, c2: float) -> list:
    return [math.trunc(c2 * (1 - math.cos(i * c1))) for i in range(4097)]


def vector(angle_raw: int, k: float, q16: float, q16n: float):
    t = angle_raw * k
    return math.trunc(math.sin(t) * q16), math.trunc(math.cos(t) * q16n)


def func_proc_globals(track, w, h, k, q16, q16n):
    """0x1005cab0-0x1005cb33。返り値は (cx, cy, vx, vy, blur1, hw, halfplane)。"""
    centre_x, centre_y, angle, blur, width = track
    cx = c_div(w, 2) + centre_x
    cy = c_div(h, 2) + centre_y
    vx, vy = vector(angle, k, q16, q16n)
    hw = to_i32(width << 15)
    return cx, cy, vx, vy, blur + 1, hw, hw == 0


def apply(alpha, track, w, h, table, k, q16, q16n, thread_num=1):
    """両ワーカーを1本に畳んだ再実装。`alpha` は [h][w] の list を破壊的に更新。

    分岐は3つとも `m` の作り方だけが違うので、命令に対応させたまま1本に
    まとめてある(0x1005cb70 と 0x1005ccb0 の prologue は同一)。
    """
    cx, cy, vx, vy, blur1, hw, halfplane = func_proc_globals(track, w, h, k, q16, q16n)
    band = math.trunc(math.sqrt(float(vx) * vx + float(vy) * vy) * blur1)
    div = sar(band + 255 + (0 if band + 255 >= 0 else 0xFF), 8)      # ceil(band/256)
    base = sar(band, 1) - cy * vy - cx * vx

    for tid in range(thread_num):
        y0 = c_div(h * tid, thread_num)
        y1 = c_div(h * (tid + 1), thread_num)
        if y0 >= y1:                                                # (B) ガードのみ
            continue
        for y in range(y0, y1):
            acc = to_i32(vy * y + base)
            if not halfplane:
                acc = to_i32(acc - c_div(band, 2))                  # 0x1005cd9f / 0x1005ce37
            for x in range(w):
                if halfplane:
                    m = acc                                         # s + band/2
                elif hw > 0:
                    m = hw - abs(acc)                               # 0x1005cdba
                else:
                    m = abs(acc) + hw                               # 0x1005ce51
                if m < band:
                    if m <= 0:
                        alpha[y][x] = 0
                    else:
                        alpha[y][x] = sar(alpha[y][x] * table[c_div(m * 16, div)], 12)
                acc = to_i32(acc + vx)
    return alpha


def flat(w, h, value=FULL):
    return [[value] * w for _ in range(h)]


def visible(alpha):
    return sum(1 for row in alpha for a in row if a > 0)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)
    k, q16, q16n = img.f64(DEG10), img.f64(Q16), img.f64(Q16_NEG)
    table = make_table(img.f64(EASE_C1), img.f64(EASE_C2))

    def run_mask(w, h, centre_x=0, centre_y=0, angle=0, blur=1, width=0, threads=1):
        return apply(flat(w, h), (centre_x, centre_y, angle, blur, width),
                     w, h, table, k, q16, q16n, threads)

    print("--- 1. 分岐は 幅 == 0 ちょうど ---")
    check("shl 幅,15 が 0 になるのは 幅 == 0 だけ(生値 -2000..2000)",
          [x for x in range(-2000, 2001) if to_i32(x << 15) == 0] == [0])
    check("幅 = ±1 でも hw = ±32768 ≠ 0 なので帯ワーカーへ行く",
          to_i32(1 << 15) == 32768 and to_i32(-1 << 15) == -32768)

    print("\n--- 2. 幅 は帯の全幅、hw はその半分 ---")
    print(f"  {'幅':>6}{'hw = 幅<<15':>14}{'hw / 65536 [画素]':>20}")
    for width in (1, 2, 8, 40, 2000):
        print(f"  {width:>6}{to_i32(width << 15):>14}{to_i32(width << 15) / 65536:>20.2f}")
    check("hw/65536 = 幅/2 が全範囲で成り立つ",
          all(to_i32(x << 15) / 65536 == x / 2 for x in range(-2000, 2001)))

    print("\n--- 3. 半平面の階調帯は直線の上に centered ---")
    # 32x32、角度 0、中心ぴったり。行方向のプロファイルを見る
    prof = [row[0] for row in run_mask(4, 32, blur=3, width=0)]
    cy = 16
    print("  角度=0・ぼかし=3(帯 4 画素)・32行の縦プロファイル(y=12..19):")
    for y in range(12, 20):
        print(f"    y={y:>3}  d={cy - y:+3d}px  alpha={prof[y]:>5}  "
              f"({prof[y] / FULL:.4f})")
    check("y = cy の1つ上と1つ下でアルファが対称的にまたがる(帯が線の上に乗る)",
          prof[cy - 1] > FULL // 2 > prof[cy], f"{prof[cy - 1]} / {prof[cy]}")
    check("帯の外はきれいに 0 と 4096",
          prof[cy - 4] == FULL and prof[cy + 3] == 0)

    print("\n--- 4. 帯の階調は内側(幅>0)/外側(幅<0)にだけ乗る ---")
    inner = [row[0] for row in run_mask(4, 40, blur=1, width=10)]     # 帯を残す
    outer = [row[0] for row in run_mask(4, 40, blur=1, width=-10)]    # 帯を消す
    cy = 20
    print(f"  角度=0・ぼかし=1(階調 2 画素)・幅=±10、cy={cy}:")
    print(f"  {'y':>4}{'d [px]':>8}{'幅=+10':>10}{'幅=-10':>10}")
    for y in range(cy - 8, cy + 1):
        print(f"  {y:>4}{cy - y:>8}{inner[y]:>10}{outer[y]:>10}")
    check("幅=+10: |d| >= 5 で完全に透明、|d| <= 3 で完全に不透明",
          inner[cy - 5] == 0 and inner[cy - 3] == FULL)
    check("幅=-10: |d| <= 5 で完全に透明、|d| >= 7 で完全に不透明",
          outer[cy - 5] == 0 and outer[cy - 7] == FULL)
    print("  → アルファ0の境目はどちらも |d| = 幅/2 ちょうど。完全不透明までの")
    print("    ぼかし+1 画素が、+ では内側へ、- では外側へ伸びる。")

    print("\n--- 5. 対にしても元に戻るのは半平面だけ ---")
    a1 = run_mask(4, 40, angle=0, blur=3, width=0)
    a2 = run_mask(4, 40, angle=1800, blur=3, width=0)     # 180.0 度
    sums = [a1[y][0] + a2[y][0] for y in range(40)]
    print(f"  角度 0 と 180.0 の半平面を足した値(y=16..23): {sums[16:24]}")
    check("半平面の対は全行で 4096 に戻る(誤差 2/4096 = 0.05% 以内)",
          all(abs(s - FULL) <= 2 for s in sums),
          f"最大ずれ {max(abs(s - FULL) for s in sums)}")
    check("土台の恒等式 table[i] + table[4096-i] は 4094..4096",
          all(FULL - 2 <= table[i] + table[4096 - i] <= FULL for i in range(4097)))
    check("4094 になるのは i = 2048 の1点だけ(cos(pi/2) の浮動小数点誤差)",
          [i for i in range(4097) if table[i] + table[4096 - i] == FULL - 2] == [2048])
    print("  実数では 2048(1-cos x) + 2048(1+cos x) = 4096 ちょうど。ずれるのは")
    print("  切り捨てが2回入るからで、しかも表の中点 table[2048] が理論値 2048 では")
    print("  なく 2047 になっている(lut_tables.md §2)ぶんが上乗せされる。")
    b1 = run_mask(4, 40, blur=3, width=12)
    b2 = run_mask(4, 40, blur=3, width=-12)
    sums = [b1[y][0] + b2[y][0] for y in range(40)]
    gap = [y for y in range(40) if sums[y] < FULL // 2]
    print(f"  幅=+12 と 幅=-12 を足した値(y=10..19): {sums[10:20]}")
    check("帯の対は境目で足しても戻らず、切れ目が残る", bool(gap), f"欠ける行 {gap}")
    check("切れ目は両縁に1つずつ、合わせて 2·(ぼかし+1) 画素程度",
          len(gap) in range(2 * (3 + 1) - 2, 2 * (3 + 1) + 4), f"{len(gap)} 行")
    print("  理由: +W は m = hw-|s|、-W は m = |s|-hw で、|d| = W/2 では両方 m = 0。")
    print("  半平面が戻るのは m の和が band に一致するからで、帯では和が 0 になる。")

    print("\n--- 6. 幅 = 0 の左右で飛ぶ ---")
    w, h = 24, 24
    print(f"  {w}x{h}・角度=0・ぼかし=1、可視画素数 (最大 {w * h}):")
    print(f"  {'幅':>6}{'可視':>8}{'不透明':>8}{'意味':>26}")
    for width in (-4, -2, -1, 0, 1, 2, 4):
        m = run_mask(w, h, blur=1, width=width)
        opaque = sum(1 for row in m for a in row if a == FULL)
        meaning = {-4: "4px幅の帯を消す", -2: "2px幅の帯を消す", -1: "1px幅の帯を消す",
                   0: "上半分を残す", 1: "1px幅の帯を残す", 2: "2px幅の帯を残す",
                   4: "4px幅の帯を残す"}[width]
        print(f"  {width:>6}{visible(m):>8}{opaque:>8}{meaning:>26}")
    m_minus1 = run_mask(w, h, blur=1, width=-1)
    m_zero = run_mask(w, h, blur=1, width=0)
    m_plus1 = run_mask(w, h, blur=1, width=1)
    check("幅=-1 は可視画素が 95% 以上残る(消えるのは中心の1行だけ)",
          visible(m_minus1) >= 0.95 * w * h, f"{visible(m_minus1)}/{w * h}")
    check("幅=+1 は可視画素が 5% 以下(残るのは中心の1行だけ)",
          visible(m_plus1) <= 0.05 * w * h, f"{visible(m_plus1)}/{w * h}")
    check("幅=0 はちょうど半分だけ残す",
          abs(visible(m_zero) - w * h / 2) <= w)
    check("幅=+1 は完全不透明な画素が1つも無い",
          not any(a == FULL for row in m_plus1 for a in row))
    print("  生値を1つ動かしただけで可視画素が 4% ⇄ 96% に飛ぶ。`幅` は 0 を")
    print("  またいで連続なパラメータではなく、3つのモードのセレクタである。")
    print("  UI 上どう体感されるかは実機で見ていない ―― これは命令列とその")
    print("  Python 再実装からの帰結である。")

    print("\n--- 7. 幅 < 2(ぼかし+1) では完全不透明が消える ---")
    print(f"  {'ぼかし':>8}{'2(ぼかし+1)':>14}{'完全不透明が出る最小の 幅':>28}")
    for blur in (0, 1, 2, 5):
        threshold = None
        for width in range(1, 40):
            m = run_mask(8, 64, blur=blur, width=width)
            if any(a == FULL for row in m for a in row):
                threshold = width
                break
        print(f"  {blur:>8}{2 * (blur + 1):>14}{threshold:>28}")
        checks.append(threshold == 2 * (blur + 1))
    check("しきい値は常に 幅 = 2(ぼかし+1)", checks[-4:] == [True] * 4)

    print("\n--- 8. スレッド分割 ---")
    ref = run_mask(19, 19, blur=2, width=6, threads=1)
    for n in (2, 3, 4, 8, 32):
        got = run_mask(19, 19, blur=2, width=6, threads=n)
        checks.append(got == ref)
    check("thread_num = 2/3/4/8/32 のどれでも1スレッドと同じ結果になる",
          all(checks[-5:]))
    print("  ワーカーは thread_split.md の (B) だけの形(`if (y0 >= y1) return;`)で、")
    print("  `寸法 < thread_num` で担当が空になるスレッドが増えるだけ。行ループの")
    print("  外に書き込みが無いので §4 の重複書き込みも起きない。")

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
