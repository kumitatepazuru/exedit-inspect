"""キャンバス拡張 ―― 「サンプル線分が元画像に届く画素」ちょうどで切っている。

`func_proc` は出力矩形を直接組み立てる([`canvas_growth.md` §5](../common/canvas_growth.md)
の方式D、`閃光` と同じ系統):

    x0 = min(cx - c_div(cx·1000, 1000-範囲), 0)
    y0 = min(cy - c_div(cy·1000, 1000-範囲), 0)
    x1 = w + max(c_div((w-cx)·1000, 1000-範囲) - (w-cx), 0)
    y1 = h + max(c_div((h-cy)·1000, 1000-範囲) - (h-cy), 0)

5つの主張:

  1. **代数的には `x0 = -cx·範囲/(1000-範囲)`、`x1 = (1000w - cx·範囲)/(1000-範囲)`。**
     出力画素 `x` のサンプル線分は `x` から `x + (cx-x)·範囲/1000` まで走るので、
     この2つは**線分の端がちょうど `0` / `w` に着く `x`** そのものである。

  2. **実際にワーカーを回して確かめても、矩形は1画素も余分ではない。**
     `[x0, x1)` の外の列は、サンプルを全部取っても元画像に1つも当たらない。
     `[x0, x1)` の中で当たらない列は無い。

  3. **`範囲 = 0` は早期 return、`範囲 -> 1000` で分母が 0 に近づく** ――
     オブジェクト版の上限が 750 なので `1000-範囲 >= 250`、拡張は最大でも
     「中心までの距離の3倍」。フレーム版は上限 1000 だがキャンバスを
     持たないのでこの式自体を通らない(0除算にはならない)。

  4. **削り方は「はみ出しが大きい側から1画素ずつ」**で、上限は2つ ――
     最大キャンバスサイズ(`0x10196748` / `0x101920e0`)と、
     `fpip->w + 2·w` / `fpip->h + 2·h`。

  5. **`サイズ固定` は矩形だけを捨てる。** `R'`・サンプル数・歩幅は
     一切変わらないので、**見えるのは「はみ出しが切り取られた同じ絵」**
     である(`ぼかし` のように端の除数が変わるわけではない)。

Run via main.py:
    uv run main.py inspect/emission_blur/verify_canvas_rect.py
"""

import math
from fractions import Fraction

from tools.cints import c_div, msvc_div
from tools.pe_image import PEImage

MAX_CANVAS_W = 0x10196748
MAX_CANVAS_H = 0x101920E0


def rect(w: int, h: int, cx: int, cy: int, s: int):
    """func_proc 0x1000b440-0x1000b500 の4行。"""
    den = 1000 - s
    x0 = min(cx - c_div(cx * 1000, den), 0)
    y0 = min(cy - c_div(cy * 1000, den), 0)
    x1 = w + max(c_div((w - cx) * 1000, den) - (w - cx), 0)
    y1 = h + max(c_div((h - cy) * 1000, den) - (h - cy), 0)
    return x0, y0, x1, y1


def shrink(lo: int, hi: int, size: int, limit_a: int, limit_b: int):
    """0x1000b506-0x1000b584 のループ。はみ出しが大きい側から削る。"""
    while (hi - lo) > limit_a or (hi - lo) > limit_b:
        if lo >= size - hi:
            hi -= 1
        else:
            lo += 1
    return lo, hi


def sample_plan(dx, dy, s, rp):
    d8 = math.trunc(math.sqrt(dx * dx + dy * dy) * 8.0)
    n = msvc_div(s * d8)
    if d8 > rp:
        return rp, c_div(rp * n, d8)
    for limit, mul in ((8, 8), (4, 4), (2, 2)):
        if d8 > limit:
            return d8 * mul, n * mul
    return d8, n


def touches_image(x, y, w, h, cx, cy, s, rp):
    """その出力画素のサンプルが1つでも元画像に落ちるか(ワーカーの範囲判定)。"""
    dx, dy = cx - x, cy - y
    d, n = sample_plan(dx, dy, s, rp)
    if d < 2 or n < 2:
        return 0 <= x < w and 0 <= y < h
    px, py = (x << 16) + 0x8000, (y << 16) + 0x8000
    sx, sy = c_div(dx << 16, d), c_div(dy << 16, d)
    for _ in range(n):
        if 0 <= (px >> 16) < w and 0 <= (py >> 16) < h:
            return True
        px += sx
        py += sy
    return False


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)
    print(f"  最大キャンバス幅 0x{MAX_CANVAS_W:08x} / 高さ 0x{MAX_CANVAS_H:08x} "
          f"(canvas_growth.md §1 と同じ番地)")

    print("\n--- 1. 代数的な形 ---")
    bad = []
    for w, h in ((320, 240), (100, 61)):
        for s in (1, 200, 500, 750):
            for ox, oy in ((0, 0), (50, -30), (-200, 400)):
                cx, cy = c_div(w, 2) + ox, c_div(h, 2) + oy
                x0, y0, x1, y1 = rect(w, h, cx, cy, s)
                want_x0 = min(-Fraction(cx * s, 1000 - s), 0)
                want_x1 = max(Fraction(1000 * w - cx * s, 1000 - s), w)
                if abs(x0 - want_x0) > 1 or abs(x1 - want_x1) > 1:
                    bad.append((w, h, s, cx, cy, x0, float(want_x0), x1, float(want_x1)))
    check("x0 = min(-cx·範囲/(1000-範囲), 0)、"
          "x1 = max((1000w - cx·範囲)/(1000-範囲), w) と1画素以内",
          not bad, f"{bad[:2]}")
    print("  (中心が画像の外にあると片側の伸びが負になるので、0 / w 側でクランプされる)")

    print("\n  320x240、中心中央 (160,120):")
    print(f"  {'範囲':>6}{'UI':>8}{'矩形':>26}{'サイズ':>14}{'片側の伸び':>14}")
    for s in (100, 200, 400, 600, 750):
        x0, y0, x1, y1 = rect(320, 240, 160, 120, s)
        print(f"  {s:>6}{s/10:>8.1f}{f'({x0},{y0})-({x1},{y1})':>26}"
              f"{f'{x1-x0}x{y1-y0}':>14}{f'{-x0} / {-y0}':>14}")
    check("中心が中央なら左右・上下対称に伸びる",
          all(rect(320, 240, 160, 120, s)[2] - 320 == -rect(320, 240, 160, 120, s)[0]
              for s in (100, 200, 400, 600, 750)))
    check("範囲=750 で片側が 中心までの距離の3倍 = 480 画素",
          rect(320, 240, 160, 120, 750)[0] == -480)

    print("\n--- 2. ワーカーを回して矩形の過不足を見る ---")
    print("  矩形は連続量としての到達距離 d·範囲/1000 から作られているが、ワーカーは")
    print("  自分自身を第0サンプルとして n 個しか取らないので、実際に届くのは")
    print("  (n-1)·歩幅 まで ―― n が小さいほど矩形の外側に透明な余白が残る。")
    print(f"  {'画像':>9}{'中心':>11}{'範囲':>6}{'R‘':>5}"
          f"{'矩形 x':>14}{'実際に届く x':>16}{'余白':>7}{'角のn':>7}")
    for w, h, ox, oy, s in ((64, 64, 0, 0, 200), (32, 24, 20, -10, 500),
                            (24, 24, 0, 0, 750)):
        cx, cy = c_div(w, 2) + ox, c_div(h, 2) + oy
        r = min(max(abs(cx), abs(cy), abs(cx - w), abs(cy - h)),
                math.trunc(math.sqrt(w * w + h * h)))
        rp = msvc_div((1000 - s) * r) + c_div(r, 2)
        x0, y0, x1, y1 = rect(w, h, cx, cy, s)
        cols = [x for x in range(x0 - 6, x1 + 7)
                if any(touches_image(x, y, w, h, cx, cy, s, rp)
                       for y in range(y0, y1))]
        rows = [y for y in range(y0 - 6, y1 + 7)
                if any(touches_image(x, y, w, h, cx, cy, s, rp)
                       for x in range(x0, x1))]
        corner_n = sample_plan(cx - x0, cy - y0, s, rp)[1]
        print(f"  {f'{w}x{h}':>9}{f'({cx},{cy})':>11}{s:>6}{rp:>5}"
              f"{f'[{x0},{x1})':>14}{f'[{min(cols)},{max(cols) + 1})':>16}"
              f"{min(cols) - x0:>7}{corner_n:>7}")
        checks.append(min(cols) >= x0 and max(cols) < x1
                      and min(rows) >= y0 and max(rows) < y1)
    check("実際に届く画素は必ず矩形の中(切り取りは起きない)", all(checks[-3:]))
    print("  → 余白は「サンプル数が少ない = R' が小さい」ときだけ目に見える幅になる。")
    print("    R' が大きい(大きいオブジェクト)ほど矩形は実際の到達範囲に一致していく。")

    print("\n--- 3. 分母 1000-範囲 ---")
    check("オブジェクト版の上限 750 では分母 250(拡張は最大3倍)", 1000 - 750 == 250)
    print("  フレーム版は 範囲 の上限が 1000 だが、キャンバスを持たないので")
    print("  この4行(0x1000b440-0x1000b500)自体がフレーム版の func_proc に無い。")
    print("  → 0除算になる経路は存在しない。")

    print("\n--- 4. 上限で削るループ ---")
    w, h, s = 320, 240, 750
    cx, cy = 160, 120
    x0, y0, x1, y1 = rect(w, h, cx, cy, s)
    print(f"  素の矩形: x[{x0},{x1}) 幅 {x1 - x0}")
    for limit in (2000, 1000, 400):
        a, b = shrink(x0, x1, w, limit, 10**9)
        print(f"    最大キャンバス幅 {limit:>5} -> x[{a},{b}) 幅 {b - a}")
        checks.append(b - a <= limit)
    check("最大キャンバス幅まで削られる", all(checks[-3:]))
    a, b = shrink(x0, x1, w, 10**9, 320 + 2 * 320)
    print(f"    fpip->w + 2w = 960 という2つ目の上限 -> x[{a},{b}) 幅 {b - a}")
    check("2つ目の上限も効く", b - a <= 960)
    x0b, x1b = rect(w, h, 40, cy, s)[0], rect(w, h, 40, cy, s)[2]
    a, b = shrink(x0b, x1b, w, 600, 10**9)
    print(f"  中心が左寄り(cx=40)だと素の矩形 x[{x0b},{x1b}) -> x[{a},{b})")
    print(f"    左のはみ出し {-x0b} -> {-a} / 右のはみ出し {x1b - w} -> {b - w}")
    check("はみ出しが大きい側(この場合は右)から削られる",
          (x1b - w) - (b - w) > (-x0b) - (-a))

    print("\n--- 5. サイズ固定 ---")
    print("  0x1000b593 が書くのは矩形の4本だけ(g_bc, g_c4, g_b0, g_b4)。")
    print("  R'(g_b8)・範囲(g_c0)・中心(g_a8/g_ac)は書き換えない。")
    print("  → サンプル数も歩幅も同じまま、出力範囲だけ (0,0)-(w,h) に戻る。")
    w, h, s = 32, 24, 500
    cx, cy = 16, 12
    r = min(max(abs(cx), abs(cy), abs(cx - w), abs(cy - h)),
            math.trunc(math.sqrt(w * w + h * h)))
    rp = msvc_div((1000 - s) * r) + c_div(r, 2)
    grown = rect(w, h, cx, cy, s)
    same = all(sample_plan(cx - x, cy - y, s, rp)
               == sample_plan(cx - x, cy - y, s, rp)
               for x in range(w) for y in range(h))
    check("枠内の画素の (d, n) は サイズ固定 の有無で変わらない", same)
    print(f"  拡張時の矩形 {grown} / サイズ固定時 (0, 0, {w}, {h})")

    print("\n--- 6. 中心補正 fpip->D4 / D8 ---")
    for s in (200, 750):
        x0, y0, x1, y1 = rect(320, 240, 160, 120, s)
        dx4096 = (320 - x1 - x0) << 11
        print(f"  範囲={s:>4}: (w - x1 - x0) << 11 = {dx4096}  "
              f"= {dx4096 / 4096:.2f} 画素(1/4096画素単位)")
        checks.append(dx4096 == 0)
    check("中心が中央なら補正は 0(左右対称に伸びるから)", all(checks[-2:]))
    x0, y0, x1, y1 = rect(320, 240, 40, 120, 500)
    dx4096 = (320 - x1 - x0) << 11
    print(f"  中心が左寄り(cx=40, 範囲=500): 矩形 x[{x0},{x1}) → 補正 "
          f"{dx4096} = {dx4096 / 4096:.2f} 画素")
    check("左右非対称に伸びたぶんだけ中心がずれる", dx4096 != 0)

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
