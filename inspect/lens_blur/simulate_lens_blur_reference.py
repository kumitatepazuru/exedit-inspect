"""`レンズブラー` の整数忠実リファレンス実装(縮小が起きない `範囲 <= 8`)。

`範囲 <= 8` では内部半径 `R = 範囲` で縮小も拡大も起きない
(`verify_pipeline.py` §3)ので、**順変換 → 円形カーネル → 逆変換** の
3工程がそのまま出力になる。ここを厳密に再実装して、`範囲 >= 9` の
リサイズ工程はその前後に挟まる相似変換として扱う。

出力:

  §1  輝度カーブの往復(`光の強さ` の効き)
  §2  32x32 のスプライトに `範囲=5` を適用して ASCII 描画
  §3  **ハイライトが円板になる** ―― これが「レンズブラー」たるゆえん。
      1画素の明点を通すと `2R+1` 画素の円になり、`光の強さ` を上げるほど
      円の縁が立つ
  §4  端の扱い ―― 覆えた面積で正規化されるので平坦な不透明部は端でも
      アルファ 4096 のまま
  §5  スレッド数 1〜32 で一致すること
  §6  負の色差の丸め ―― `+sum_a/2` の四捨五入項は正の側にしか効かない

Run via main.py:
    uv run main.py inspect/lens_blur/simulate_lens_blur_reference.py
"""

import math

from tools.cints import c_div

FULL = 0x1000


# --------------------------------------------------------------------------
# 輝度カーブ(exp_log_curve.md §3、8バイト画素版)
# --------------------------------------------------------------------------

def base_of(strength: int) -> float:
    return 1.0 + max(1, min(100, strength)) * 0.001


def curve_forward(px, base):
    y, cb, cr, a = px
    if a <= 0:
        return (0.0, 0, 0, a)
    yy = float(pow(base, max(0, min(4096, y)) / 16.0) - 1.0)
    return (yy,
            max(-128, min(127, (cb + 8) >> 4)),
            max(-128, min(127, (cr + 8) >> 4)),
            a)


def curve_inverse(px, base):
    y, cb, cr, a = px
    yy = math.floor(math.log(y + 1.0) * 16.0 / math.log(base) + 0.5)
    return (yy, cb << 4, cr << 4, a)


# --------------------------------------------------------------------------
# 円形カーネル(0x10012880)
# --------------------------------------------------------------------------

def radii(r: int):
    outer = math.trunc((r + 0.5) ** 2)
    inner = math.trunc((r - 0.5) ** 2)
    return outer, inner, outer - inner


def worker(src, w, h, r, tid=0, nthread=1):
    outer, inner, div = radii(r)
    lo = c_div(h * tid, nthread)
    hi = c_div(h * (tid + 1), nthread)
    out = [[(0.0, 0, 0, 0)] * w for _ in range(h)]
    for y in range(lo, hi):
        for x in range(w):
            y0 = max(y - r, 0)
            y1 = min(y + r, h - 1)
            x0 = max(x - r, 0)
            x1 = min(x + r, w - 1)
            if y0 - y > y1 - y:
                continue
            sum_y = 0.0
            sum_cb = sum_cr = sum_a = sum_w = 0
            for dy in range(y0 - y, y1 - y + 1):
                d2 = dy * dy + (x0 - x) ** 2
                dx = x0 - x
                while dx <= x1 - x:
                    if d2 < outer:
                        if d2 <= inner:
                            wgt = FULL
                        else:
                            wgt = c_div((outer - d2) << 12, div)
                        sum_w += wgt
                        py, pcb, pcr, pa = src[y + dy][x + dx]
                        wa = pa if wgt == FULL else (pa * wgt) >> 12
                        sum_cb += pcb * wa
                        sum_cr += pcr * wa
                        sum_y += py * float(wa)
                        sum_a += wa
                    d2 += 2 * dx + 1
                    dx += 1
            if sum_a:
                out[y][x] = (sum_y / sum_a,
                             c_div(sum_cb + c_div(sum_a, 2), sum_a),
                             c_div(sum_cr + c_div(sum_a, 2), sum_a),
                             math.trunc(sum_a * 4096.0 / sum_w + 0.5))
            else:
                out[y][x] = (0.0, 0, 0, 0)
    return out


def lens_blur(src, w, h, rng, strength):
    """範囲 <= 8 の全工程。"""
    assert 1 <= rng <= 8
    base = base_of(strength)
    cur = [[curve_forward(p, base) for p in row] for row in src]
    cur = worker(cur, w, h, rng)
    return [[curve_inverse(p, base) for p in row] for row in cur]


RAMP = " .:-=+*#%@"


def draw(img, key, label, scale=FULL):
    print(f"  {label}")
    for row in img:
        line = "".join(RAMP[max(0, min(len(RAMP) - 1,
                                       key(p) * (len(RAMP) - 1) // scale))]
                       for p in row)
        print(f"    |{line}|")


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. 輝度カーブの往復 ---")
    print(f"  {'光の強さ':>10}{'base':>10}{'y=4096 のカーブ値':>20}"
          f"{'y=2048 のカーブ値':>20}{'比':>8}")
    for s in (0, 1, 10, 32, 60):
        b = base_of(s)
        hi = pow(b, 4096 / 16) - 1
        mid = pow(b, 2048 / 16) - 1
        print(f"  {s:>10}{b:>10.3f}{hi:>20.3f}{mid:>20.3f}"
              f"{hi / mid if mid else 0:>8.1f}")
    check("光の強さ = 0 でも base = 1.001(ヘルパーのクランプ)",
          base_of(0) == base_of(1) == 1.001)
    check("値が大きいほど明部が支配的になる",
          (pow(base_of(60), 256) - 1) / (pow(base_of(60), 128) - 1)
          > (pow(base_of(1), 256) - 1) / (pow(base_of(1), 128) - 1))

    print("\n--- 2. 32x32 スプライト、範囲=5、光の強さ=32 ---")
    w = h = 32
    src = [[(3500, -400, 900, FULL) if (12 <= x < 20 and 12 <= y < 20)
            else (0, 0, 0, 0) for x in range(w)] for y in range(h)]
    out = lens_blur(src, w, h, 5, 32)
    draw([row[6:26] for row in out[6:26]], lambda p: p[3],
         "出力アルファ(中央 20x20)")
    check("アルファは 4096 を超えない", max(p[3] for row in out for p in row) <= FULL)
    check("角が丸い(正方形の窓ではない)",
          out[7][7][3] == 0 and out[7][16][3] > 0,
          f"角 {out[7][7][3]} / 辺 {out[7][16][3]}")

    print("\n--- 3. 1画素のハイライトが円板になる ---")
    w = h = 21
    point = [[(4096, 0, 0, FULL) if (x == 10 and y == 10) else (0, 0, 0, 0)
              for x in range(w)] for y in range(h)]
    for rng in (3, 6):
        o = lens_blur(point, w, h, rng, 32)
        peak = max(p[3] for row in o for p in row)
        draw([row[10 - rng - 1:10 + rng + 2]
              for row in o[10 - rng - 1:10 + rng + 2]],
             lambda p: p[3],
             f"範囲={rng} のアルファ(直径 {2*rng+1} 画素、最大 {peak}/4096 で正規化)",
             scale=peak)
        lit = sum(1 for row in o for p in row if p[3] > 0)
        area = math.pi * rng * rng
        print(f"    点灯画素 {lit} / πR² = {area:.1f}   "
              f"アルファのピーク {peak} ≈ 4096/πR² = {4096/area:.0f}")
        checks.append(abs(lit - area) < 0.25 * area + 4)
        checks.append(abs(peak - 4096 / area) < 4)
    check("点灯範囲が πR² に一致 = 円板になっている", all(checks[-4::2]))
    check("アルファは 4096/πR² まで薄まる(1画素ぶんの光が円板に広がる)",
          all(checks[-3::2]))

    # 光の強さ の効きは「窓の中に明暗が混ざっている」ときに出る。
    mixed = [[(4096, 0, 0, FULL) if (x == 10 and y == 10) else (200, 0, 0, FULL)
              for x in range(w)] for y in range(h)]
    o_lo = lens_blur(mixed, w, h, 6, 1)
    o_hi = lens_blur(mixed, w, h, 6, 60)
    flat_lo = lens_blur([[(200, 0, 0, FULL)] * w for _ in range(h)], w, h, 6, 1)
    print(f"  暗い面(y=200)に明点(y=4096)を1つ置いて 範囲=6:")
    print(f"    光の強さ=1  -> 明点の位置の輝度 {o_lo[10][10][0]}"
          f"(周囲 {flat_lo[10][10][0]})")
    print(f"    光の強さ=60 -> 同 {o_hi[10][10][0]}")
    check("光の強さ を上げると明点の寄与が支配的になる",
          o_hi[10][10][0] > o_lo[10][10][0] + 100,
          f"{o_lo[10][10][0]} -> {o_hi[10][10][0]}")
    print("  → 一様重みの円板 + 明部を持ち上げるカーブ = 玉ボケ。")

    print("\n--- 4. 端の扱い ---")
    w = h = 24
    flat = [[(3000, 0, 0, FULL)] * w for _ in range(h)]
    o = lens_blur(flat, w, h, 6, 32)
    edge = [o[12][x][3] for x in range(8)]
    print(f"  平坦な不透明画像の左端のアルファ: {edge}")
    check("端でもアルファ 4096(覆えた面積で正規化される)",
          all(a == FULL for a in edge))
    print(f"  中央の画素: y={o[12][12][0]}, cb={o[12][12][1]}, cr={o[12][12][2]}")
    check("平坦部の輝度はカーブ往復で保たれる(±2 以内)",
          abs(o[12][12][0] - 3000) <= 2, f"{o[12][12][0]}")

    print("\n--- 5. スレッド分割 ---")
    w = h = 20
    src = [[(3500, -400, 900, FULL) if (7 <= x < 13 and 7 <= y < 13)
            else (0, 0, 0, 0) for x in range(w)] for y in range(h)]
    base = base_of(32)
    cur = [[curve_forward(p, base) for p in row] for row in src]
    ref = worker(cur, w, h, 4)
    ok = True
    for nthread in (1, 2, 3, 5, 8, 16, 32):
        acc = [[(0.0, 0, 0, 0)] * w for _ in range(h)]
        for tid in range(nthread):
            part = worker(cur, w, h, 4, tid, nthread)
            lo = c_div(h * tid, nthread)
            hi = c_div(h * (tid + 1), nthread)
            for y in range(lo, hi):
                acc[y] = part[y]
        if acc != ref:
            ok = False
    check("1〜32 スレッドで出力が完全一致", ok)

    print("\n--- 6. 色差の丸め ---")
    print("  out.cb = c_div(sum_cb + c_div(sum_a, 2), sum_a) ―― `+半分` は")
    print("  0方向切り捨てと組み合わさるので、**正の側だけが四捨五入**になる。")
    for num, den in ((1000, 7), (-1000, 7), (500, 7), (-500, 7)):
        exact = num / den
        got = c_div(num + c_div(den, 2), den)
        print(f"    {num:>6}/{den}: 厳密 {exact:>8.3f}  実装 {got:>5}  "
              f"ずれ {got - exact:+.3f}")
    check("負の側は 0 に寄る(四捨五入にならない)",
          c_div(-1000 + 3, 7) == -142 and abs(-1000 / 7 - (-142)) > 0.5)

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
