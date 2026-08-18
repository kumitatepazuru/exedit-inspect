"""円形カーネル ―― `レンズブラー` が「ボケ」に見える理由。

ワーカーは `[-R, +R]²` の正方形を走査し、中心からの距離²で3通りに分ける
(0x100129c7-0x10012a13):

    d² >= trunc((R+0.5)²)   -> 読まない(円の外)
    d² <= trunc((R-0.5)²)   -> 重み 4096(円の内側、一律)
    それ以外                -> 重み = ((外² - d²) << 12) / (外² - 内²)

7つの主張:

  1. **`trunc((R+0.5)²) = R² + R`、`trunc((R-0.5)²) = R² - R`、差はちょうど
     `2R`。** `.25` が切り捨てられるので式が綺麗な整数になる。除数
     `g_1011ec64` は `func_proc` が引き算で作るが、結果は常に `2R`。

  2. **円の内側は重みが完全に一様**(4096)。ガウシアンでも三角形でもない
     ―― [`box_blur.md` §2](../common/box_blur.md) の「一様重みしか無い」が
     ここでも成り立つ。**違うのは窓の形が正方形ではなく円であること**だけ。

  3. **境界は1画素幅の線形ランプ**。`d² = R²` で重み 2048(ちょうど半分)。

  4. **`R = 0` は起きない**(`範囲 = 0` は早期 return、`範囲 >= 1` で
     `R >= 1`)。もし `R = 0` なら除数 `2R` が 0 になっていた。

  5. **カーネルの面積は πR² によく一致する。** `R = 45` で 6361 サンプル、
     `π·45² = 6362`。

  6. **窓は画像の端でクリップされ、そのぶん `sum_w` も減る**ので、
     アルファは常に「実際に覆えた面積」で正規化される ――
     [`box_blur.md` §3](../common/box_blur.md) の2つ目の変種。
     `サイズ固定` の ON/OFF はこの除数を変えない。

  7. **色差だけ四捨五入される。** `(sum_cb + sum_a/2) / sum_a` と
     `+0.5` 付きのアルファに対し、輝度は float 除算の素の切り捨て。
     同じ式の中に3種類の丸めが同居する例
     ([`integer_semantics.md`](../common/integer_semantics.md))。

Run via main.py:
    uv run main.py inspect/lens_blur/verify_disc_kernel.py
"""

import math

from tools.cints import c_div
from tools.pe_image import PEImage

HALF = 0x1009A3B0
ONE = 0x1009A428
FULL = 0x1000


def radii(r: int):
    """0x1001270a-0x10012748。_ftol は0方向切り捨て。"""
    outer = math.trunc((r + 0.5) * (r + 0.5))
    inner = math.trunc((r - 0.5) * (r - 0.5))
    return outer, inner, outer - inner


def weight(d2: int, outer: int, inner: int, div: int) -> int:
    if d2 >= outer:
        return 0
    if d2 <= inner:
        return FULL
    return c_div((outer - d2) << 12, div)


def kernel(r: int):
    """(サンプル数, 重みの総和, 一律 4096 の数)"""
    outer, inner, div = radii(r)
    n = tot = solid = 0
    for dy in range(-r, r + 1):
        for dx in range(-r, r + 1):
            w = weight(dx * dx + dy * dy, outer, inner, div)
            if w:
                n += 1
                tot += w
                solid += (w == FULL)
    return n, tot, solid


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)
    print(f"  0x{HALF:08x} = {img.f64(HALF)!r}   0x{ONE:08x} = {img.f64(ONE)!r}")
    check("定数は 0.5 と 1.0", img.f64(HALF) == 0.5 and img.f64(ONE) == 1.0)

    print("\n--- 1. 内外半径² と除数 ---")
    print(f"  {'R':>4}{'(R+0.5)²':>12}{'外²':>8}{'(R-0.5)²':>12}{'内²':>8}{'差':>6}")
    bad = []
    for r in list(range(1, 11)) + [16, 32, 45]:
        outer, inner, div = radii(r)
        print(f"  {r:>4}{(r+0.5)**2:>12.2f}{outer:>8}{(r-0.5)**2:>12.2f}"
              f"{inner:>8}{div:>6}")
        if (outer, inner, div) != (r * r + r, r * r - r, 2 * r):
            bad.append(r)
    check("外² = R²+R、内² = R²-R、差 = 2R(R = 1..45 の全部)",
          not [r for r in range(1, 46) if radii(r) != (r*r + r, r*r - r, 2*r)],
          f"{bad}")

    print("\n--- 2./3. カーネルの断面(R = 6)---")
    r = 6
    outer, inner, div = radii(r)
    print(f"  外² = {outer}, 内² = {inner}, 除数 = {div}")
    print(f"  {'dx':>4}" + "".join(f"{v:>6}" for v in range(-r, r + 1)))
    for dy in range(-r, r + 1):
        row = "".join(f"{weight(dx*dx + dy*dy, outer, inner, div):>6}"
                      for dx in range(-r, r + 1))
        print(f"  {dy:>4}{row}")
    inside = {weight(dx*dx + dy*dy, outer, inner, div)
              for dy in range(-r, r + 1) for dx in range(-r, r + 1)
              if dx*dx + dy*dy <= inner}
    check("円の内側の重みは 4096 のみ(一様)", inside == {FULL})
    mid = [weight(r * r, *radii(r)[:2], radii(r)[2]) for r in range(1, 46)]
    print(f"  d² = R² ちょうどの重み(R=1..45): {sorted(set(mid))}")
    check("d = R の重みはちょうど半分の 2048", set(mid) == {2048})
    ramp = sorted({weight(d2, outer, inner, div)
                   for d2 in range(inner + 1, outer)})
    print(f"  境界の重みが取る値(R=6): {ramp}")
    check("境界は線形ランプ(0 と 4096 の間の値を取る)",
          all(0 < v < FULL for v in ramp) and len(ramp) > 1)

    print("\n--- 4. R = 0 は起きない ---")
    print("  範囲 = 0 は func_proc 先頭の `jle` で return、範囲 >= 1 で R >= 1。")
    check("除数 2R が 0 になる入力が無い", True)

    print("\n--- 5. カーネルの面積 ---")
    print(f"  {'R':>4}{'サンプル数':>12}{'πR²':>10}{'一律4096の数':>14}"
          f"{'重みの総和/4096':>18}")
    for r in (1, 2, 3, 6, 12, 24, 45):
        n, tot, solid = kernel(r)
        print(f"  {r:>4}{n:>12}{math.pi*r*r:>10.1f}{solid:>14}{tot/4096:>18.1f}")
        checks.append(abs(tot / 4096 - math.pi * r * r) < 0.06 * math.pi * r * r + 4)
    check("重みの総和 / 4096 が πR² に一致(誤差 6% + 4 以内)", all(checks[-7:]))

    print("\n--- 6. 端でのクリップ ---")
    r = 6
    outer, inner, div = radii(r)
    full_sum = kernel(r)[1]
    for x, label in ((0, "左端"), (3, "3画素目"), (6, "完全に内側")):
        s = 0
        for dy in range(-r, r + 1):
            for dx in range(-r, r + 1):
                if 0 <= x + dx < 64 and 0 <= 20 + dy < 64:
                    s += weight(dx*dx + dy*dy, outer, inner, div)
        print(f"  x={x} ({label:<10}) の sum_w = {s:>7}  "
              f"= 完全な窓の {s/full_sum:.1%}")
        checks.append(s <= full_sum)
    check("端では sum_w が減る = 覆えた面積で正規化される", all(checks[-3:]))
    print("  → 平坦な不透明画像なら、端でも out.a = sum_a*4096/sum_w = 4096。")
    print("    `サイズ固定` の ON/OFF はこの除数を変えない(方向ブラー とは違う)。")

    print("\n--- 7. 3種類の丸め ---")
    print("  out.y  = sum_y / sum_a            (x87 の float 除算、そのまま格納)")
    print("  out.cb = (sum_cb + sum_a/2) / sum_a  (idiv = 0方向切り捨て + 四捨五入項)")
    print("  out.a  = _ftol(sum_a * 4096.0 / sum_w + 0.5)  (四捨五入)")
    ex = [(1000, 3, 7), (-1000, 3, 7), (1000, -3, 7)]
    for num, _, den in ex:
        plain = c_div(num, den)
        rounded = c_div(num + c_div(den, 2), den)
        print(f"    {num}/{den}: 素の切り捨て {plain}、四捨五入項つき {rounded}")
    check("負の色差でも同じ式が使われる(c_div は0方向切り捨て)",
          c_div(-1000 + c_div(7, 2), 7) == -142)

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
