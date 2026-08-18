"""`間隔` が決めるのは重み ―― 指数移動平均の減衰係数。

`func_proc` は `n = 間隔 × 分解能` から Q12 の係数を1つだけ作る
(0x1006be44-0x1006be70):

    A = trunc(4096 - 4096 / (1 + n·(1/3.14)))
      = trunc(4096 · n / (n + 3.14))

ワーカーはこれを蓄積バッファの重みに、`B = 4096 - A` を新しいサンプルの
重みに使う。つまり**サブフレームごとの指数移動平均**である。

6つの主張:

  1. **定数 `0x1009a748` は `1/3.14`**(π の2桁近似の逆数)。
     `A/4096 = n/(n + 3.14)` と読み替えられる。

  2. **A は `間隔 = 0` で 0、`間隔` を上げると 4096 に漸近する。**
     `間隔 = 0` なら `A = 0` = 蓄積を毎回捨てる = 何もしないのと同じ。

  3. **指数移動平均の時定数(サブフレーム単位)は `1 + n/3.14`**、
     フレーム単位では `1/分解能 + 間隔/3.14`。つまり
     **尻尾の長さはおよそ `間隔/3.14` フレーム**で、`分解能` はそこへ
     `1/分解能` フレームしか足さない ―― `分解能` は尻尾の長さではなく
     **なめらかさ**のパラメータである。

  4. **`分解能` は A にも入る**(`n = 間隔 × 分解能`)。サブフレームの数が
     増えるぶん1回あたりの減衰を弱める、という辻褄合わせで、
     おかげで尻尾の長さが `分解能` にほとんど依存しない。

  5. **オブジェクトの端では A が縮む。** 開始からの経過フレーム
     (`fpip->frame`)と終了までの残り(`fp+0x11C - fpip+0xA8`)のどちらかが
     `間隔` より小さいと、その値で `n` を作り直した小さいほうを使う。
     **尻尾がオブジェクトの外へはみ出さない。**

  6. **`出力時に分解能を上げる` は `分解能` を 100 に上書きする** ――
     `n = 間隔 × 分解能` も 10 倍になるので `A` は大きくなるが、
     時定数をフレーム単位に直すと `1/分解能 + 間隔/3.14` の第1項が
     縮むだけで、**尻尾の長さはほぼ変わらない**。変わるのは
     サンプルの細かさ = なめらかさのほうである。

Run via main.py:
    uv run main.py inspect/motion_blur/verify_weight.py
"""

import math

from tools.pe_image import PEImage

INV_314 = 0x1009A748
ONE = 0x1009A428
Q12 = 0x1009A3A0
FULL = 0x1000


def weight(n: int, inv: float) -> int:
    """0x1006be4d-0x1006be69。_ftol は0方向切り捨て。"""
    return math.trunc(4096.0 - 4096.0 / (1.0 + n * inv))


def coefficient(interval: int, resolution: int, frame: int, remain: int, inv: float):
    """func_proc 0x1006be44-0x1006bf10 の全体。"""
    n = interval * resolution
    a = weight(n, inv)
    for other in (frame * resolution, remain * resolution):
        if other < n:
            t = weight(other, inv)
            if a > t:
                a = t
    return max(a, 0)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)
    inv = img.f64(INV_314)

    print("--- 1. 定数 ---")
    print(f"  0x{INV_314:08x} = {inv!r}   1/x = {1 / inv!r}")
    check("1/3.14 ちょうど", abs(1 / inv - 3.14) < 1e-12)
    check("π そのものではない(3.14 の2桁近似)", abs(1 / inv - math.pi) > 1e-4)
    print(f"  0x{ONE:08x} = {img.f64(ONE)!r}   0x{Q12:08x} = {img.f64(Q12)!r}")
    check("1.0 と 4096.0", img.f64(ONE) == 1.0 and img.f64(Q12) == 4096.0)

    print("\n--- 2. A の値(オブジェクトの中ほど、端のクランプが効かない場合) ---")
    print(f"  {'間隔':>6}{'分解能':>8}{'n':>7}{'A':>7}{'A/4096':>9}"
          f"{'B = 4096-A':>12}")
    for interval, res in ((0, 10), (1, 10), (2, 10), (5, 10), (10, 10),
                          (30, 10), (100, 10), (1, 25), (1, 100)):
        n = interval * res
        a = weight(n, inv)
        print(f"  {interval:>6}{res:>8}{n:>7}{a:>7}{a / 4096:>9.4f}{4096 - a:>12}")
    check("間隔 = 0 なら A = 0(何もしない)", weight(0, inv) == 0)
    check("間隔 を上げると 4096 に漸近する(超えない)",
          all(weight(i * 10, inv) < 4096 for i in range(0, 101))
          and weight(100 * 10, inv) > 4080)
    check("A は 間隔 について単調増加",
          all(weight(i * 10, inv) <= weight((i + 1) * 10, inv) for i in range(100)))
    check("A/4096 = n/(n + 3.14) と一致(誤差 1/4096 以内)",
          all(abs(weight(n, inv) / 4096 - n / (n + 3.14)) < 1 / 4096
              for n in range(0, 2501)))

    print("\n--- 3./4. 尻尾の長さ ---")
    print("  指数移動平均の時定数 τ = 1/(1 - A/4096) [サブフレーム]")
    print(f"  {'間隔':>6}{'分解能':>8}{'τ[サブフレーム]':>18}{'τ[フレーム]':>14}"
          f"{'間隔/3.14':>12}")
    for interval, res in ((1, 5), (1, 10), (1, 25), (5, 10), (10, 10),
                          (30, 10), (100, 10)):
        a = weight(interval * res, inv)
        tau = 4096 / (4096 - a)
        print(f"  {interval:>6}{res:>8}{tau:>18.2f}{tau / res:>14.3f}"
              f"{interval / 3.14:>12.3f}")
        want = 1 / res + interval / 3.14
        checks.append(abs(tau / res - want) < 0.02 * want + 0.001)
    check("τ[フレーム] = 1/分解能 + 間隔/3.14 と一致(A の量子化ぶん 2% 以内)",
          all(checks[-7:]))
    print("  → 尻尾の長さは 分解能 にほとんど依存しない。1/分解能 フレームぶん")
    print("    しか変わらないので、分解能 は「なめらかさ」だけを決める。")

    print("\n--- 5. オブジェクトの端でのクランプ ---")
    interval, res = 10, 10
    print(f"  間隔={interval}, 分解能={res}(中ほどの A = "
          f"{coefficient(interval, res, 999, 999, inv)}):")
    print(f"  {'経過フレーム':>14}{'残りフレーム':>14}{'A':>7}{'τ[フレーム]':>14}")
    for frame, remain in ((0, 999), (1, 999), (3, 999), (10, 999), (999, 999),
                          (999, 3), (999, 0)):
        a = coefficient(interval, res, frame, remain, inv)
        tau = 4096 / (4096 - a) / res if a < 4096 else float("inf")
        print(f"  {frame:>14}{remain:>14}{a:>7}{tau:>14.3f}")
    check("開始直後は A が小さい(尻尾が過去へはみ出さない)",
          coefficient(interval, res, 0, 999, inv) == 0
          and coefficient(interval, res, 3, 999, inv)
          < coefficient(interval, res, 999, 999, inv))
    check("終了直前も同じように縮む",
          coefficient(interval, res, 999, 0, inv) == 0)
    check("経過・残りが 間隔 以上なら中ほどと同じ",
          coefficient(interval, res, interval, interval, inv)
          == coefficient(interval, res, 999, 999, inv))

    print("\n--- 6. 出力時に分解能を上げる ---")
    print(f"  {'間隔':>6}{'プレビュー(分解能=10)':>26}{'出力(分解能=100)':>22}")
    for interval in (1, 3, 10, 30):
        a10 = weight(interval * 10, inv)
        a100 = weight(interval * 100, inv)
        t10 = 4096 / (4096 - a10) / 10
        t100 = 4096 / (4096 - a100) / 100
        print(f"  {interval:>6}{f'A={a10} τ={t10:.3f}f':>26}"
              f"{f'A={a100} τ={t100:.3f}f':>22}")
        checks.append(a100 > a10)
    check("出力側のほうが A が大きい", all(checks[-4:]))
    print("  τ の差は 1/10 - 1/100 = 0.09 フレームなので尻尾の長さはほぼ同じだが、")
    print("  サンプルが 10 倍細かくなるぶん、なめらかさは上がる。")

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
