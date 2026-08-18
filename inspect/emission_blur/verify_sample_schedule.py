"""`範囲` が決めているのは「どこまで走るか」と「何回サンプルするか」の両方。

ワーカーは出力画素ごとに、**中心へ向かう線分を等間隔にサンプルして平均する**。
その線分の長さとサンプル数は次のように決まる(`disasm_params.py` §2):

    d8 = trunc(8·√(dx² + dy²))            // 中心までの距離、1/8 画素単位
    n  = trunc(範囲 · d8 / 1000)          // ひとまずのサンプル数
    d8 > R'  ->  n = R'·n/d8 ;  d = R'                    // 遠い画素
    d8 <= R' ->  d = d8·m ; n = n·m   (m = 8/4/2/1)       // 近い画素
    歩幅 = (dx << 16)/d, (dy << 16)/d   を n 回

6つの主張:

  1. **`R'` は `func_proc` が1回だけ作る「サンプル数の基準」**で、
     `R' = trunc((1000-範囲)·R/1000) + c_div(R, 2)`。
     `R` は中心から画像の4辺までの距離の最大値(対角線でクランプ、
     `fpip->flag & 0x200` なら 50 でクランプ)。

  2. **どの枝を通っても、走る距離は「中心までの距離 × 範囲/1000」**。
     `範囲` の生値 750(オブジェクト版の上限)なら中心までの 75%、
     フレーム版の 1000 なら 100%。表示スケール 10 なので UI の
     `75.0` / `100.0` がそのまま「中心までの何%か」になる。

  3. **遠い画素ではサンプル数が `範囲·R'/1000` で頭打ちになる。**
     距離に比例して増え続けないので、大きなオブジェクトでも計算量が
     `O(w·h·R')` で止まる。代わりに歩幅が 1 画素より粗くなる。

  4. **サンプル数は `範囲` に対して単調増加ではない。** `R'` が `範囲` と
     ともに減るので、上限のサンプル数 `範囲·R'/1000` は
     `範囲 = 750` でちょうど最大になる ―― **オブジェクト版のスライダー上限
     750 は、この山の頂点そのもの**である。

  5. **近い画素では逆に 8/4/2 倍まで密にサンプルする。** `d8 <= 8`
     (中心から 1 画素以内)だけが等倍で、そこから外は最大 64 サンプル/画素。
     中心付近が縞にならないための措置と読める。

  6. **`d < 2` または `n < 2` なら平均せず素通し**(枠内ならコピー、
     枠外なら完全に透明)。中心のごく近傍がぼけないのはこれ。

Run via main.py:
    uv run main.py inspect/emission_blur/verify_sample_schedule.py
"""

import math

from tools.cints import MAGIC_1000, c_div, divisor_of, msvc_div
from tools.pe_image import PEImage

# func_proc / worker がマジック除算に使う定数(0x1000b418 / 0x1000b76a)
MAGIC_VA_PROC = 0x1000B419
MAGIC_VA_WORKER = 0x1000B76B
EIGHT = 0x1009A400


def reference_R(w: int, h: int, cx: int, cy: int, low_quality: bool = False) -> int:
    """func_proc 0x1000b32e-0x1000b40c をそのまま。"""
    r = max(abs(cx), abs(cy), abs(cx - w), abs(cy - h))
    r = min(r, math.trunc(math.sqrt(w * w + h * h)))
    if low_quality:
        r = min(r, 50)
    return r


def reference_Rp(r: int, s: int) -> int:
    """R' = trunc((1000-範囲)*R/1000) + c_div(R,2)   (0x1000b40c-0x1000b443)"""
    return msvc_div((1000 - s) * r) + c_div(r, 2)


def sample_plan(dx: int, dy: int, s: int, rp: int):
    """1画素分の (d, n)。0x1000b72a-0x1000b7ce をそのまま。"""
    d8 = math.trunc(math.sqrt(dx * dx + dy * dy) * 8.0)
    n = msvc_div(s * d8)
    if d8 > rp:
        return rp, c_div(rp * n, d8), d8
    for limit, mul in ((8, 8), (4, 4), (2, 2)):
        if d8 > limit:
            return d8 * mul, n * mul, d8
    return d8, n, d8


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)

    print("--- 0. 使っている定数 ---")
    for va in (MAGIC_VA_PROC, MAGIC_VA_WORKER):
        got = img.u32(va)
        print(f"  0x{va:08x}: マジック 0x{got:08x}")
        checks.append(got == MAGIC_1000)
    check("func_proc とワーカーの両方が 0x10624dd3 を使う",
          all(img.u32(va) == MAGIC_1000 for va in (MAGIC_VA_PROC, MAGIC_VA_WORKER)))
    check("(0x10624dd3, sar 6) は本当に /1000", divisor_of(MAGIC_1000, 6) == 1000)
    check(f"距離を 8 倍する定数 0x{EIGHT:08x} は 8.0", img.f64(EIGHT) == 8.0)

    print("\n--- 1. R と R'(中心が既定 = 画像の中央のとき) ---")
    print(f"  {'w x h':>10}{'R':>7}{'対角':>7}{'範囲=200 の R‘':>16}"
          f"{'範囲=750 の R‘':>16}")
    for w, h in ((100, 100), (320, 240), (640, 480), (1920, 1080)):
        cx, cy = c_div(w, 2), c_div(h, 2)
        r = reference_R(w, h, cx, cy)
        print(f"  {f'{w}x{h}':>10}{r:>7}{math.trunc(math.sqrt(w*w+h*h)):>7}"
              f"{reference_Rp(r, 200):>16}{reference_Rp(r, 750):>16}")
    check("中心が中央なら R = max(w,h)/2 になる",
          all(reference_R(w, h, c_div(w, 2), c_div(h, 2))
              == max(c_div(w, 2), c_div(h, 2))
              for w, h in ((100, 100), (320, 240), (640, 480), (1920, 1080))))

    print("\n  中心を画面外へ飛ばすと対角線でクランプされる (640x480):")
    for x in (0, 500, 2000):
        cx, cy = 320 + x, 240
        raw = max(abs(cx), abs(cy), abs(cx - 640), abs(cy - 480))
        print(f"    X={x:>5}  クランプ前 {raw:>5}  クランプ後 "
              f"{reference_R(640, 480, cx, cy):>4}  (対角 800)")
    check("X=2000 では 2320 -> 800 に切り詰められる",
          reference_R(640, 480, 320 + 2000, 240) == 800)
    check("描画品質フラグが立つと R は 50 で頭打ち",
          reference_R(640, 480, 320, 240, low_quality=True) == 50)

    print("\n--- 2. どの枝でも走る距離は 範囲/1000 倍 ---")
    print("  640x480、中心 (320,240)、範囲=200。d は中心までの画素距離。")
    print(f"  {'d':>6}{'枝':>8}{'n':>7}{'歩幅[px]':>11}{'走行[px]':>11}"
          f"{'期待 d*0.2':>12}")
    rp = reference_Rp(reference_R(640, 480, 320, 240), 200)
    worst = 0.0
    for dist in (2, 5, 10, 30, 100, 240, 400):
        dx, dy = dist, 0
        d, n, d8 = sample_plan(dx, dy, 200, rp)
        if d < 2 or n < 2:
            branch, travel, step = "コピー", 0.0, 0.0
        else:
            branch = "遠" if d8 > rp else "近"
            step = c_div(dx << 16, d) / 65536
            travel = n * step
        want = dist * 200 / 1000
        worst = max(worst, abs(travel - want)) if branch != "コピー" else worst
        print(f"  {dist:>6}{branch:>8}{n:>7}{step:>11.4f}{travel:>11.3f}{want:>12.3f}")
    check("走行距離が d·範囲/1000 と 1 画素以内で一致する", worst < 1.0,
          f"最大ずれ {worst:.3f} px")

    print("\n  全方向・全距離での検算 (640x480, 中心中央, 範囲 = 200/500/750):")
    print("  ずれの理由は n と歩幅の切り捨てなので、上界は「1サンプル分 + 0.5 px」。")
    for s in (200, 500, 750):
        rp = reference_Rp(reference_R(640, 480, 320, 240), s)
        worst, worst_at, over = 0.0, None, 0
        for y in range(0, 480, 7):
            for x in range(0, 640, 7):
                dx, dy = 320 - x, 240 - y
                d, n, d8 = sample_plan(dx, dy, s, rp)
                if d < 2 or n < 2:
                    continue
                sx, sy = c_div(dx << 16, d), c_div(dy << 16, d)
                travel = math.hypot(n * sx, n * sy) / 65536
                step = math.hypot(sx, sy) / 65536
                want = math.hypot(dx, dy) * s / 1000
                err = abs(travel - want)
                if err > step + 0.5:
                    over += 1
                if err > worst:
                    worst, worst_at = err, (x, y)
        print(f"    範囲={s:>4}  R'={rp:>4}  最大ずれ {worst:.3f} px  at {worst_at}  "
              f"上界超え {over} 画素")
        checks.append(over == 0)
    check("3設定とも「1サンプル分 + 0.5 px」を超える画素が1つも無い", all(checks[-3:]))

    print("\n--- 3./4. サンプル数の上限は 範囲=750 で最大になる ---")
    r = reference_R(640, 480, 320, 240)
    print(f"  640x480、中心中央 → R = {r}")
    print(f"  {'範囲':>6}{'UI':>8}{'R‘':>7}{'遠方のサンプル数':>18}")
    best, best_s = -1, None
    table = []
    for s in range(1, 1001):
        rp = reference_Rp(r, s)
        # 遠方の極限。n = trunc(R'·trunc(範囲·d8/1000)/d8) -> 範囲·R'/1000
        n = c_div(rp * msvc_div(s * 100000), 100000)
        table.append((s, rp, n))
        if n > best:
            best, best_s = n, s
    for s in (100, 200, 400, 600, 750, 800, 1000):
        rp, n = next((rp, n) for ss, rp, n in table if ss == s)
        print(f"  {s:>6}{s/10:>8.1f}{rp:>7}{n:>18}")
    check("サンプル数の山の頂点はちょうど 範囲 = 750", best_s == 750,
          f"頂点は {best_s}(= UI の {best_s/10:.1f})")
    check("オブジェクト版のスライダー上限がその 750",
          [x.track_e[0] for x in __import__("tools.filter_table", fromlist=["find"])
           .find(img, "放射ブラー")] == [750, 1000])

    print("\n--- 5. 近い画素の 8/4/2 倍 ---")
    print(f"  {'距離[px]':>10}{'d8':>6}{'倍率':>6}{'サンプル数':>12}"
          f"{'歩幅[px]':>11}{'密度[/px]':>11}")
    rp = reference_Rp(r, 200)
    for dx in (1, 2, 3, 6, 20):
        dy = 0
        d8 = math.trunc(math.sqrt(dx * dx) * 8.0)
        d, n, _ = sample_plan(dx, dy, 200, rp)
        mul = d // d8 if d8 else 0
        step = c_div(dx << 16, d) / 65536 if d >= 2 else 0.0
        dens = 1 / step if step else 0.0
        print(f"  {dx:>10}{d8:>6}{mul:>6}{n:>12}{step:>11.4f}{dens:>11.1f}")
    check("d8 > 8(= 1画素超)で 8 倍、それ以下は 4/2/1 倍",
          sample_plan(2, 0, 200, rp)[0] == 16 * 8
          and sample_plan(1, 0, 200, rp)[0] == 8 * 4)

    print("\n--- 6. 素通しになる条件 ---")
    passthrough = []
    for dist in range(0, 40):
        d, n, _ = sample_plan(dist, 0, 200, rp)
        if d < 2 or n < 2:
            passthrough.append(dist)
    print(f"  範囲=200 で素通しになる中心からの距離: {passthrough} 画素")
    check("中心のごく近傍だけが素通しになる", passthrough and max(passthrough) < 10)
    for s, expect in ((750, True), (1, True)):
        d, n, _ = sample_plan(0, 0, s, rp)
        checks.append((d < 2 or n < 2) == expect)
    check("中心そのもの(距離0)はどの 範囲 でも必ず素通し", all(checks[-2:]))

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
