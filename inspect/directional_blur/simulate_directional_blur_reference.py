"""`方向ブラー` の整数忠実リファレンス実装。

出力:

  §1  32x32 のスプライトをオブジェクト版に通して、アルファを ASCII で描く
  §2  **`サイズ固定` の ON/OFF は端の除数を変える** ―― OFF はカーネル幅
      `2N+1` で割り(枠外を透明として数える)、ON は枠内に落ちたサンプルの
      本数で割る([`box_blur.md` §3](../common/box_blur.md) の1つ目と2つ目)。
      平坦な不透明領域の端で、OFF だけがフェードすることを見る
  §3  `角度` と `角度+180` が完全に同じ絵になること
  §4  スレッド数 1〜32 で結果が一致すること
  §5  フレーム版(6バイト/画素)。除数は**生存サンプル数**で、
      カウンタが 0 のときは**書き込みそのものをしない**(古い内容が残る)
  §6  `範囲 > 128` で1画素あたり1サンプルを割り込むこと ―― 縞の出方

Run via main.py:
    uv run main.py inspect/directional_blur/simulate_directional_blur_reference.py
"""

import math

from tools.cints import c_div

FULL = 0x1000


def q16(angle_raw: int):
    th = angle_raw * (math.pi / 1800.0)
    return (math.trunc(math.sin(th) * -65536.0),
            math.trunc(math.cos(th) * 65536.0))


def schedule(rng: int, vx: int, vy: int, low_quality: bool = False):
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


def worker_object(src, w, h, vx, vy, n, x0, y0, x1, y1,
                  size_fixed: bool, tid=0, nthread=1):
    """0x1000c4a0(size_fixed=False)/ 0x1000c720(True)。

    差は最後の1行 ―― アルファを 2N+1 で割るか、枠内サンプルの本数で割るか。
    """
    kw = 2 * n + 1
    height = y1 - y0
    lo = y0 + c_div(height * tid, nthread)
    hi = y0 + c_div(height * (tid + 1), nthread)
    out = {}
    for y in range(lo, hi):
        for x in range(x0, x1):
            px = (x << 16) - n * vx + 0x8000
            py = (y << 16) - n * vy + 0x8000
            sy = scb = scr = sa = 0
            live = 0
            for _ in range(kw):
                sx, syy = px >> 16, py >> 16          # sar = floor
                px += vx
                py += vy
                if not (0 <= sx < w and 0 <= syy < h):
                    continue
                live += 1                              # ON 版だけが使う
                yy, cb, cr, a = src[syy][sx]
                if a == 0:
                    continue
                if a >= FULL:
                    sy += yy
                    scb += cb
                    scr += cr
                else:
                    sy += (yy * a) >> 12
                    scb += (cb * a) >> 12
                    scr += (cr * a) >> 12
                sa += a
            div = live if size_fixed else kw
            if div == 0:
                out[(x, y)] = (0, 0, 0, 0)
                continue
            if sa != 0:
                col = tuple(math.trunc(v * 4096.0 / sa) for v in (sy, scb, scr))
                out[(x, y)] = (col[0], col[1], col[2], c_div(sa, div))
            else:
                out[(x, y)] = (0, 0, 0, 0)
    return out


def worker_frame(src, w, h, vx, vy, n):
    """0x1000cb10。除数は生存サンプル数、0 なら書き込まない。"""
    kw = 2 * n + 1
    out = [list(row) for row in src]
    for y in range(h):
        for x in range(w):
            px = (x << 16) - n * vx + 0x8000
            py = (y << 16) - n * vy + 0x8000
            acc = [0, 0, 0]
            live = 0
            for _ in range(kw):
                sx, syy = px >> 16, py >> 16
                px += vx
                py += vy
                if not (0 <= sx < w and 0 <= syy < h):
                    continue
                live += 1
                for i in range(3):
                    acc[i] += src[syy][sx][i]
            if live:
                out[y][x] = tuple(c_div(v, live) for v in acc)
    return out


RAMP = " .:-=+*#%@"


def draw(px, x0, y0, x1, y1, label):
    print(f"  {label}  ({x1 - x0}x{y1 - y0}, 左上 ({x0},{y0}))")
    for y in range(y0, y1):
        row = "".join(RAMP[min(px.get((x, y), (0, 0, 0, 0))[3] * (len(RAMP) - 1) // FULL,
                               len(RAMP) - 1)] for x in range(x0, x1))
        print(f"    |{row}|")


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    w = h = 32
    src = [[(4096, -600, 1200, FULL) if (12 <= x < 20 and 12 <= y < 20)
            else (0, 0, 0, 0) for x in range(w)] for y in range(h)]

    print("--- 1. オブジェクト版 (32x32, 範囲=6, 角度=450 = 45.0度) ---")
    rng, deg = 6, 450
    vx, vy, n = schedule(rng, *q16(deg))
    print(f"  v = ({vx}, {vy})  N = {n}  カーネル幅 = {2*n+1}  "
          f"支持長 = {2*rng+1} 画素")
    x0, y0, x1, y1 = -rng, -rng, w + rng, h + rng
    px = worker_object(src, w, h, vx, vy, n, x0, y0, x1, y1, size_fixed=False)
    draw(px, 6, 6, 28, 28, "出力アルファ(中央 22x22 だけ表示)")
    check("アルファは 4096 を超えない",
          max(v[3] for v in px.values()) <= FULL)
    # v = (-sin45, +cos45)·65536 = 左下向き。窓は対称なので伸びるのは
    # 「左下 ⇔ 右上」の対角線方向で、「左上 ⇔ 右下」には伸びない。
    check("45.0度は 左下⇔右上 の対角線方向に伸びる",
          px[(10, 21)][3] > 0 and px[(21, 21)][3] == 0,
          f"(10,21)={px[(10, 21)][3]} (21,21)={px[(21, 21)][3]}")

    print("\n--- 2. サイズ固定 の ON / OFF ―― 端の除数 ---")
    flat = [[(3000, 0, 0, FULL)] * w for _ in range(h)]
    voff, vony, nn = schedule(10, *q16(900))       # 角度 90.0 = 真横
    a_off = worker_object(flat, w, h, voff, vony, nn, 0, 0, w, h, size_fixed=False)
    a_on = worker_object(flat, w, h, voff, vony, nn, 0, 0, w, h, size_fixed=True)
    print("  平坦な不透明画像(32x32、全部 a=4096)を 範囲=10・角度=90.0 で:")
    print("    x =        " + "".join(f"{x:>6}" for x in range(0, 13, 2)))
    print("    OFF の a   " + "".join(f"{a_off[(x, 16)][3]:>6}" for x in range(0, 13, 2)))
    print("    ON  の a   " + "".join(f"{a_on[(x, 16)][3]:>6}" for x in range(0, 13, 2)))
    edge = [a_off[(x, 16)][3] for x in range(11)]
    check("OFF は端に向かって単調にアルファが落ちる(枠外を透明として数える)",
          edge == sorted(edge) and edge[0] < FULL * 0.6 and edge[-1] == FULL,
          f"x=0 で {edge[0]} = 窓の約 {edge[0]/FULL:.0%}")
    check("ON は端でもアルファが 4096 のまま(生存サンプル数で割り直す)",
          all(a_on[(x, 16)][3] == FULL for x in range(w)))
    check("中央では両者が一致",
          a_off[(16, 16)] == a_on[(16, 16)] == (3000, 0, 0, FULL))

    print("\n--- 3. 角度 と 角度+180 ---")
    same = True
    for deg in (0, 231, 450, 900, 1234):
        p = schedule(9, *q16(deg))
        q = schedule(9, *q16(deg + 1800))
        a = worker_object(src, w, h, *p, 0, 0, w, h, size_fixed=True)
        b = worker_object(src, w, h, *q, 0, 0, w, h, size_fixed=True)
        if a != b:
            same = False
    check("5つの角度で出力が完全一致", same)

    print("\n--- 4. スレッド分割 ---")
    base = worker_object(src, w, h, vx, vy, n, x0, y0, x1, y1, size_fixed=False)
    ok = True
    for nthread in (1, 2, 3, 5, 8, 16, 32):
        acc = {}
        for tid in range(nthread):
            acc.update(worker_object(src, w, h, vx, vy, n, x0, y0, x1, y1,
                                     False, tid, nthread))
        if acc != base:
            ok = False
    check("1〜32 スレッドで出力が完全一致", ok)

    print("\n--- 5. フレーム版 ---")
    fw = fh = 12
    fsrc = [[(4096, 0, 0) if (4 <= x < 8 and 4 <= y < 8) else (0, 0, 0)
             for x in range(fw)] for y in range(fh)]
    fvx, fvy, fn = schedule(3, *q16(900))
    fout = worker_frame(fsrc, fw, fh, fvx, fvy, fn)
    print("  範囲=3・角度=90.0(真横)、輝度:")
    for row in fout:
        print("    " + " ".join(f"{p[0]:>4}" for p in row))
    check("横方向にだけ広がる",
          fout[6][2][0] > 0 and fout[2][6][0] == 0)
    check("生存サンプル数で割るので、端でも平均が薄まらない",
          worker_frame([[(4096, 0, 0)] * fw for _ in range(fh)],
                       fw, fh, fvx, fvy, fn)[6][0][0] == 4096)

    print("\n--- 6. 範囲 > 128 の粗さ ---")
    print(f"  {'範囲':>6}{'N':>6}{'歩幅[px]':>11}{'サンプル間隔':>14}")
    for rng in (100, 128, 200, 300, 500):
        a, b, nn2 = schedule(rng, *q16(900))
        step = math.hypot(a, b) / 65536
        print(f"  {rng:>6}{nn2:>6}{step:>11.3f}{'1画素以下' if step <= 1 else f'{step:.2f} 画素とび':>14}")
        checks.append((step <= 1.0) == (rng <= 128))
    check("128 を境に歩幅が1画素を超える", all(checks[-5:]))
    print("  → 範囲 が 128 を超えると、元画像の画素を飛ばしながらサンプルする。")
    print("    128 サンプルの櫛が見えるかどうかは元画像次第。")

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
