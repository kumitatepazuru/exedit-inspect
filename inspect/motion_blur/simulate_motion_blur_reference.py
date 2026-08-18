"""`モーションブラー` の整数忠実リファレンス実装。

「その時刻でオブジェクトを描き直す」部分は exedit のコア側(`0x1004b200` /
`0x1004ccf0`)なので再実装できない。代わりに **「時刻 t を渡すと画像を返す
関数」を外から与えて**、ワーカー3本と `func_proc` のループだけを厳密に
再現する。

出力:

  §1  ワーカーの式 ―― `新 = (A·蓄積 + B·入力)` をアルファ加重のまま
  §2  `残像` OFF: 動く四角を通したときのブレを ASCII で描く
  §3  `残像` ON: 同じ入力で、現在の姿が**そのまま残り尻尾だけが後ろに付く**
      こと(`0x1000ad80` = 合成モード表 0x12 番の「下に置く」合成)
  §4  蓄積がフレームをまたいで効くこと ―― 1フレームだけ光らせた点が
      何フレームか尾を引くこと、その長さが `間隔/3.14` フレームに乗ること
  §5  フレーム版(6バイト/画素)は `+0x800` の四捨五入項を持つこと
  §6  スレッド数 1〜32 で結果が一致すること

Run via main.py:
    uv run main.py inspect/motion_blur/simulate_motion_blur_reference.py
"""

import math

from tools.cints import c_div

FULL = 0x1000
INV_314 = 1.0 / 3.14


def weight(n: int) -> int:
    return math.trunc(4096.0 - 4096.0 / (1.0 + n * INV_314))


def coefficient(interval, resolution, frame, remain, reused=True):
    n = interval * resolution
    a = weight(n)
    for other in (frame * resolution, remain * resolution):
        if other < n:
            t = weight(other)
            if a > t:
                a = t
    if not reused or a < 0:
        a = 0
    return a


# --------------------------------------------------------------------------
# ワーカー
# --------------------------------------------------------------------------

def blend_pixel(acc, src, a_w, b_w):
    """0x1006c384-0x1006c48c。戻り値 (y, cb, cr, a)。"""
    sy = scb = scr = sa = 0
    y, cb, cr, a = acc
    if a != 0:
        if a >= FULL:
            sy, scb, scr = y * a_w, cb * a_w, cr * a_w
        else:
            sy = ((y * a) >> 12) * a_w
            scb = ((cb * a) >> 12) * a_w
            scr = ((cr * a) >> 12) * a_w
        sa = (a * a_w) >> 12
    y, cb, cr, a = src
    if a != 0:
        if a >= FULL:
            sy += y * b_w
            scb += cb * b_w
            scr += cr * b_w
        else:
            sy += ((y * a) >> 12) * b_w
            scb += ((cb * a) >> 12) * b_w
            scr += ((cr * a) >> 12) * b_w
        sa += (a * b_w) >> 12
    if sa:
        return (c_div(sy, sa), c_div(scb, sa), c_div(scr, sa), sa)
    return (0, 0, 0, 0)


def composite_under(dst, px):
    """0x1000ad80 = ブレンド関数表 0x12 番。px を dst の **下** に置く。"""
    y, cb, cr, a = px
    dy, dcb, dcr, da = dst
    if da <= 0:
        return (y, cb, cr, a)
    if da >= FULL:
        return dst
    if a >= FULL:
        return (y + ((dy - y) * da >> 12),
                cb + ((dcb - cb) * da >> 12),
                cr + ((dcr - cr) * da >> 12),
                FULL)
    out_a = (0x1000800 - (FULL - da) * (FULL - a)) >> 12
    x = c_div(da << 12, out_a)
    yb = c_div((FULL - da) * a, out_a)
    return ((dy * x + y * yb) >> 12,
            (dcb * x + cb * yb) >> 12,
            (dcr * x + cr * yb) >> 12,
            out_a)


def worker_object(acc, src, dst, w, h, a_w, afterimage, tid=0, nthread=1):
    """0x1006c2e0(afterimage=False)/ 0x1006c0d0(True)。acc/dst は破壊的に更新。"""
    b_w = FULL - a_w
    lo = c_div(h * tid, nthread)
    hi = c_div(h * (tid + 1), nthread)
    for y in range(lo, hi):
        for x in range(w):
            mixed = blend_pixel(acc[y][x], src[y][x], a_w, b_w)
            acc[y][x] = mixed
            dst[y][x] = composite_under(dst[y][x], mixed) if afterimage else mixed


def worker_frame(acc, src, dst, w, h, a_w):
    """0x1006c500。6バイト/画素、+0x800 の四捨五入項つき。"""
    b_w = FULL - a_w
    for y in range(h):
        for x in range(w):
            m = tuple((src[y][x][i] * b_w + acc[y][x][i] * a_w + 0x800) >> 12
                      for i in range(3))
            acc[y][x] = m
            dst[y][x] = m


# --------------------------------------------------------------------------
# func_proc のループ
# --------------------------------------------------------------------------

def run_frame(render, acc, w, h, interval, resolution, frame, remain,
              afterimage, reused=True, nthread=1):
    """1フレーム分。render(t) が「相対時刻 t の画像」を返す。"""
    a_w = coefficient(interval, resolution, frame, remain, reused)
    dst = None
    for i in range(resolution):
        t = 0.0 if (i == 0 or a_w == 0) else -1.0 + c_div(i * 100, resolution) / 100.0
        src = render(t)
        if dst is None or not afterimage:
            dst = [list(row) for row in src]
        else:
            dst = [list(row) for row in src]     # 描き直しが dst を上書きする
        for tid in range(nthread):
            worker_object(acc, src, dst, w, h, a_w, afterimage, tid, nthread)
    return dst, a_w


RAMP = " .:-=+*#%@"


def draw(img, key, label, scale=FULL):
    print(f"  {label}")
    for row in img:
        print("    |" + "".join(
            RAMP[max(0, min(len(RAMP) - 1, key(p) * (len(RAMP) - 1) // scale))]
            for p in row) + "|")


def moving_square(w, h, speed):
    """相対時刻 t で x が speed·t だけ動く 4x4 の四角。"""
    def render(t):
        cx = 4 + speed * (t + 1.0)
        img = [[(0, 0, 0, 0)] * w for _ in range(h)]
        for y in range(h):
            for x in range(w):
                if abs(x - cx) < 2 and abs(y - h // 2) < 2:
                    img[y][x] = (4096, 0, 0, FULL)
        return img
    return render


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. ワーカーの式 ---")
    a_w = coefficient(1, 10, 999, 999)
    print(f"  間隔=1, 分解能=10 -> A = {a_w}, B = {FULL - a_w}")
    acc = (4096, 0, 0, FULL)
    src = (0, 0, 0, 0)
    print(f"  不透明な白 + 完全な透明: {blend_pixel(acc, src, a_w, FULL - a_w)}")
    print(f"  完全な透明 + 不透明な白: "
          f"{blend_pixel(src, acc, a_w, FULL - a_w)}")
    check("透明な入力は蓄積のアルファを A/4096 倍に落とす",
          blend_pixel(acc, src, a_w, FULL - a_w)[3] == (FULL * a_w) >> 12)
    check("色はアルファで割り戻されるので保たれる",
          blend_pixel(acc, src, a_w, FULL - a_w)[0] == 4096)
    both = blend_pixel((4096, 0, 0, FULL), (0, 0, 0, FULL), a_w, FULL - a_w)
    print(f"  不透明な白 + 不透明な黒: {both}")
    check("不透明どうしなら重み付き平均になる",
          both[3] == FULL and abs(both[0] - 4096 * a_w // 4096) < 2)

    print("\n--- 2. 残像 OFF ―― 動く四角 ---")
    w, h = 24, 9
    render = moving_square(w, h, 8)
    acc = [[(0, 0, 0, 0)] * w for _ in range(h)]
    out = None
    for f in range(3):                      # 3フレーム回して蓄積を育てる
        out, a_w = run_frame(render, acc, w, h, 2, 10, 99, 99, afterimage=False)
    draw(out, lambda p: p[3], f"アルファ(間隔=2, 分解能=10, A={a_w})")
    peak = max(p[3] for row in out for p in row)
    print(f"  アルファの最大値: {peak} / 4096")
    check("進行方向の後ろに尾を引く",
          out[4][8][3] > 0 and out[4][8][3] < out[4][11][3])
    check("残像 OFF では四角自身もにじむので、完全に不透明な画素が残らない",
          peak < FULL, f"最大 {peak}")

    print("\n--- 3. 残像 ON ―― 現在の姿が残る ---")
    acc2 = [[(0, 0, 0, 0)] * w for _ in range(h)]
    out2 = None
    for f in range(3):
        out2, _ = run_frame(render, acc2, w, h, 2, 10, 99, 99, afterimage=True)
    draw(out2, lambda p: p[3], "アルファ(残像 ON)")
    check("尾の部分は OFF 版と同じかそれより濃い",
          all(out2[y][x][3] >= out[y][x][3] - 1
              for y in range(h) for x in range(w)))
    check("現在の四角は完全に不透明のまま",
          out2[4][12][3] == FULL and out2[4][13][3] == FULL)
    print("  → 0x1000ad80 は「引数を転送先の下に置く」ので、最後に描き直した")
    print("    現在の姿がそのまま前面に残り、蓄積は背後にだけ見える。")

    print("\n--- 4. 蓄積はフレームをまたぐ ---")
    w2, h2 = 1, 1
    lit = [[(4096, 0, 0, FULL)]]
    dark = [[(0, 0, 0, 0)]]
    for interval in (1, 5, 20):
        acc3 = [[(0, 0, 0, 0)]]
        a_w = coefficient(interval, 10, 999, 999)
        seq = []
        for f in range(14):
            src_img = lit if f == 0 else dark
            dst = [[(0, 0, 0, 0)]]
            for i in range(10):
                worker_object(acc3, src_img, dst, w2, h2, a_w, False)
            seq.append(dst[0][0][3])
        tau = 4096 / (4096 - a_w) / 10
        half = next((i for i, v in enumerate(seq) if v < seq[0] // 2), None)
        print(f"  間隔={interval:>3} (A={a_w}, τ={tau:.2f} フレーム): "
              + " ".join(f"{v:>4}" for v in seq[:10]))
        print(f"      アルファが半分になるフレーム: {half}"
              f"   (τ·ln2 = {tau * math.log(2):.2f})")
        checks.append(half is None or abs(half - tau * math.log(2)) <= 1.5)
    check("減衰の半減期が τ·ln2 に乗る(間隔が小さいうち)", all(checks[-3:]))

    print("  ところが 間隔 を上げると、切り捨てのせいで実測はもっと早く消える:")
    for interval in (50, 100):
        acc3 = [[(0, 0, 0, 0)]]
        a_w = coefficient(interval, 10, 999, 999)
        seq = []
        for f in range(40):
            src_img = lit if f == 0 else dark
            dst = [[(0, 0, 0, 0)]]
            for i in range(10):
                worker_object(acc3, src_img, dst, w2, h2, a_w, False)
            seq.append(dst[0][0][3])
        tau = 4096 / (4096 - a_w) / 10
        half = next((i for i, v in enumerate(seq) if v < seq[0] // 2), None)
        gone = next((i for i, v in enumerate(seq) if v == 0), None)
        print(f"  間隔={interval:>3} (A={a_w}, τ={tau:.1f}f, τ·ln2={tau*math.log(2):.1f}f): "
              f"半減 {half}f / 消滅 {gone}f  先頭 {seq[:6]}")
        checks.append(half is not None and half < tau * math.log(2))
    check("(x·A)>>12 の切り捨てが指数減衰より速く効く", all(checks[-2:]))
    print("  → アルファが小さいところでは 1 サブサンプルにつき最大 1 ずつ")
    print("    余計に減るので、尻尾の末端は指数ではなく線形に消える。")

    print("\n--- 5. フレーム版の四捨五入 ---")
    accf = [[(1000, 0, 0)]]
    dstf = [[(0, 0, 0)]]
    srcf = [[(2000, 0, 0)]]
    worker_frame(accf, srcf, dstf, 1, 1, 2048)
    exact = (2000 * 2048 + 1000 * 2048) / 4096
    print(f"  A=2048、蓄積 1000 + 入力 2000 -> {dstf[0][0][0]}(厳密 {exact})")
    check("+0x800 で四捨五入される(オブジェクト版には無い)",
          dstf[0][0][0] == 1500)
    accf2 = [[(1001, 0, 0)]]
    dstf2 = [[(0, 0, 0)]]
    worker_frame(accf2, srcf, dstf2, 1, 1, 2048)
    print(f"  蓄積 1001 + 入力 2000 -> {dstf2[0][0][0]}"
          f"(厳密 {(2000*2048 + 1001*2048)/4096})")
    check("端数 0.5 は上へ", dstf2[0][0][0] == 1501)

    print("\n--- 6. スレッド分割 ---")
    ok = True
    for nthread in (1, 2, 3, 5, 8, 16, 32):
        acc4 = [[(0, 0, 0, 0)] * w for _ in range(h)]
        out4 = None
        for f in range(3):
            out4, _ = run_frame(render, acc4, w, h, 2, 10, 99, 99,
                                afterimage=False, nthread=nthread)
        if out4 != out:
            ok = False
    check("1〜32 スレッドで出力が完全一致", ok)

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
