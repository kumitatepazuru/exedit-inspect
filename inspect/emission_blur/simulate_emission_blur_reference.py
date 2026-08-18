"""`放射ブラー` の整数忠実リファレンス実装。

`verify_*.py` で個別に確かめた式を1本にまとめ、実際に画像を通す。整数の
丸め(`sar` = floor / `idiv` = 0方向切り捨て / x87 の double 除算)は
[`integer_semantics.md`](../common/integer_semantics.md) の通りに書き分けて
ある。

出力:

  §1  8x8 のスプライトをオブジェクト版に通して、アルファをアスキーで描く
  §2  スレッド数 1〜32 で結果が完全に一致すること(分割は `thread_split.md`
      の (B) だけなので、行の重複も抜けも起きない)
  §3  `サイズ固定` の ON/OFF が、重なっている領域では**同じ画素値**を出す
      こと ―― 矩形しか変わらないという `verify_canvas_rect.py` §5 の帰結
  §4  フレーム版(6バイト/画素、アルファ無し)。中心が枠内かどうかで
      ワーカーが分かれるが、**枠内側は範囲判定を持たないだけで式は同じ**
      なので、同じ入力に対して同じ出力になること
  §5  平坦な不透明領域は素通しになること(平均しても値が変わらない)

Run via main.py:
    uv run main.py inspect/emission_blur/simulate_emission_blur_reference.py
"""

import math

from tools.cints import c_div, msvc_div

FULL = 0x1000


# --------------------------------------------------------------------------
# func_proc
# --------------------------------------------------------------------------

def params(w: int, h: int, ox: int, oy: int, s: int, low_quality: bool = False):
    """0x1000b310-0x1000b443。中心・参照半径 R・サンプル基準 R'。"""
    cx = c_div(w, 2) + ox
    cy = c_div(h, 2) + oy
    r = max(abs(cx), abs(cy), abs(cx - w), abs(cy - h))
    r = min(r, math.trunc(math.sqrt(w * w + h * h)))
    if low_quality:
        r = min(r, 50)
    rp = msvc_div((1000 - s) * r) + c_div(r, 2)
    return cx, cy, r, rp


def canvas_rect(w, h, cx, cy, s, size_fixed=False,
                max_w=4000, max_h=4000, frame_w=1280, frame_h=720):
    """0x1000b440-0x1000b5b1。"""
    if size_fixed:
        return 0, 0, w, h
    den = 1000 - s
    x0 = min(cx - c_div(cx * 1000, den), 0)
    y0 = min(cy - c_div(cy * 1000, den), 0)
    x1 = w + max(c_div((w - cx) * 1000, den) - (w - cx), 0)
    y1 = h + max(c_div((h - cy) * 1000, den) - (h - cy), 0)
    while (x1 - x0) > max_w or (x1 - x0) > frame_w + 2 * w:
        if x0 >= w - x1:
            x1 -= 1
        else:
            x0 += 1
    while (y1 - y0) > max_h or (y1 - y0) > frame_h + 2 * h:
        if y0 >= h - y1:
            y1 -= 1
        else:
            y0 += 1
    return x0, y0, x1, y1


def sample_plan(dx: int, dy: int, s: int, rp: int):
    """0x1000b72a-0x1000b7ce。戻り値 (d, n)。"""
    d8 = math.trunc(math.sqrt(dx * dx + dy * dy) * 8.0)
    n = msvc_div(s * d8)
    if d8 > rp:
        return rp, c_div(rp * n, d8)
    for limit, mul in ((8, 8), (4, 4), (2, 2)):
        if d8 > limit:
            return d8 * mul, n * mul
    return d8, n


# --------------------------------------------------------------------------
# worker
# --------------------------------------------------------------------------

def worker_object(src, w, h, cx, cy, s, rp, x0, y0, x1, y1, tid=0, nthread=1):
    """0x1000b660。src は [h][w] の (y, cb, cr, a)。戻りは辞書 {(x,y): 画素}。"""
    height = y1 - y0
    lo = y0 + c_div(height * tid, nthread)
    hi = y0 + c_div(height * (tid + 1), nthread)
    out = {}
    for y in range(lo, hi):
        for x in range(x0, x1):
            dx, dy = cx - x, cy - y
            d, n = sample_plan(dx, dy, s, rp)
            if d < 2 or n < 2:
                out[(x, y)] = src[y][x] if 0 <= x < w and 0 <= y < h else (0, 0, 0, 0)
                continue
            stepx = c_div(dx << 16, d)
            stepy = c_div(dy << 16, d)
            px, py = (x << 16) + 0x8000, (y << 16) + 0x8000
            sy_ = scb = scr = sa = 0
            for _ in range(n):
                sx, syy = px >> 16, py >> 16          # sar = floor
                px += stepx
                py += stepy
                if not (0 <= sx < w and 0 <= syy < h):
                    continue
                yy, cb, cr, a = src[syy][sx]
                if a == 0:
                    continue
                if a >= FULL:
                    sy_ += yy
                    scb += cb
                    scr += cr
                else:
                    sy_ += (yy * a) >> 12             # sar = floor
                    scb += (cb * a) >> 12
                    scr += (cr * a) >> 12
                sa += a
            if sa != 0:
                # x87 の double 除算 -> _ftol(0方向切り捨て)
                col = tuple(math.trunc(v * 4096.0 / sa) for v in (sy_, scb, scr))
                out[(x, y)] = (col[0], col[1], col[2], c_div(sa, n))
            else:
                # 色は書かれない。ここでは「前の内容 = 透明な黒」とする
                out[(x, y)] = (0, 0, 0, 0)
    return out


def worker_frame(src, w, h, cx, cy, s, rp, clip: bool):
    """0x1000bb90(clip=False)/ 0x1000be30(clip=True)。6バイト/画素。"""
    out = [[(0, 0, 0)] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            dx, dy = cx - x, cy - y
            d, n = sample_plan(dx, dy, s, rp)
            if d < 2 or n < 2:
                out[y][x] = src[y][x]
                continue
            stepx = c_div(dx << 16, d)
            stepy = c_div(dy << 16, d)
            px, py = (x << 16) + 0x8000, (y << 16) + 0x8000
            acc = [0, 0, 0]
            for _ in range(n):
                sx, syy = px >> 16, py >> 16
                px += stepx
                py += stepy
                if clip and not (0 <= sx < w and 0 <= syy < h):
                    continue
                p = src[syy][sx]
                for i in range(3):
                    acc[i] += p[i]
            out[y][x] = tuple(c_div(v, n) for v in acc)   # idiv
    return out


# --------------------------------------------------------------------------

def make_sprite(w, h):
    """中央から外れた位置に不透明な明るい四角、周囲は透明。

    中央に置くと放射状の伸びが出ないので、わざと偏らせてある。
    """
    img = [[(0, 0, 0, 0)] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            if w * 5 // 8 <= x < w * 7 // 8 and h * 5 // 8 <= y < h * 7 // 8:
                img[y][x] = (4096, -600, 1200, FULL)
    return img


RAMP = " .:-=+*#%@"


def draw_alpha(px, x0, y0, x1, y1, label):
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
    src = make_sprite(w, h)

    print("--- 1. オブジェクト版 (32x32, 中心中央, 範囲=300) ---")
    s = 300
    cx, cy, r, rp = params(w, h, 0, 0, s)
    x0, y0, x1, y1 = canvas_rect(w, h, cx, cy, s)
    print(f"  cx={cx} cy={cy} R={r} R'={rp}  矩形 ({x0},{y0})-({x1},{y1})")
    print(f"  遠方のサンプル数 = 範囲·R'/1000 = {c_div(rp * s, 1000)} 個 ―― "
          "小さいオブジェクトではサンプルが数個しか無い(§1 の縞はこれ)")
    px = worker_object(src, w, h, cx, cy, s, rp, x0, y0, x1, y1)
    draw_alpha({(x, y): src[y][x] for y in range(h) for x in range(w)},
               0, 0, w, h, "入力アルファ")
    draw_alpha(px, x0, y0, x1, y1, "出力アルファ")
    inside = [px[(x, y)][3] for x in range(x0, x1) for y in range(y0, y1)]
    check("アルファが入力の最大 4096 を超えない", max(inside) <= FULL, f"最大 {max(inside)}")
    check("中心の画素は素通し(距離0はサンプル計画が d<2)",
          px[(cx, cy)] == src[cy][cx] if 0 <= cx < w else True)
    corner = px[(x0, y0)]
    check("拡張した角は透明", corner[3] == 0, f"{corner}")

    print("\n--- 2. スレッド数を変えても同じ ---")
    base = px
    same = True
    for nthread in (1, 2, 3, 5, 8, 16, 32):
        acc = {}
        for tid in range(nthread):
            acc.update(worker_object(src, w, h, cx, cy, s, rp, x0, y0, x1, y1,
                                     tid, nthread))
        if acc != base:
            same = False
    check("1〜32 スレッドで出力が完全一致", same)
    check("担当行の総和がちょうど高さぶん",
          all(sum(c_div((y1 - y0) * (t + 1), n) - c_div((y1 - y0) * t, n)
                  for t in range(n)) == y1 - y0
              for n in (1, 3, 7, 32)))

    print("\n--- 3. サイズ固定 ON / OFF ---")
    fx0, fy0, fx1, fy1 = canvas_rect(w, h, cx, cy, s, size_fixed=True)
    fixed = worker_object(src, w, h, cx, cy, s, rp, fx0, fy0, fx1, fy1)
    check("重なっている領域の画素値が完全に一致",
          all(fixed[(x, y)] == base[(x, y)]
              for x in range(fx0, fx1) for y in range(fy0, fy1)))
    print(f"  拡張時 {x1 - x0}x{y1 - y0} / 固定時 {fx1 - fx0}x{fy1 - fy0}")
    draw_alpha(fixed, fx0, fy0, fx1, fy1, "サイズ固定 ON のアルファ")

    print("\n--- 4. フレーム版 ---")
    fsrc = [[(4096, -600, 1200) if (2 <= x < 6 and 2 <= y < 6) else (0, 0, 0)
             for x in range(w)] for y in range(h)]
    cxf, cyf, rf, rpf = params(w, h, 0, 0, s)
    a = worker_frame(fsrc, w, h, cxf, cyf, s, rpf, clip=False)
    b = worker_frame(fsrc, w, h, cxf, cyf, s, rpf, clip=True)
    check("中心が枠内なら、範囲判定の有無で結果が変わらない", a == b)
    print("  出力の輝度 (中心が枠内のワーカー):")
    for row in a:
        print("    " + " ".join(f"{p[0]:>5}" for p in row))
    print("  枠外のサンプルは足されないが割る数は n のまま ―― つまり黒として平均される。")
    out_cx, out_cy, _, out_rp = params(w, h, 40, 0, s)
    c = worker_frame(fsrc, w, h, out_cx, out_cy, s, out_rp, clip=True)
    check("中心を枠外へ出しても落ちない(範囲判定つきワーカー側)", c is not None)

    print("\n--- 5. 平坦な不透明領域 ---")
    flat = [[(3000, 100, -200, FULL)] * w for _ in range(h)]
    fx0, fy0, fx1, fy1 = canvas_rect(w, h, cx, cy, s, size_fixed=True)
    out = worker_object(flat, w, h, cx, cy, s, rp, fx0, fy0, fx1, fy1)
    vals = {out[(x, y)] for x in range(1, w - 1) for y in range(1, h - 1)}
    print(f"  内側の画素値: {sorted(vals)}")
    check("平坦な不透明領域は色もアルファも素通し", vals == {(3000, 100, -200, FULL)})

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
