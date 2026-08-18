"""ワイプ全体(進捗ランプ + パターン生成 + ぼかし + 最終合成)を1本の
整数忠実リファレンスにまとめ、小さな矩形でオブジェクトのタイムライン全体を
ASCIIで描画する。

進捗ランプは `フェード` と同じ形([`disasm_params.py`](disasm_params.py))。
5パターンの式は [`verify_patterns.py`](verify_patterns.py)、ぼかしの
半径分割は [`verify_blur.py`](verify_blur.py) から。

**モデル化していないもの、とその理由**:

  * ぼかしパスの境界処理。実装は窓が画像端にかかると「生存サンプル数」で
    割る変則ボックス平均([`box_blur.md`](../common/box_blur.md) の分類でいう
    「常にカーネル幅」ではない側)だが、ここでは説明用にエッジを複製する
    簡易版で近似している。エッジのごく数画素だけがずれうる。
  * カスタムPNGパターン。ファイルI/Oを要するのでこのリファレンスには含めず、
    `verify_custom_pattern.py` の `band()`/`threshold()` を参照。
  * `フェード` 同様、`*(fpip+0x118)` のサブオブジェクト遅延は使わない
    (ワイプの `t` にはそもそも乗らない)。

Run via main.py:
    uv run main.py inspect/wipe/simulate_wipe_reference.py
    uv run main.py inspect/wipe/simulate_wipe_reference.py --pattern 0 --width 24 --height 12
    uv run main.py inspect/wipe/simulate_wipe_reference.py --pattern 3 --invert-in --blur 6
"""

import argparse
import math

from tools.cints import c_div, sar

FULL = 0x1000


# --------------------------------------------------------------- func_proc

def to_frames(raw: int, rate: int, scale: int) -> int:
    return int(raw * float(rate) / (float(scale) * 100.0))


def progress_ramp(frame, start, end, in_raw, out_raw, rate, scale, invert_in, invert_out):
    """0x100904a0-0x10090581. `invert_in`/`invert_out` は check[0]/check[1] の
    値。返り値 (retval, g, checkbox_invert):
      retval==1, g=None  -> ワーカー起動せず全域可視 (return 1)
      retval==0           -> オブジェクト自体を描かない (return 0)
      それ以外             -> g をワーカーへ、checkbox_invert を演算子入れ替えへ渡す
    """
    in_f = to_frames(in_raw, rate, scale)
    out_f = to_frames(out_raw, rate, scale)

    g = FULL
    invert = invert_in                                    # 0x100904ab の既定と同じ扱い
    t = frame - start                                    # フェードと違い fpip+0x118 は乗らない
    if t < in_f:
        a = c_div((t + 1) << 12, in_f + 1)
        if a < g:
            g, invert = a, invert_in                      # check[0] = 反転(イン)
    u = end - frame
    if u < out_f:
        a = c_div((u + 1) << 12, out_f + 1)
        if g > a:
            g, invert = a, invert_out                     # check[1] = 反転(アウト)

    if g >= FULL:
        return 1, None, invert
    if g <= 0:
        return 0, g, invert
    if invert:
        g = FULL - g                                       # 反転①: 時間方向
    return 1, g, invert                                    # invert がそのまま反転②(演算子入れ替え)へ


# -------------------------------------------------------------- patterns

def circle_mask(w, h, g, invert):
    r2 = sar((w * w + h * h) * g, 12)
    band = 4 * int(math.sqrt(r2))
    out = [[0] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            # 円だけ距離を2倍座標で測る(README §4)。実効半径が R/2 になり、
            # g=4096 でちょうど四隅に届く。
            d2 = (2 * x - w + 1) ** 2 + (2 * y - h + 1) ** 2
            v = (r2 - d2) if not invert else (d2 - r2)
            out[y][x] = 0 if v <= 0 else (0x1000 if v >= band else c_div(v << 12, band))
    return out


# 四角/時計/横/縦は setcc の結果を dec+and 0x1000 で反転してから書くので、実効的な
# 既定条件は `<=`、反転側は `>=` になる(README §4「読み間違えやすい点」)。
def square_mask(w, h, g, invert):
    cx, cy = w // 2, h // 2
    threshold = sar((cx + cy) * g, 12)
    out = [[0] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            d1 = abs(x - cx) + abs(y - cy)
            visible = (d1 <= threshold) if not invert else (d1 >= threshold)
            out[y][x] = 0x1000 if visible else 0
    return out


def horizontal_mask(w, h, g, invert):
    threshold = c_div(w * g, FULL)
    out = [[0] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            visible = (x <= threshold) if not invert else (x >= threshold)
            out[y][x] = 0x1000 if visible else 0
    return out


def vertical_mask(w, h, g, invert):
    threshold = c_div(h * g, FULL)
    out = [[0] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            visible = (y <= threshold) if not invert else (y >= threshold)
            out[y][x] = 0x1000 if visible else 0
    return out


def clock_mask(w, h, g, invert):
    cx, cy = w // 2, h // 2
    threshold = (g * 16) & 0xFFFF               # round(g * 65536/4096) = g*16
    out = [[0] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            if x == cx and y == cy:
                # 中心画素は fpatan を呼ばずに無条件で可視(0x10090b15 / 0x10090b83)。
                out[y][x] = 0x1000
                continue
            dx, dy = x - cx, y - cy
            ang = math.atan2(dy, dx)
            units = int(-ang * (65536 / (2 * math.pi))) & 0xFFFF
            swept = (0x4000 - units) & 0xFFFF
            visible = (swept <= threshold) if not invert else (swept >= threshold)
            out[y][x] = 0x1000 if visible else 0
    return out


PATTERNS = {0: ("円", circle_mask), 1: ("四角", square_mask), 2: ("時計", clock_mask),
           3: ("横", horizontal_mask), 4: ("縦", vertical_mask)}


# ------------------------------------------------------------------ blur

def kernel_split(blur: int):
    r_lo = blur >> 1
    r_hi = blur - r_lo
    return r_hi, r_lo


def _box1d(row, r):
    """簡易版: 窓 2r+1 の単純平均、端はクランプで近似(実装の『生存サンプル数
    で割る』挙動そのものではない ―― モジュール docstring 参照)。"""
    n = len(row)
    out = [0] * n
    for i in range(n):
        s = sum(row[max(0, i - r):min(n, i + r + 1)])
        cnt = min(n, i + r + 1) - max(0, i - r)
        out[i] = c_div(s, cnt)
    return out


def box_blur_pass(mask, r):
    if r <= 0:
        return mask
    h = len(mask)
    w = len(mask[0])
    # 軸1: 垂直
    cols = [[mask[y][x] for y in range(h)] for x in range(w)]
    cols = [_box1d(c, r) for c in cols]
    tmp = [[cols[x][y] for x in range(w)] for y in range(h)]
    # 軸2: 水平
    rows = [_box1d(tmp[y], r) for y in range(h)]
    return rows


def blur_mask(mask, blur):
    r_hi, r_lo = kernel_split(blur)
    if r_hi > 0:
        mask = box_blur_pass(mask, r_hi)
    if r_lo > 0:
        mask = box_blur_pass(mask, r_lo)
    return mask


# --------------------------------------------------------------- display

GLYPHS = " .:-=+*#%@"


def glyph(v):
    return GLYPHS[max(0, min(len(GLYPHS) - 1, v * len(GLYPHS) // FULL))]


def render(mask):
    return "\n".join("".join(glyph(v) for v in row) for row in mask)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="simulate_wipe_reference")
    p.add_argument("--pattern", type=int, default=0, choices=range(5),
                   help="0=円 1=四角 2=時計 3=横 4=縦 (default: %(default)s)")
    p.add_argument("--width", type=int, default=32)
    p.add_argument("--height", type=int, default=16)
    p.add_argument("--in", dest="wipe_in", type=float, default=1.0, help="イン [s]")
    p.add_argument("--out", dest="wipe_out", type=float, default=1.0, help="アウト [s]")
    p.add_argument("--blur", type=int, default=0, help="ぼかし raw 0..100")
    p.add_argument("--invert-in", action="store_true")
    p.add_argument("--invert-out", action="store_true")
    p.add_argument("--fps", default="30")
    p.add_argument("--length", type=int, default=24)
    p.add_argument("--frames", type=int, default=6, help="表示するコマ数")
    args = p.parse_args(argv or [])

    rate, scale = {"30": (30, 1), "29.97": (30000, 1001), "24": (24, 1),
                   "60": (60, 1)}[args.fps]
    in_raw = round(args.wipe_in * 100)
    out_raw = round(args.wipe_out * 100)
    start, end = 0, args.length - 1
    name, fn = PATTERNS[args.pattern]

    print(f"pattern={name}  {args.width}x{args.height}  イン={args.wipe_in}s アウト={args.wipe_out}s "
          f"length={args.length} fps={args.fps} blur={args.blur}")
    print(f"反転(イン)={args.invert_in}  反転(アウト)={args.invert_out}\n")

    step = max(1, args.length // args.frames)
    for frame in range(start, end + 1, step):
        ret, g, checkbox_invert = progress_ramp(
            frame, start, end, in_raw, out_raw, rate, scale,
            args.invert_in, args.invert_out)
        if ret == 1 and g is None:
            print(f"frame {frame:3d}: g=full   (return 1, ワーカー起動せず全域可視)")
            continue
        if ret == 0:
            print(f"frame {frame:3d}: g=0      (return 0, オブジェクト自体を描かない)")
            continue
        # progress_ramp が①時間方向の反転(g=FULL-g)を既に適用済み。
        # ワーカー側の②演算子入れ替えには同じ checkbox_invert をそのまま渡す。
        mask = fn(args.width, args.height, g, checkbox_invert)
        if args.blur:
            mask = blur_mask(mask, args.blur)
        frac = sum(1 for row in mask for v in row if v >= 0x1000) / (args.width * args.height)
        print(f"frame {frame:3d}: g={g:4d} ({g/FULL*100:5.1f}%)  visible~{frac*100:5.1f}%")
        print(render(mask))
        print()


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
