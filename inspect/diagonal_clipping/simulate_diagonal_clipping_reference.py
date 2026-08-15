"""`斜めクリッピング` の整数忠実リファレンス実装と、その ASCII 描画。

`func_proc`(グローバル6個の組み立て)と2つのワーカー(3分岐)を、命令に
対応させたまま1本に畳んである。式の根拠は
[`verify_direction.py`](verify_direction.py) /
[`verify_edge_ramp.py`](verify_edge_ramp.py) /
[`verify_clip_geometry.py`](verify_clip_geometry.py) にある。

このエフェクトは**オブジェクトのアルファに 0..4096 の係数を掛けるだけ**で、
`y`/`cb`/`cr` を一度も読まない。キャンバスも動かさず、対バッファも使わず、
共有ワーカーも呼ばない ―― なので「モデル化していないもの」は実質的に無い。
唯一の近似は `fsin`/`fcos`/`fsqrt` をホストの libm で代用している点で、
食い違いうる角度は 30 度の倍数の 322 組だけ、影響も境界が 1/65536 画素
ずれるだけである(`verify_direction.py` §6)。

出力は「元のアルファが一様に 4096 のオブジェクト」にこのエフェクトを掛けた
結果のマスク。文字は濃いほど不透明:

    #  4096(完全に残る)   +  3/4   o  1/2   .  1/4   (空白)  0(完全に消える)

Run via main.py:
    uv run main.py inspect/diagonal_clipping/simulate_diagonal_clipping_reference.py
    uv run main.py inspect/diagonal_clipping/simulate_diagonal_clipping_reference.py --angle 30 --blur 3
    uv run main.py inspect/diagonal_clipping/simulate_diagonal_clipping_reference.py --clip-width 16 --blur 2
    uv run main.py inspect/diagonal_clipping/simulate_diagonal_clipping_reference.py --clip-width -16 --angle 60
"""

import argparse
import math

from tools.cints import c_div, sar, to_i32
from tools.pe_image import PEImage

DEG10 = 0x1009A410      # +pi/1800
Q16 = 0x1009A3E8        # 65536.0
Q16_NEG = 0x1009A408    # -65536.0
EASE_C1 = 0x1009A758    # pi/4096
EASE_C2 = 0x1009A4F8    # 2048.0

FULL = 0x1000
GLYPHS = " ...ooo+++###"


class DiagonalClipping:
    """トラックバー5本 + オブジェクトの寸法から、アルファ係数マスクを作る。

    生値はすべて UI の生値(`fp->track[]` の中身)。`角度` は 1/10 度単位、
    それ以外は表示値そのままである。
    """

    def __init__(self, img: PEImage, centre_x=0, centre_y=0, angle=0, blur=1, width=0):
        self.k = img.f64(DEG10)
        self.q16 = img.f64(Q16)
        self.q16n = img.f64(Q16_NEG)
        c1, c2 = img.f64(EASE_C1), img.f64(EASE_C2)
        self.table = [math.trunc(c2 * (1 - math.cos(i * c1))) for i in range(4097)]
        self.track = (centre_x, centre_y, angle, blur, width)

    # ------------------------------------------------------------ func_proc
    def globals_for(self, w: int, h: int) -> dict:
        """0x1005cab0-0x1005cb33。`fp->track[]` -> グローバル6個。"""
        centre_x, centre_y, angle, blur, width = self.track
        t = angle * self.k
        return {
            "cx": c_div(w, 2) + centre_x,                            # g_101b20c8
            "cy": c_div(h, 2) + centre_y,                            # g_101b20cc
            "vx": math.trunc(math.sin(t) * self.q16),                # g_101b20d0
            "vy": math.trunc(math.cos(t) * self.q16n),               # g_101b20d4
            "blur1": blur + 1,                                       # g_101b20d8
            "hw": to_i32(width << 15),                               # g_101b20c4
        }

    # --------------------------------------------------------------- worker
    def mask(self, w: int, h: int, thread_num: int = 1) -> list:
        """0x1005cb70 / 0x1005ccb0。返り値は [h][w] の 0..4096。

        元のアルファは一様 4096 とみなす。実際のワーカーは in-place で
        `alpha = (alpha * 係数) >> 12` を書くので、任意の元アルファに対する
        結果はこのマスクとの積(と `>> 12`)になる。
        """
        g = self.globals_for(w, h)
        vx, vy, hw = g["vx"], g["vy"], g["hw"]
        band = math.trunc(math.sqrt(float(vx) * vx + float(vy) * vy) * g["blur1"])
        div = c_div(band + 255, 256)
        base = sar(band, 1) - g["cy"] * vy - g["cx"] * vx
        halfplane = hw == 0

        out = [[FULL] * w for _ in range(h)]
        for tid in range(thread_num):
            y0 = c_div(h * tid, thread_num)
            y1 = c_div(h * (tid + 1), thread_num)
            if y0 >= y1:
                continue
            for y in range(y0, y1):
                acc = to_i32(vy * y + base)
                if not halfplane:
                    acc = to_i32(acc - c_div(band, 2))
                row = out[y]
                for x in range(w):
                    m = acc if halfplane else (hw - abs(acc) if hw > 0 else abs(acc) + hw)
                    if m < band:
                        row[x] = 0 if m <= 0 else sar(row[x] * self.table[c_div(m * 16, div)], 12)
                    acc = to_i32(acc + vx)
        return out

    # ---------------------------------------------------------- 説明用の量
    def describe(self, w: int, h: int) -> list:
        g = self.globals_for(w, h)
        vx, vy = g["vx"], g["vy"]
        norm = math.hypot(vx, vy)
        band = math.trunc(norm * g["blur1"])
        centre_x, centre_y, angle, blur, width = self.track
        lines = [
            f"  トラックバー  中心X={centre_x} 中心Y={centre_y} "
            f"角度={angle / 10:.1f} ぼかし={blur} 幅={width}",
            f"  直線が通る点  ({g['cx']}, {g['cy']}) [画素]  = (w/2+中心X, h/2+中心Y)",
            f"  法線ベクトル  ({vx}, {vy}) Q16 = "
            f"({vx / 65536:+.4f}, {vy / 65536:+.4f})  |v|={norm:.4f}",
            f"  階調帯 band   {band} = trunc(|v|·(ぼかし+1)) → "
            f"{band / norm:.4f} 画素、除数 ceil(band/256)={c_div(band + 255, 256)}",
        ]
        if g["hw"] == 0:
            lines.append("  モード        幅 = 0 → 半平面。法線が指す側が残り、"
                         "階調帯は直線を挟んで centered")
        elif g["hw"] > 0:
            lines.append(f"  モード        幅 > 0 → 帯を残す。|d| <= {width / 2:.1f}px が可視、"
                         f"|d| <= {width / 2 - band / norm:.1f}px が完全不透明")
        else:
            lines.append(f"  モード        幅 < 0 → 帯を消す。|d| <= {-width / 2:.1f}px が透明、"
                         f"|d| >= {-width / 2 + band / norm:.1f}px が完全不透明")
        return lines


def render(mask: list) -> str:
    rows = []
    for row in mask:
        rows.append("".join(GLYPHS[min(len(GLYPHS) - 1, a * len(GLYPHS) // (FULL + 1))]
                            for a in row))
    return "\n".join(f"  |{r}|" for r in rows)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="simulate_diagonal_clipping_reference")
    parser.add_argument("--width", type=int, default=48, help="オブジェクトの幅 [画素]")
    parser.add_argument("--height", type=int, default=20, help="オブジェクトの高さ [画素]")
    parser.add_argument("--centre-x", type=int, default=0, help="中心X (生値)")
    parser.add_argument("--centre-y", type=int, default=0, help="中心Y (生値)")
    parser.add_argument("--angle", type=float, default=None,
                        help="角度 [度]。既定は 0.0 / 30.0 / 60.0 の3枚を並べる")
    parser.add_argument("--blur", type=int, default=1, help="ぼかし (生値 0..2000)")
    parser.add_argument("--clip-width", type=int, default=None,
                        help="幅 (生値 -2000..2000)。既定は 0 / +16 / -16 の3枚")
    parser.add_argument("--threads", type=int, default=1, help="thread_num")
    args = parser.parse_args(argv or [])

    img = PEImage(dll_path)
    w, h = args.width, args.height

    if args.angle is None and args.clip_width is None:
        cases = [("幅 = 0 ―― 半平面(既定)", 0.0, 0),
                 ("幅 = +16 ―― 帯を残す", 0.0, 16),
                 ("幅 = -16 ―― 帯を消す", 0.0, -16),
                 ("角度 = 30.0・幅 = 0", 30.0, 0),
                 ("角度 = 60.0・幅 = +16", 60.0, 16)]
    else:
        cases = [("", args.angle or 0.0, args.clip_width or 0)]

    for label, angle, clip_width in cases:
        eff = DiagonalClipping(img, args.centre_x, args.centre_y,
                               round(angle * 10), args.blur, clip_width)
        print(f"\n=== {label or f'角度 {angle:.1f} / 幅 {clip_width}'} "
              f"({w}x{h}, ぼかし={args.blur}) ===")
        for line in eff.describe(w, h):
            print(line)
        mask = eff.mask(w, h, args.threads)
        print(render(mask))
        vis = sum(1 for row in mask for a in row if a > 0)
        opaque = sum(1 for row in mask for a in row if a == FULL)
        print(f"  可視 {vis}/{w * h} 画素、うち完全不透明 {opaque}")

    print("\n文字: '#'=4096  '+'≈3/4  'o'≈1/2  '.'≈1/4  ' '=0")
    print("マスクは元のアルファに掛かる係数。色は一切変わらない。")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
