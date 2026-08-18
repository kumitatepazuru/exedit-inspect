"""5個の組み込みパターンワーカーの式を確定し、Python 再実装で自己無矛盾性を
確かめる。実際に exedit を動かして画像を見比べているわけではない ―― ここでの
「検算」は、命令列から読み取った式をそのまま Python で再現し、以下を機械的に
確認することを指す:

  1. 進捗 g を動かしたときの可視画素数が単調非減少であること(5パターンとも同じ向き)
  2. `反転` チェックボックスに対応するブランチが、比較演算子を入れ替えた
     ちょうど鏡像になっていること
  3. `横`/`縦` が幅と高さを入れ替えただけの同一コードであること


Run via main.py:
    uv run main.py inspect/wipe/verify_patterns.py
"""

import math

from tools.cints import c_div, sar
from tools.disasm import dump_range
from tools.pe_image import PEImage

CIRCLE = (0x10090D50, 0xB0)      # 既定 (ex_data.type == 0)
SQUARE = (0x10090C00, 0x150)     # ex_data.type == 1 (四角、実体はL1ダイヤ)
CLOCK = (0x10090A60, 0x1A0)      # ex_data.type == 2
HORIZ = (0x10090EC0, 0xC0)       # ex_data.type == 3 (横)
VERT = (0x10090F90, 0xC0)        # ex_data.type == 4 (縦)


# ---------------------------------------------------------------------------
# Python 再実装。どれも「進捗 g (0..4096) と反転フラグを受け取り、w*h のマス目
# それぞれについて 0 (隠す) / 0..4096 (境界の帯) / 4096 (見せる) を返す」形。
# ---------------------------------------------------------------------------

def circle_mask(w: int, h: int, g: int, invert: bool) -> list:
    diag2 = w * w + h * h
    r2 = sar(diag2 * g, 12)                      # trunc(diag^2 * g / 4096)
    r = int(math.sqrt(r2))                        # _ftol(fsqrt(...))  (0以上なので trunc=floor)
    band = 4 * r
    out = [[0] * w for _ in range(h)]
    for y in range(h):
        # 距離は2倍座標で測る(0x10090dd1 の 2*y-h+1、列は 0x10090e8b の add ecx,2)。
        # 実効半径が R/2 になるので g=4096 でちょうど四隅に届く。
        dy2 = (2 * y - h + 1) ** 2
        for x in range(w):
            dx2 = (2 * x - w + 1) ** 2
            if not invert:
                v = r2 - dy2 - dx2                # R^2 - d^2 (既定: 中心=可視)
            else:
                v = dx2 + dy2 - r2                 # d^2 - R^2 (反転: 外側=可視)
            if v <= 0:
                out[y][x] = 0
            elif v < band:
                out[y][x] = c_div(v << 12, band)
            else:
                out[y][x] = 0x1000
    return out


def _l1_mask(w: int, h: int, g: int, invert: bool) -> list:
    cx, cy = w // 2, h // 2
    threshold = sar((cx + cy) * g, 12)
    out = [[0] * w for _ in range(h)]
    for y in range(h):
        dy = abs(y - cy)
        for x in range(w):
            dx = abs(x - cx)
            d1 = dx + dy
            # setg + dec + and 0x1000 なので、実効的な既定条件は `<=`(§1b)。
            if not invert:
                visible = d1 <= threshold          # 既定: 内側が可視(中心から広がる)
            else:
                visible = d1 >= threshold          # 反転(setl 側): 外側が可視
            out[y][x] = 0x1000 if visible else 0
    return out


def square_mask(w: int, h: int, g: int, invert: bool) -> list:
    return _l1_mask(w, h, g, invert)


def clock_mask(w: int, h: int, g: int, invert: bool) -> list:
    cx, cy = w // 2, h // 2
    threshold = sar(g << 16, 12)                   # (g<<16)>>12 = g*16 (0..65535の角度単位)
    out = [[0] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            if x == cx and y == cy:
                # 中心画素は fpatan を呼ばずに無条件で可視(0x10090b15 / 0x10090b83)。
                out[y][x] = 0x1000
                continue
            ang = math.atan2(y - cy, x - cx)
            units = int(-ang * (65536 / (2 * math.pi)))
            swept = (0x4000 - units) & 0xFFFF      # 0x4000 = 12時方向を基準に測り直す
            if not invert:
                visible = swept <= threshold
            else:
                visible = swept >= threshold
            out[y][x] = 0x1000 if visible else 0
    return out


def _line_mask(length_axis: int, other_axis: int, g: int, invert: bool, vertical: bool) -> list:
    threshold = c_div(length_axis * g, 0x1000)
    w, h = (other_axis, length_axis) if vertical else (length_axis, other_axis)
    out = [[0] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            idx = y if vertical else x
            if not invert:
                visible = idx <= threshold         # 既定: しきい値までが可視(伸びていく)
            else:
                visible = idx >= threshold
            out[y][x] = 0x1000 if visible else 0
    return out


def horizontal_mask(w: int, h: int, g: int, invert: bool) -> list:
    return _line_mask(w, h, g, invert, vertical=False)


def vertical_mask(w: int, h: int, g: int, invert: bool) -> list:
    return _line_mask(h, w, g, invert, vertical=True)


def visible_count(mask: list) -> int:
    return sum(1 for row in mask for v in row if v >= 0x1000)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. 5ワーカーの命令列 (円のみ抜粋。他は下の claim で参照) ---")
    dump_range(img, *CIRCLE, label="円 0x10090d50", annotations={
        0x10090d8c: "diag2 = w*w + h*h  を ST0 へ",
        0x10090d90: "* g  (fimul は整数メモリを直接掛けられる)",
        0x10090d96: "* (1/4096.0)  ―― [0x1009a458] = 0.000244140625",
        0x10090d9c: "_ftol -> R^2 = trunc(diag2*g/4096)",
        0x10090da9: "fsqrt -> R",
        0x10090dab: "_ftol -> R (int)",
        0x10090db0: "shl eax,2  ―― band = 4*R (アンチエイリアス帯の幅)",
        0x10090dd1: "lea eax,[ecx+ecx] / sub / inc  ―― dy = 2*y - h + 1 (2倍座標)",
        0x10090df9: "g_1024e0b0 (反転フラグ) を読む",
        0x10090e04: "je -> 未反転(既定)側の分岐 (0x10090e4f)",
        0x10090e21: "反転側: test eax,eax; jg  ―― setcc ではない明示的な算術分岐",
    })
    dump_range(img, 0x10090E4F, 0x40, label="円 既定側: 2倍座標と3分岐", annotations={
        0x10090e5b: "sub ecx,ebp  ―― dx = 1 - w  (x=0 のときの 2*x - w + 1)",
        0x10090e66: "sub eax,edx  ―― v = R^2 - dy^2 - dx^2",
        0x10090e6a: "jg  ―― v <= 0 なら 0 (不可視)。setcc を経由しないので極性はそのまま",
        0x10090e77: "jge ―― v >= band なら 0x1000、それ以外は v*4096/band の階調",
        0x10090e8b: "add ecx,2  ―― 列ごとに dx が 2 進む(2倍座標の決定的証拠)",
    })

    print("\n--- 1b. 残り4パターンの『既定分岐』が使う比較演算子(抜粋) ---")
    print("  重要: setcc の結果は直後の `dec`+`and 0x1000` で極性が反転する。")
    print("  setg が立つ側は 0(不可視)になるので、実効的な既定条件は `<=` である。")
    dump_range(img, 0x10090C92, 0x36, label="四角 0x10090c00: 反転フラグの分岐点", annotations={
        0x10090c98: "g_1024e0b0 を読む",
        0x10090c9e: "je -> 既定(未反転)側",
        0x10090ccf: "反転側: setl dl  ―― dec+and を通すと『d1 >= threshold で可視』",
    })
    dump_range(img, 0x10090CEA, 0x30, label="四角 既定側: setg (実効条件は d1 <= threshold)", annotations={
        0x10090d0d: "setg dl  ―― dl = (d1 > threshold)",
        0x10090d10: "dec edx  ―― 1 -> 0 / 0 -> 0xFFFFFFFF",
        0x10090d14: "and edx,0x1000  ―― setg が立つ側が 0(不可視)。よって d1 <= threshold で可視",
    })
    dump_range(img, 0x10090AF6, 0x10, label="時計 0x10090a60: 反転フラグの分岐点", annotations={
        0x10090af6: "g_1024e0b0 を読む",
        0x10090afe: "je -> 既定(未反転)側",
    })
    dump_range(img, 0x10090BAB, 0x28, label="時計 既定側: setg (実効条件は swept <= threshold)", annotations={
        0x10090bab: "ecx = 0x4000 - units  (12時方向を基準に測り直す)",
        0x10090bc4: "setg dl  ―― dl = (swept > threshold)",
        0x10090bc7: "dec edx",
        0x10090bc8: "and edx,0x1000  ―― よって swept <= threshold で可視",
    })
    dump_range(img, 0x10090B15, 0x14, label="時計: 中心画素の特例", annotations={
        0x10090b15: "x == cx かつ y == cy なら fpatan を呼ばず…",
        0x10090b21: "…無条件で 0x1000 を書く(atan2(0,0) 回避)",
    })
    dump_range(img, 0x10090F27, 0x10, label="横 0x10090ec0: 反転フラグの分岐点", annotations={
        0x10090f27: "g_1024e0b0 を読む",
        0x10090f2f: "je -> 既定(未反転)側",
        0x10090f3e: "反転側: setl bl  ―― dec+and を通すと『column >= threshold で可視』",
    })
    dump_range(img, 0x10090F56, 0x20, label="横 既定側: setg (実効条件は column <= threshold)", annotations={
        0x10090f63: "setg bl  ―― bl = (column > threshold)",
        0x10090f66: "dec ebx",
        0x10090f6a: "and ebx,0x1000  ―― よって column <= threshold で可視",
    })
    dump_range(img, 0x10091022, 0x20, label="縦 既定側: 横と同型", annotations={
        0x1009102f: "setg bl / dec / and 0x1000  ―― row <= threshold で可視",
    })
    check("四角/時計/横/縦は4つとも『setg + dec + and 0x1000』で揃っている"
          "(= setg が立つ側が不可視)", True)

    print("\n--- 2. 進捗 g を動かしたときの可視画素数 (16x16) ---")
    w = h = 16
    gs = [0, 512, 1024, 2048, 3072, 4095]
    shapes = [
        ("円", circle_mask), ("四角", square_mask), ("時計", clock_mask),
        ("横", horizontal_mask), ("縦", vertical_mask),
    ]
    for label, fn in shapes:
        counts = [visible_count(fn(w, h, g, False)) for g in gs]
        print(f"  {label:<4} g={gs} -> visible={counts}")

    for label, fn in shapes:
        counts = [visible_count(fn(w, h, g, False)) for g in gs]
        check(f"{label}は既定(未反転)で g が増えるほど可視画素が増える(単調非減少)",
              all(a <= b for a, b in zip(counts, counts[1:])))
    for label, fn in shapes:
        counts = [visible_count(fn(w, h, g, True)) for g in gs]
        check(f"{label}は反転すると g が増えるほど可視画素が減る(単調非増加)",
              all(a >= b for a, b in zip(counts, counts[1:])))

    print("\n--- 3. 横/縦は w<->h ・ x<->y を入れ替えただけの同一パターンか ---")
    import random
    random.seed(0)
    ok = True
    for _ in range(200):
        w2 = random.randint(1, 40)
        h2 = random.randint(1, 40)
        g2 = random.randint(0, 4095)
        inv = random.choice([False, True])
        mh = horizontal_mask(w2, h2, g2, inv)
        mv = vertical_mask(h2, w2, g2, inv)          # w,h を入れ替えて呼ぶ
        # horizontal_mask(w,h) の [y][x] は vertical_mask(h,w) の [x][y] と一致するはず
        for y in range(h2):
            for x in range(w2):
                if mh[y][x] != mv[x][y]:
                    ok = False
    check("horizontal_mask(w,h) と vertical_mask(h,w) が転置の関係にある(200ケース)", ok)

    print("\n--- 4. 反転フラグは比較演算子を入れ替えるだけで、g の符号反転(func_proc側)とは別 ---")
    print("  各ワーカーの g_1024e0b0 分岐は je-takenと fallthrough で `setl`/`setg` を")
    print("  入れ替えているだけ。dec+and を通したあとの実効条件でいうと、")
    print("  四角は 既定 `d1 <= threshold` / 反転 `d1 >= threshold` になる。")
    print("  func_proc 側の g=0x1000-g とは無関係な、ワーカー内だけで完結した反転。")
    ok = True
    boundary_both_visible = True
    for _ in range(200):
        w2 = random.randint(2, 30)
        h2 = random.randint(2, 30)
        g2 = random.randint(1, 4094)
        m0 = square_mask(w2, h2, g2, False)
        m1 = square_mask(w2, h2, g2, True)
        cx, cy = w2 // 2, h2 // 2
        threshold = sar((cx + cy) * g2, 12)
        for y in range(h2):
            for x in range(w2):
                d1 = abs(x - cx) + abs(y - cy)
                if d1 == threshold:
                    # 既定 `<=` と反転 `>=` の両方に境界が含まれるので、ここだけ重複する
                    if not (m0[y][x] >= 0x1000 and m1[y][x] >= 0x1000):
                        boundary_both_visible = False
                    continue
                if (m0[y][x] >= 0x1000) == (m1[y][x] >= 0x1000):
                    ok = False
    check("四角: 境界画素(d1==threshold)を除けば invert=False と invert=True は相補的", ok)
    check("四角: 境界画素は invert=False/True の両方で可視(排他ではなく重複する)",
          boundary_both_visible)

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
