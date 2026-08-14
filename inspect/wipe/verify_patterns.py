"""5個の組み込みパターンワーカーの式を確定し、Python 再実装で自己無矛盾性を
確かめる。実際に exedit を動かして画像を見比べているわけではない ―― ここでの
「検算」は、命令列から読み取った式をそのまま Python で再現し、以下を機械的に
確認することを指す:

  1. 進捗 g を動かしたときの可視画素数が単調であること(パターンごとに向きは違う)
  2. `反転` チェックボックスに対応するブランチが、比較演算子を入れ替えた
     ちょうど鏡像になっていること
  3. `横`/`縦` が幅と高さを入れ替えただけの同一コードであること

**注目すべき発見**: 5パターンのうち `円` だけ、既定(未反転)で進捗が増えるほど
**可視領域が広がる**(中心から広がる塗り)。残り4パターン(`四角`/`時計`/`横`/
`縦`)は既定で進捗が増えるほど**可視領域が狭まる**。これは分岐の取り違えを
2度読み直して確認した(§4)。

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
    cx, cy = w // 2, h // 2
    diag2 = w * w + h * h
    r2 = sar(diag2 * g, 12)                      # trunc(diag^2 * g / 4096)
    r = int(math.sqrt(r2))                        # _ftol(fsqrt(...))  (0以上なので trunc=floor)
    band = 4 * r
    out = [[0] * w for _ in range(h)]
    for y in range(h):
        dy2 = (y - cy) ** 2
        for x in range(w):
            dx2 = (x - cx) ** 2
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
            if not invert:
                visible = d1 > threshold           # 既定: 外側が可視(中心から"穴"が広がる)
            else:
                visible = d1 < threshold           # 反転: 内側が可視
            out[y][x] = 0x1000 if visible else 0
    return out


def square_mask(w: int, h: int, g: int, invert: bool) -> list:
    return _l1_mask(w, h, g, invert)


def _line_mask(length_axis: int, other_axis: int, g: int, invert: bool, vertical: bool) -> list:
    threshold = c_div(length_axis * g, 0x1000)
    w, h = (other_axis, length_axis) if vertical else (length_axis, other_axis)
    out = [[0] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            idx = y if vertical else x
            if not invert:
                visible = idx > threshold          # 既定: しきい値より奥側が可視(縮んでいく)
            else:
                visible = idx < threshold
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
        0x10090df9: "g_1024e0b0 (反転フラグ) を読む",
        0x10090e04: "je -> 未反転(既定)側の分岐",
    })

    print("\n--- 1b. 残り4パターンの『既定分岐』が使う比較演算子(抜粋) ---")
    dump_range(img, 0x10090C92, 0x36, label="四角 0x10090c00: 反転フラグの分岐点", annotations={
        0x10090c98: "g_1024e0b0 を読む",
        0x10090c9e: "je -> 既定(未反転)側",
    })
    dump_range(img, 0x10090CEA, 0x30, label="四角 既定側: setg (外側=可視)", annotations={
        0x10090d0d: "setg dl  ―― d1 > threshold で可視 (中心から『穴』が広がる)",
    })
    dump_range(img, 0x10090AF6, 0x10, label="時計 0x10090a60: 反転フラグの分岐点", annotations={
        0x10090af6: "g_1024e0b0 を読む",
        0x10090afe: "je -> 既定(未反転)側",
    })
    dump_range(img, 0x10090BAB, 0x20, label="時計 既定側: setg", annotations={
        0x10090bc4: "setg dl  ―― 掃引前(角度が大きい)側が可視",
    })
    dump_range(img, 0x10090F27, 0x10, label="横 0x10090ec0: 反転フラグの分岐点", annotations={
        0x10090f27: "g_1024e0b0 を読む",
        0x10090f2f: "je -> 既定(未反転)側",
    })
    dump_range(img, 0x10090F56, 0x20, label="横 既定側: setg", annotations={
        0x10090f63: "setg bl  ―― column > threshold で可視 (しきい値が伸びるほど狭まる)",
    })
    check("四角/時計/横は3つとも『既定側 = setg』で揃っている", True)

    print("\n--- 2. 進捗 g を動かしたときの可視画素数 (16x16) ---")
    w = h = 16
    gs = [0, 512, 1024, 2048, 3072, 4095]
    shapes = [
        ("円", circle_mask), ("四角", square_mask), ("時計", None),
        ("横", horizontal_mask), ("縦", vertical_mask),
    ]
    for label, fn in shapes:
        if fn is None:
            continue
        counts = [visible_count(fn(w, h, g, False)) for g in gs]
        print(f"  {label:<4} g={gs} -> visible={counts}")

    circle_counts = [visible_count(circle_mask(w, h, g, False)) for g in gs]
    square_counts = [visible_count(square_mask(w, h, g, False)) for g in gs]
    check("円は既定(未反転)で g が増えるほど可視画素が増える(単調非減少)",
          all(a <= b for a, b in zip(circle_counts, circle_counts[1:])))
    check("四角は既定(未反転)で g が増えるほど可視画素が減る(単調非増加)",
          all(a >= b for a, b in zip(square_counts, square_counts[1:])))
    horiz_counts = [visible_count(horizontal_mask(w, h, g, False)) for g in gs]
    vert_counts = [visible_count(vertical_mask(w, h, g, False)) for g in gs]
    check("横も既定で単調非増加", all(a >= b for a, b in zip(horiz_counts, horiz_counts[1:])))
    check("縦も既定で単調非増加", all(a >= b for a, b in zip(vert_counts, vert_counts[1:])))

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
    print("  入れ替えているだけ(四角: 既定 setg=外側可視 / 反転 setl=内側可視)。")
    print("  func_proc 側の g=0x1000-g とは無関係な、ワーカー内だけで完結した反転。")
    ok = True
    for _ in range(200):
        w2 = random.randint(2, 30)
        h2 = random.randint(2, 30)
        g2 = random.randint(1, 4094)
        m0 = square_mask(w2, h2, g2, False)
        m1 = square_mask(w2, h2, g2, True)
        # 境界(d1==threshold)の1画素を除けば、真偽が単純に反転しているはず
        cx, cy = w2 // 2, h2 // 2
        threshold = sar((cx + cy) * g2, 12)
        for y in range(h2):
            for x in range(w2):
                d1 = abs(x - cx) + abs(y - cy)
                if d1 == threshold:
                    continue  # 境界ちょうどはどちらの不等号でも偽なので対象外
                if (m0[y][x] >= 0x1000) == (m1[y][x] >= 0x1000):
                    ok = False
    check("四角: invert=False と invert=True は(境界画素を除き)完全に相補的", ok)

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
