"""境界の階調 ―― `ぼかし+1`、イージング表、そして添字を表からはみ出させない
たった1つの切り上げ。

3つのワーカー分岐(`幅` の 0 / 正 / 負)は、最後の4命令だけを見ると完全に
同じことをしている:

    m >= band           -> アルファを触らない
    m <= 0              -> アルファ = 0
    それ以外            -> alpha = (alpha * table[m*16 / div]) >> 12

違うのは `m` の作り方だけ(`verify_clip_geometry.py`)。ここでは `m` が
決まったあとの共通部分を確定させる。

6つの主張:

  1. **`ぼかし` は常に +1 されて使われる**(`0x1005caf0` の `inc eax`)。
     `ぼかし = 0` でも階調帯は 1 画素残るので、**このエフェクトでハード
     エッジは作れない**。斜めの直線を扱う以上そうでないとジャギーが出る、
     という意味で理にかなっている ―― `ぼかし = 0` がハードエッジになる
     [`ワイプ`](../wipe/README.md) との対比。

  2. **表は共有の 1-cos イージング表 `0x101dcf78`**
     ([`lut_tables.md`](../common/lut_tables.md))。`.rdata` の実定数から
     `table[i] = trunc(2048·(1 - cos(i·pi/4096)))` を再現する。実行時に
     埋めるのは `ノイズ` の `func_init`(`verify_registration.py` §5)。

  3. **除数は `ceil(band/256)`** ―― `lea eax,[ebx+0xff]` + 0方向切り捨ての
     `/256`。添字は `m*16 / ceil(band/256)` で、`m·4096/band` の**切り下げ側**に
     必ず入る。

  4. **その切り上げが唯一の範囲ガード**である。`floor(band/256)` で割って
     いたら `band mod 256 >= 2` のとき添字が 4096 を超え、`band` が 256 の
     倍数でない角度は実際に存在する(45度・ぼかし=0 で `band = 65534`)。
     はみ出す先は表の直後の3ワードのパディングと、その次に置かれた
     **sin テーブル `0x101def80`** ―― 落ちはしないが階調が壊れる。

  5. **`m*16` は int32 に収まる。** 最悪は `ぼかし = 2000`(生値の上限)の
     `16·(band-1) = 2098200560` で、`INT32_MAX` の 97.7%。`ぼかし` の上限が
     2048 だったらここは溢れていた。

  6. **アルファは減る一方**。`table[i] <= 4096` かつ `>> 12` が `sar`(floor)
     なので `alpha' <= alpha` が常に成り立つ。色(`y`/`cb`/`cr`)には
     一度も触らない ―― [`フェード`](../fade/README.md) /
     [`ワイプ`](../wipe/README.md) と同じ「アルファだけを掛け算する」系。

Run via main.py:
    uv run main.py inspect/diagonal_clipping/verify_edge_ramp.py
"""

import math

from tools.cints import c_div, sar
from tools.pe_image import PEImage

EASE_C1 = 0x1009A758     # pi/4096
EASE_C2 = 0x1009A4F8     # 2048.0
TABLE = 0x101DCF78       # table[0]
TABLE_END = 0x101DEF78   # table[4096]
SIN_TABLE = 0x101DEF80   # lut_tables.md のテーブル3

BLUR_RAW = (0, 2000)


def ease_table(c1: float, c2: float) -> list:
    """0x1006c680(= ノイズ の func_init)が実行時に埋める 4097 要素。"""
    return [math.trunc(c2 * (1 - math.cos(i * c1))) for i in range(4097)]


def div256(x: int) -> int:
    """`cdq / and edx,0xff / add eax,edx / sar eax,8` = 0方向切り捨ての /256。"""
    edx = -1 if x < 0 else 0
    return sar(x + (edx & 0xFF), 8)


def divisor(band: int) -> int:
    """0x1005cbf4-0x1005cc10: `(band + 255) / 256` = ceil(band/256)。"""
    return div256(band + 255)


def ramp(alpha: int, m: int, band: int, table: list) -> int:
    """0x1005cc4c-0x1005cc7a、幅の3分岐に共通の末端。"""
    if m >= band:
        return alpha
    if m <= 0:
        return 0
    return sar(alpha * table[c_div(m * 16, divisor(band))], 12)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)
    c1, c2 = img.f64(EASE_C1), img.f64(EASE_C2)
    table = ease_table(c1, c2)

    print("--- 1. ぼかし は常に +1 される ---")
    insn = img.code(0x1005CAF0, 1)
    check("0x1005caf0 は `inc eax`(0x40)= track[3] + 1", insn == b"\x40",
          f"{insn.hex()}")
    check("その結果が g_101b20d8 へ入る(0x1005caf7 の mov)",
          img.code(0x1005CAF7, 1) == b"\xa3")
    print("  ぼかし の生値範囲は 0..2000、既定 1。使われるのは 1..2001。")
    print("  → 階調帯の幅は最小でも 1 画素。ハードエッジを選ぶ手段が無い。")

    print("\n--- 2. イージング表 ---")
    check(f"0x{EASE_C1:08x} = pi/4096", c1 == math.pi / 4096)
    check(f"0x{EASE_C2:08x} = 2048.0", c2 == 2048.0)
    check(f"0x{TABLE:08x} + 4096*2 = 0x{TABLE_END:08x} = &table[4096]",
          TABLE + 4096 * 2 == TABLE_END)
    print(f"  table[0]={table[0]}  table[1024]={table[1024]}  table[2048]={table[2048]}"
          f"  table[3072]={table[3072]}  table[4096]={table[4096]}")
    check("単調非減少で 0..4096 に収まる",
          all(table[i] <= table[i + 1] for i in range(4096))
          and table[0] == 0 and table[4096] == 4096)
    check("表は .data の未初期化領域にあり、ファイル上は全ゼロ",
          all(img.i16(TABLE + 2 * i) == 0 for i in range(0, 4097, 512)))

    print("\n--- 3. 除数は ceil(band/256) ---")
    bad = [x for x in range(-100000, 100001, 7) if div256(x) != c_div(x, 256)]
    check("命令列 cdq/and/add/sar の再現が c_div(x,256) と一致", not bad, f"{bad[:1]}")
    bad = [b for b in range(1, 200000) if divisor(b) != -(-b // 256)]
    check("divisor(band) = ceil(band/256)", not bad, f"{bad[:1]}")

    print("\n--- 4. 切り上げが唯一の範囲ガード ---")
    # 実際に出る band を集める: band = trunc(|v|·(ぼかし+1))、|v| は 65534.63..65536
    def vec(raw):
        t = raw * (math.pi / 1800)
        return math.trunc(math.sin(t) * 65536.0), math.trunc(math.cos(t) * -65536.0)

    bands = set()
    for raw in range(-36000, 36001, 149):
        n = math.hypot(*vec(raw))
        for b in list(range(0, 32)) + [100, 250, 500, 999, 1000, 1500, 1999, 2000]:
            bands.add(math.trunc(n * (b + 1)))
    over_ceil = [b for b in bands if c_div((b - 1) * 16, divisor(b)) > 4096]
    over_floor = [b for b in bands if b >= 256 and c_div((b - 1) * 16, b // 256) > 4096]
    check(f"実装(切り上げ)では {len(bands)} 通りの band すべてで添字 <= 4096",
          not over_ceil, f"{sorted(over_ceil)[:3]}")
    check(f"floor(band/256) で割っていたら {len(over_floor)} 通りが表からはみ出す",
          len(over_floor) > 0)
    if over_floor:
        b = min(over_floor)
        worst = max(c_div((x - 1) * 16, x // 256) for x in over_floor)
        print(f"  例: band={b} (45.0度・ぼかし=0) -> 添字 "
              f"{c_div((b - 1) * 16, b // 256)}、最悪 {worst}")
        print(f"  表の直後: 0x{TABLE_END:08x}=table[4096] の次は "
              f"{(SIN_TABLE - TABLE_END - 2) // 2} ワードのパディング、"
              f"その先が sin テーブル 0x{SIN_TABLE:08x}")
        check("最悪の添字でも .data の中なので落ちはしない(値が壊れるだけ)",
              img.valid(TABLE + 2 * worst, 2))
    check("実装の添字上限は 4095 ―― table[4096](= 完全不透明)には届かない",
          max(c_div((b - 1) * 16, divisor(b)) for b in bands) == 4095)
    print("  添字が 4096 に届かないのは実害ではない: m >= band の分岐が先に")
    print("  「触らない」を選ぶので、完全不透明側は表を引かずに表現されている。")

    print("\n--- 5. m*16 の int32 余裕 ---")
    band_max = math.trunc(65536.0 * (BLUR_RAW[1] + 1))
    product = 16 * (band_max - 1)
    check(f"最大 band = {band_max} (ぼかし=2000, 角度=0)、16·(band-1) = {product}",
          product < (1 << 31), f"INT32_MAX の {100 * product / (1 << 31):.1f}%")
    check("ぼかし の上限が 2048 だったら溢れていた",
          16 * (math.trunc(65536.0 * 2049) - 1) >= (1 << 31))

    print("\n--- 6. アルファは減る一方、色は触らない ---")
    bad = []
    for band in (65536, 65534, 131072, 655360):
        for m in range(-5, band + 5, max(1, band // 977)):
            for a in (0, 1, 2048, 4096):
                if ramp(a, m, band, table) > a:
                    bad.append((band, m, a))
    check("alpha' <= alpha が常に成り立つ", not bad, f"{bad[:1]}")
    check("m <= 0 は必ずアルファ0、m >= band は必ず素通し",
          ramp(4096, 0, 65536, table) == 0 and ramp(4096, 65536, 65536, table) == 4096)
    mono = all(ramp(4096, m, 65536, table) <= ramp(4096, m + 1, 65536, table)
               for m in range(-1, 65536))
    check("m について単調非減少(境界を跨いでも段差が逆転しない)", mono)

    print("\n  ぼかし ごとの階調(法線方向の距離 d [画素] に対する alpha 倍率、角度=0):")
    print(f"  {'d':>7}" + "".join(f"{f'ぼかし={b}':>12}" for b in (0, 1, 4)))
    for d in (-2.0, -1.0, -0.5, -0.25, 0.0, 0.25, 0.5, 1.0, 2.0):
        row = f"  {d:>7.2f}"
        for b in (0, 1, 4):
            band = 65536 * (b + 1)
            m = int(d * 65536) + band // 2          # 幅=0 の m = s + band/2
            row += f"{ramp(4096, m, band, table) / 4096:>12.4f}"
        print(row)
    print("  d は直線からの符号付き距離(正 = 残る側)。ぼかし=0 でも ±0.5 画素の")
    print("  階調があり、ぼかし=4 では ±2.5 画素にわたって滑らかに落ちる。")

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
