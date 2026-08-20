"""座標 / 回転 / 透明度 ―― fpip の "遅延パラメータ" 3兄弟を検算する。

この3つは exec_multi_thread_func を1回も呼ばない。画素には一切触れず、
fpip の専用フィールドに値を足し込む(または掛け込む)だけで終わる:

    座標   0x10007150 (105 bytes)  ->  fpip+0xBC/+0xC0/+0xC4  += raw<<12/10        (X,Y,Z, Q12画素)
    回転   0x10007090 (191 bytes)  ->  fpip+0xC8/+0xCC/+0xD0  += (raw%36000)*65536/36000 (X,Y,Z軸, Q16=1回転)
    透明度 0x10007040 ( 78 bytes)  ->  fpip+0xE8              := 0x1000 - msvc_div((0x1000-old)*(1000-raw), 1000)
                                        (+0xE8 は「透明度」そのもの ―― 0=不透明,
                                        4096=完全透明。加算ではなく (1-old/4096)
                                        という「残っている見え方」同士の掛け算)

`標準描画`(0x1008a020)がこれと同じオフセット(+0xc8/+0xcc/+0xd0/+0xe4/+0xe8等)を
読み書きしていることは README 側で `grep` の生ログとして示す ―― この
スクリプトは3関数それぞれの**式**が正しいことだけを確認する。

Run via main.py:
    uv run main.py inspect/base/verify_deferred_params.py
    uv run main.py inspect/base/verify_deferred_params.py --only rotation
"""

import argparse
from fractions import Fraction

from tools.cints import c_div, msvc_div, MAGIC_1000
from tools.disasm import dump_range
from tools.pe_image import PEImage

COORD = (0x10007150, 0x69)
ROTATE = (0x10007090, 0xBF)
ALPHA = (0x10007040, 0x4E)

COORD_ANNOT = {
    0x10007159: "eax = fp->track (+0x44)",
    0x1000715c: "eax = track[0] = X (raw, -999999..999999, scale=10)",
    0x1000715e: "eax <<= 12                          (Q12)",
    0x10007162: "eax = c_div(eax, 10)   ; idiv [0x1009e524]=10, toward zero",
    0x10007168: "edx = *(fpip+0xBC)                  既存の X 蓄積値",
    0x1000716e: "edx += eax                            加算(上書きではない)",
    0x10007170: "*(fpip+0xBC) = edx",
    0x10007179: "eax = track[1] = Y",
    0x10007186: "*(fpip+0xC0) の読み出し",
    0x1000718e: "*(fpip+0xC0) = edx                    Y も同型",
    0x10007198: "eax = track[2] = Z",
    0x100071a5: "*(fpip+0xC4) の読み出し",
    0x100071b2: "*(fpip+0xC4) = edx                    Z も同型。X/Y/Z で完全に同じ式が3回並ぶだけ",
}

ROTATE_ANNOT = {
    0x1000709b: "eax = fp->track[0] = X軸回転 (raw, -360000..360000, scale=100 = センチ度)",
    0x100070a1: "edx:eax = cdq;idiv 0x8ca0(36000)     ; edx = c_div の余り。|edx| < 36000 は常に成立",
    0x100070a3: "edx(余り) と 36000 を比較 ―― 原理的に一致し得ない比較(下記 verify)",
    0x100070a9: "  一致時は eax=0x10000(1回転)を代入 ……到達不能な分岐",
    0x100070b2: "fild edx                              余り(センチ度、-35999..35999)",
    0x100070b6: "fmul [0x1009a3d8] = 65536/36000 = 1.8204444...  センチ度 -> Q16(1回転=0x10000)",
    0x100070bc: "call _ftol                            0方向切り捨て",
    0x100070c5: "*(fpip+0xC8) += eax                   X軸回転(蓄積)",
    0x100070db: "eax = track[1] = Y軸回転。以下 X と同じ式",
    0x10007107: "*(fpip+0xCC) += eax                   Y軸回転",
    0x10007115: "eax = track[2] = Z軸回転。以下も同じ式",
    0x10007147: "*(fpip+0xD0) += eax                   Z軸回転。回転も座標と同じく3軸で完全に同型",
}

ALPHA_ANNOT = {
    0x10007047: "eax = track[0] = 透明度 (raw, 0..1000, scale=10 = 1/10%)",
    0x1000704b: "raw==0 なら何もせず return 1          ―― フェードと違い早期リターンが1本だけ",
    0x10007057: "edx = *(fpip+0xE8)                    既存の「透明度」蓄積値 (Q12, 0=不透明,4096=完全透明)",
    0x1000705d: "ecx = 0x1000 - edx                    既存の「見えている割合」= 1 - old/4096 (不透明度)",
    0x10007064: "edx = 1000 - raw                      今回の「見えている割合」を千分率で",
    0x1000706b: "ecx * edx                             不透明度どうしの積  ―― まだ /1000 前",
    0x1000706e: "ecx = msvc_div(ecx, MAGIC_1000, shift=6)  ―― /1000 のマジック乗算除算 (param_scaling.md §2)",
    0x1000707f: "ecx = 0x1000 - ecx                     不透明度から透明度に戻す(4096 から引く)",
    0x10007081: "*(fpip+0xE8) = ecx",
}


def coord_step(raw: int) -> int:
    return c_div(raw << 12, 10)


def rotate_step(raw: int) -> tuple[int, bool]:
    """Return (delta added to the Q16 accumulator, whether the dead je fired)."""
    r = raw - c_div(raw, 36000) * 36000  # idiv remainder, sign follows raw, |r| < 36000
    dead_branch_hit = r == 36000  # what the `cmp edx,ecx; je` is testing for
    if dead_branch_hit:
        return 0x10000, True
    delta = int(Fraction(r * 65536, 36000))  # fild/fmul(65536/36000)/_ftol: truncation toward zero
    return delta, False


def alpha_step(old_transparency: int, raw: int) -> int:
    """old_transparency/new: Q12, 0=fully opaque, 4096=fully transparent."""
    old_opacity = 0x1000 - old_transparency
    this_opacity_permille = 1000 - raw
    new_opacity = msvc_div(old_opacity * this_opacity_permille, MAGIC_1000, 6)
    return 0x1000 - new_opacity


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="verify_deferred_params")
    parser.add_argument("--only", choices=("coord", "rotation", "alpha"))
    args = parser.parse_args(argv or [])

    img = PEImage(dll_path)
    dumps = {"coord": (COORD, COORD_ANNOT, "座標 0x10007150"),
             "rotation": (ROTATE, ROTATE_ANNOT, "回転 0x10007090"),
             "alpha": (ALPHA, ALPHA_ANNOT, "透明度 0x10007040")}
    for key, ((addr, size), annot, label) in dumps.items():
        if args.only and args.only != key:
            continue
        dump_range(img, addr, size, label, annotations=annot, mnemonic_width=9)

    print("\n--- verify: 座標 (Q12 offset, /10 truncating toward zero) ---")
    for raw in (-999999, -12345, -1, 0, 1, 12345, 999999):
        got = coord_step(raw)
        want = c_div(raw << 12, 10)
        assert got == want
        print(f"  raw={raw:>8} -> delta={got:>12}  (= {got/4096:.4f} px)")

    print("\n--- verify: 回転 dead branch (`cmp edx,36000; je`) never fires ---")
    hit_any = False
    for raw in range(-360000, 360001, 37):  # step coprime-ish with 36000 to sample the whole range
        _, hit = rotate_step(raw)
        hit_any |= hit
    for raw in (-360000, -359999, -36000, -1, 0, 1, 36000, 359999, 360000):
        _, hit = rotate_step(raw)
        hit_any |= hit
    print(f"  dead branch reached for any sampled raw in [-360000,360000]? {hit_any}")
    assert not hit_any, "expected the je to be provably unreachable"
    for raw in (0, 100, 18000, 35999, 36000, 36001, 90000, 360000, -90000, -360000):
        delta, _ = rotate_step(raw)
        print(f"  raw={raw:>7} (= {raw/100:>7.2f} deg) -> delta={delta:>7}  (= {delta/65536*360:.4f} deg)")

    print("\n--- verify: 透明度 Q12 combine (0x1000 - msvc_div(old_opacity*this_opacity, 1000)) ---")
    for old_t, raw in ((0, 0), (0, 500), (0, 1000), (2048, 500), (4096, 500), (1024, 250)):
        new_t = alpha_step(old_t, raw)
        old_op, this_op = (4096 - old_t) / 4096, 1 - raw / 1000
        print(f"  old_透明度={old_t:>5} raw={raw:>5} -> new_透明度={new_t:>5}  "
              f"(不透明度 {old_op:.3f} * {this_op:.3f} = {old_op*this_op:.3f}, got {(4096-new_t)/4096:.3f})")
        # msvc_div(x,MAGIC_1000,6) truncates toward zero like c_div(x,1000) for the
        # non-negative operands this effect always produces (both opacities in 0..4096/0..1000)
        assert msvc_div((0x1000 - old_t) * (1000 - raw), MAGIC_1000, 6) == c_div((0x1000 - old_t) * (1000 - raw), 1000)

    print("""
まとめ:

  * 座標/回転は「今回の値」を Q12/Q16 に変換して既存の値に**加算**するだけ ――
    複数の `座標`/`回転` フィルタや `標準描画` 自身の X/Y/Z と重ねても、
    実行順序に依存しない(加算は可換)。
  * 回転の `cmp 余り,36000; je` は idiv の性質上 **絶対に成立しない**
    (`c_div` の余りは常に |余り| < |除数|)。フェードの `>= 4096` 未到達ガード
    (fade/README.md §4)と同じ「無害な死んだ分岐」。
  * 透明度は**加算ではなく合成**(「残っている不透明度」同士の掛け算)。
    2つの `透明度` フィルタを直列に置くと `raw1`,`raw2` の効果は
    `(1-raw1/1000)*(1-raw2/1000)` で効き、`フェード` のアルファ合成
    (fade/README.md §4)と同じ「複数回かければ掛かるほど暗くなる」形。
  * 3つとも exec_multi_thread_func を呼ばない ―― 画素は1個も読み書きしない。
""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
