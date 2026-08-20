"""リサイズ (0x100071c0, 765 bytes) ―― 唯一「今すぐ」効くフィルタの1つ。

`座標`/`拡大率`/`透明度`/`回転` と違って、リサイズは fpip+0xE0/+0xE4 のような
遅延蓄積フィールドを一切読み書きしない。その場で `*(fpip+0xB4)`/`+0xB8`
(画像サイズ)を書き換え、AviUtl のホスト関数(`補間あり`, 既定)か
exedit 自前のワーカー(`補間なし`)のどちらかで実際にリサンプルする ――
`領域拡張`/`ローテーション`/`反転` と同じ「即時系」グループに入る。

## モード

  * **比率モード(既定)**: `拡大率`/`X`/`Y` は現在の `*(fpip+0xB4)`/`+0xB8` に
    掛かる百分率。3本とも `raw==10000`(100%)ならスキップ ―― `拡大率` の
    3本と同じ発想。掛けるたびに `+0.5` してから `_ftol` する
    (四捨五入寄り。`拡大率` 本体の 0方向切り捨てとは丸め方が違う)。
  * **`ドット数でサイズ指定`(check[1])**: `X`/`Y` は百分率ではなく**そのまま
    ドット数**になる。ただし raw は `scale=100` のトラックバーなので、
    実際に使う前に**マジック定数 `0x51eb851f`(シフト5) で /100** される
    ―― `param_scaling.md` 既出の `0x10624dd3`(/1000)/`0x68db8bad` とは
    別口の、この関数で初めて出てくる定数。

## 最大キャンバスサイズへのクランプ ―― モードで挙動が違う

  * 比率モード: `max_h*元w` と `max_w*元h` を比較して**先に食う軸**を選び、
    その軸を `max` に固定して**もう一方を新しい目標アスペクト比
    (`新w:新h`)で再計算**する ―― アスペクト比を保つ。
  * ドット数モード: `新w` を `max_w` に、`新h` を `max_h` に**それぞれ独立に**
    クランプする ―― アスペクト比は保たれない。

## サイズが変わらない/0以下になったときの2つの早期リターン

  * 新サイズが現在の `*(fpip+0xB4)`/`+0xB8` と一致するなら、何もせず `return 1`。
  * 新しい `w`/`h` のどちらかが `<= 0` なら `return 0`(`フェード` と同じ、
    そのオブジェクトはこの回、描画パイプラインから外れる)。

## `補間なし` は exedit 自前、既定(補間あり)は AviUtl 側に丸投げ

`check[0]`(`補間なし`)が立っているときだけ exedit は自前のワーカー
(`0x100074c0`)を `exec_multi_thread_func` 経由で走らせる。中身は
`src_x = x*旧w/新w`・`src_y = y*旧h/新h` という素朴な最近傍サンプリング。
既定(`補間なし` オフ)は代わりに `fp->exfunc`(`[fp+0x60]`)経由で AviUtl
本体の関数を2つ(`+0x48`/`+0x58`)呼ぶ ―― 補間アルゴリズムそのものは
`exedit.auf` の外にあるので、`rgb_ycbcr.md` §3 の YCbCr→RGB 変換と同じ扱いで
範囲外とする。

Run via main.py:
    uv run main.py inspect/base/verify_resize.py
"""

from tools.cints import divisor_of, msvc_div
from tools.disasm import dump_range
from tools.pe_image import PEImage

FUNC = (0x100071C0, 0x2FD)
MAGIC_100 = 0x51EB851F  # divide by 100, shift 5 — new to this project (param_scaling.md only had /1000, /250)

ANNOT = {
    0x100071cf: "ebx = fpip->w (+0xB4)。以下2行でグローバル [0x100d7524]/[0x100d7520] に退避",
    0x100071f2: "eax = fp->track[0] = 拡大率。== 10000(100%) ならこの軸をスキップ",
    0x10007210: "fadd 0.5   ―― 四捨五入寄りの丸め(拡大率フィルタの0方向切り捨てと対照的)",
    0x10007240: "ecx=max_w, eax=max_h*旧w, edx=max_w*旧h  ―― どちらの軸が先に頭打ちになるか比較",
    0x1000725d: "新w が max_w を超えていたら、新h の方を新しい目標比で再計算",
    0x10007280: "(逆側) 新h が max_h を超えていたら、新w を再計算",
    0x100072b8: "eax = fp->check[1] = ドット数でサイズ指定",
    0x100072c2: "0x51eb851f: X を /100 するマジック乗算(この関数だけの定数)",
    0x100072d5: "ドット数モードは新wをmax_wへ、新hをmax_hへ独立にクランプ(アスペクト比を保たない)",
    0x1000735c: "新w<=0 または 新h<=0 なら return 0(フェードと同じ「描画しない」終了)",
    0x1000736c: "現在の w/h と一致するなら何もせず return 1",
    0x10007387: "check[0] = 補間なし。0(既定)なら 0x100073d0 (AviUtl 側の補間つきリサイズ) へ",
    0x1000738c: "補間なし ON: exedit 自前のワーカー 0x100074c0 を exec_multi_thread_func で",
    0x100073ea: "call [exfunc+0x48]  ―― AviUtl 側の関数その1(補間つき経路、既定)",
    0x1000747c: "call [exfunc+0x58]  ―― AviUtl 側の関数その2(同上)",
}


def divide_by_100(x: int) -> int:
    return msvc_div(x, MAGIC_100, 5)


def aspect_preserving_clamp(new_w: int, new_h: int, old_w: int, old_h: int,
                             max_w: int, max_h: int) -> tuple[int, int]:
    """0x10007240-0x100072b1 の直訳(比率モード側)。"""
    if max_h * old_w <= max_w * old_h:
        if new_w > max_w:
            new_h = round(max_w * new_h / new_w)  # _ftol: toward zero, but max_w*new_h/new_w >= 0 here
            new_w = max_w
    else:
        if new_h > max_h:
            new_w = round(max_h * new_w / new_h)
            new_h = max_h
    return new_w, new_h


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_range(img, *FUNC, "リサイズ 0x100071c0", annotations=ANNOT, mnemonic_width=9)

    print(f"\n--- verify: 0x{MAGIC_100:08x} (shift 5) is /100 ---")
    d = divisor_of(MAGIC_100, 5)
    print(f"  divisor_of(0x{MAGIC_100:08x}, 5) = {d}")
    assert d == 100
    for x in (0, 1, 99, 100, 250, 5000, -1, -100, -250):
        print(f"  divide_by_100({x:>6}) = {divide_by_100(x)}")

    print("\n--- verify: アスペクト比を保つクランプ(比率モード) ---")
    # 正方形の元画像を横に広げようとして max_w に頭打ちになるケース
    w, h = aspect_preserving_clamp(new_w=8000, new_h=4000, old_w=100, old_h=100,
                                    max_w=4096, max_h=4096)
    print(f"  旧100x100, 目標8000x4000, 最大4096x4096 -> {w}x{h}")
    assert w == 4096 and h == round(4096 * 4000 / 8000) == 2048

    print("\n--- verify: ドット数モードは軸ごと独立にクランプ ---")
    dot_w, dot_h = min(9000, 4096), min(500, 4096)
    print(f"  目標9000x500, 最大4096x4096 -> {dot_w}x{dot_h}  (アスペクト比は保たれない)")

    print("""
まとめ:

  * `拡大率`/`座標`/`回転`/`透明度` の4つは exec_multi_thread_func を呼ばず
    fpip の状態だけを更新するのに対し、`リサイズ` は毎回その場でピクセルを
    再サンプルする。`標準描画`/`拡張描画` 自身の `拡大率` トラックバーは
    前者(fpip+0xE0/+0xE4 蓄積)側であり、リサイズフィルタとは**別系統**。
  * 「サイズが変わらなければ丸ごとスキップ」「0以下になったら return 0」の
    2段ガードがあるぶん、`拡大率`/`透明度` にある「100%ならスキップ」より
    早期リターンの種類が多い。
""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
