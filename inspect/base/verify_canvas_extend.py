"""領域拡張 (0x10006c20, 1047 bytes) ―― キャンバス拡張の「方式E」を検算する。

`inspect/common/canvas_growth.md` は3つの拡張方式(A: ワーカー自身が枠外に
書く / B: table で事前に広げる / C: オフスクリーン描画)を整理しているが、
`領域拡張` はそのどれとも違う**4本の独立したマージン(上下左右)を、既存の
`table[0x44]`(矩形転送)1回で丸ごと反映する**方式で、このスクリプトが
拡張候補として提出する「方式E」にあたる。

処理順序:

    1. 上下左右のトラックバー値をキャンバス最大サイズでクランプ
       (`inspect/common/canvas_growth.md` §1 の 0x10196748/0x101920e0)。
       ―― 左が右より先、上が下より先という**非対称な優先順位**がある
       (シャドーの「オフセットが先に食う」と同じ発想。
       canvas_growth.md §2 末尾)。
    2. `table[0x44](B, left, top, A, 0, 0, w, h, 0, 0x13000003)` で
       元画像をそのまま新しい位置へ転送し、A/B(`*(fpip+0xAC)`/`+0xB0`)を
       swap。
    3a. `塗りつぶし` ON: 上下左右の新しいマージンに**端の行/列を複製**して
        埋める(内側から外側へコピー)。
    3b. `塗りつぶし` OFF(既定): `table[0x48]`(矩形クリア、mode=2)を
        4本のマージン帯にそれぞれ呼んで**透明にクリア**する
        (「クリアされない」ではない ―― 単に色が違うだけ)。
    4. `*(fpip+0xB4)`/`+0xB8` を新サイズに、`*(fpip+0xD4)`/`+0xD8`
       (オブジェクト中心のずれ、単位 1/4096 画素)を
       `(left-right)/2` 画素・`(top-bottom)/2` 画素ぶん更新。

§4 の `<<0xb`(=×2048)は、"中心のずれ" は "半分の画素" を 1/4096 単位で
表すので `(left-right) * 4096 / 2 = (left-right) * 2048` になる ――
`閃光`/`シャドー` に次いでこの 1/4096 画素という単位を裏付ける3例目
(`inspect/common/canvas_growth.md` §8)。

Run via main.py:
    uv run main.py inspect/base/verify_canvas_extend.py
"""

from tools.disasm import dump_range
from tools.pe_image import PEImage

FUNC = (0x10006C20, 0x417)

ANNOT = {
    0x10006c38: "ecx = fp->track[1] = 下",
    0x10006c3b: "ebp = fp->track[2] = 左",
    0x10006c3e: "edx = fp->track[3] = 右",
    0x10006c41: "esi = fp->track[0] = 上",
    0x10006c32: "edi = fpip->w (+0xB4)",
    0x10006c43: "eax = fpip->h (+0xB8)",
    0x10006c4d: "ecx = max_w グローバル (canvas_growth.md §1)",
    0x10006c5e: "w+左 と max_w を比較 ―― 左を先にクランプ",
    0x10006c6a: "左 = max_w - w  (左だけで既に上限に達していた場合)",
    0x10006c76: "(左 確定後の) w+左+右 と max_w を比較 ―― 右は左のあとで削られる",
    0x10006c82: "ecx = max_h グローバル",
    0x10006c8b: "h+上 と max_h を比較 ―― 上を先にクランプ",
    0x10006ca1: "(上 確定後の) h+上+下 と max_h を比較 ―― 下は上のあとで削られる",
    0x10006cd1: "call [fp+0x64+0x44] = table[0x44]: 矩形転送(canvas_growth.md 全域)",
    0x10006cde: "check[0] = 塗りつぶし。0 なら 0x10006f01 へ(クリア分岐)",
    0x10006f01: "塗りつぶし OFF: 以下 table[0x48](矩形クリア, mode=2) を4本のマージン帯に",
    0x10006fd8: "*(fpip+0xAC) <-> *(fpip+0xB0) の swap(方式Aと同じ後始末)",
    0x10006ff8: "*(fpip+0xB4) = w + 左 + 右 (新しい幅)",
    0x1000700d: "*(fpip+0xD4) += (左-右) << 11   = (左-右)/2 画素 を Q12(1/4096画素)で",
    0x1000701c: "*(fpip+0xB8) = h + 上 + 下 (新しい高さ)",
    0x10007026: "*(fpip+0xD8) += (上-下) << 11   = (上-下)/2 画素 を Q12 で",
}


def clamp_margins(top: int, bottom: int, left: int, right: int, w: int, h: int,
                   max_w: int, max_h: int) -> tuple[int, int, int, int]:
    """0x10006c4d-0x10006ca9 の直訳。左/上が右/下より先にクランプされる。"""
    if w + left > max_w:
        left = max_w - w
    if w + left + right > max_w:
        right = max_w - w - left
    if h + top > max_h:
        top = max_h - h
    if h + top + bottom > max_h:
        bottom = max_h - h - top
    return top, bottom, left, right


def center_shift_q12(left: int, right: int, top: int, bottom: int) -> tuple[int, int]:
    return (left - right) << 11, (top - bottom) << 11


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_range(img, *FUNC, "領域拡張 0x10006c20", annotations=ANNOT, mnemonic_width=9)

    print("\n--- verify: 非対称クランプ(左/上が右/下より優先) ---")
    # 左だけで上限を使い切ると、右は 0 まで削られる。
    top, bottom, left, right = clamp_margins(top=0, bottom=0, left=5000, right=5000,
                                              w=100, h=100, max_w=4096, max_h=4096)
    print(f"  w=100,左=5000,右=5000,max_w=4096 -> 左={left} 右={right}")
    assert left == 4096 - 100 and right == 0, "左が優先的にクランプ枠を使い切る"

    top, bottom, left, right = clamp_margins(top=5000, bottom=5000, left=0, right=0,
                                              w=100, h=100, max_w=4096, max_h=4096)
    print(f"  h=100,上=5000,下=5000,max_h=4096 -> 上={top} 下={bottom}")
    assert top == 4096 - 100 and bottom == 0, "上が優先的にクランプ枠を使い切る"

    print("\n--- verify: 中心オフセットは (左-右)/2, (上-下)/2 画素を Q12 で ---")
    for left, right, top, bottom in ((10, 0, 0, 0), (0, 10, 0, 0), (7, 3, 5, 1)):
        dx_q12, dy_q12 = center_shift_q12(left, right, top, bottom)
        print(f"  左={left} 右={right} 上={top} 下={bottom} "
              f"-> Δcenter_x={dx_q12/4096:+.3f}px  Δcenter_y={dy_q12/4096:+.3f}px")
        assert dx_q12 / 4096 == (left - right) / 2
        assert dy_q12 / 4096 == (top - bottom) / 2

    print("""
まとめ:

  * `table[0x44]`/`table[0x48]` の再利用は canvas_growth.md の語彙(方式A〜D)
    にそのまま乗る ―― `領域拡張` は「4本の独立したマージンを1回の転送で
    片付ける」という、まだ無かった使い方(方式E、canvas_growth.md §7)。
  * 塗りつぶし ON/OFF は「新しい余白を端の色で埋めるか、透明にクリアするか」
    の選択であって、「クリアするかしないか」ではない ―― 2択とも必ず
    どちらかの処理が走る。
  * `+0xD4`/`+0xD8` への `<<0xb`(×2048)は、これらのフィールドが
    1/4096画素単位であるという `閃光` README の「推定」を裏付ける2件目の
    実例。
""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
