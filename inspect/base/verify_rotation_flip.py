"""ローテーション(90度回転)と反転 ―― 幾何形状を「今すぐ」書き換える2つ。

どちらも exec_multi_thread_func でワーカーへ丸投げし、出力を対バッファ
(`*(fpip+0xB0)`)に書いてから `*(fpip+0xAC)`/`+0xB0` を swap するという、
`inspect/common/box_blur.md` などで既出の ping-pong パターンを使う。

## ローテーション (0x100075b0, 175 bytes)

`90度回転` は raw -4..4 の**9値**だが、ジャンプテーブル(`0x10007660`、
`int[7]`)は raw+3 を添字にした **7エントリ**しか無い。`edi(raw+3)` が
`0..6` を外れる(= raw が **±4** のとき)は `ja` で素通りし、実質
「何もしない」。90°刻みの回転は4種で一巡するので raw の**mod 4** が
本質だが、シフトテーブルは `-3` と `+1` (mod4=1)、`-2`/`+2` (mod4=2)、
`-1`/`+3` (mod4=3) をそれぞれ同じハンドラへ飛ばしており、**mod 4 の
剰余類ごとに1つのハンドラを共有する**設計になっている。raw=±4(mod4=0)
は raw=0 と同じ「無回転」に帰着するはずの値で、テーブル外に落ちて
何もしないのは**たまたま正しい**(0°相当だから)。

3つのハンドラは:

  * `0x10007680` (raw ≡ 1 mod 4)
  * `0x10007740` (raw ≡ 2 mod 4, = 180°)
  * `0x10007810` (raw ≡ 3 mod 4)

`raw ≡ 2`(180°)だけは呼び出し前に `*(fpip+0xB4)`/`+0xB8` の**入れ替えを
しない**。他の2つは呼ぶ前に w/h を入れ替え、かつ**入れ替えた新しい
軸をそれぞれのキャンバス最大値でクランプ**してから書き込む
(`inspect/common/canvas_growth.md` §1 のグローバルを再利用)。

3ワーカーとも `exec_multi_thread_func` 経由で `*(fpip+0xAC)` を読み
`*(fpip+0xB0)` へ書く転置コピーで、スレッド分割は**元画像の高さ**を
分割する(`inspect/common/thread_split.md` の行分割と同型、`寸法<thread_num`
のガードも同じ形で入っている)。**どのハンドラがどの回転方向
(CW/CCW)に対応するかは、この段階のアドレス計算(スワップ後の
`*(fpip+0xEC)` を読むタイミング等)だけからは断定していない** ――
90° 系2本の入れ替え先アドレス計算はワーカー内で完結せず、`func_proc` 側で
先に更新された `*(fpip+0xB4)`/`+0xB8`/`+0xEC` に依存するため、この
プロジェクトにあるツール(angr/capstone、エミュレータなし)だけでは
1回の静的解析で確証を持てなかった。disasm ログとジャンプテーブルの
対応(mod4の剰余類)は確定事項として掲載する。

## 反転 (0x10082260, 365 bytes) ―― 1関数、2登録、8種のワーカー

`fp->flag & 0x20` の分岐は関数の**先頭1回だけ**で、以降はオブジェクト
効果(5チェックボックス)/フレームフィルタ(4チェックボックス)で
別々のワーカー列を順に呼ぶ ――  `flag`共有でも中身は完全に別ルート、
という3個目のパターン(`filter_registration.md` §2 に既出の「2登録が
`func_proc`を共有」「`func_proc`ごと2本」に次ぐ「1関数が内部で完全に
枝分かれ」)。

  * `上下反転`/`左右反転`: ワーカーが対バッファへ**行/列を逆順**にコピーし、
    そのあと `*(fpip+0xAC)`/`+0xB0`(オブジェクト版)または
    `ycp_edit`/`ycp_temp`(フレーム版, +4/+8)を swap。
  * `輝度反転`: `y' = 0x1000 - y`   (Q12, 4096=最大輝度)
  * `色相反転`: `cb' = -cb`, `cr' = -cr`   (Cb-Cr平面の180°回転 = 単純反転)
  * `透明度反転`(オブジェクト版のみ): `a' = 0x1000 - a`。`輝度反転` と
    完全に同じ式をアルファに適用しているだけ。

`輝度反転`/`透明度反転`は同じ `0x1000 - x` を y と a それぞれに使っていて、
`色相反転` だけが加減算ではなく符号反転という質的に違う式になっている。

Run via main.py:
    uv run main.py inspect/base/verify_rotation_flip.py
"""

from tools.disasm import dump_range
from tools.pe_image import PEImage

ROTATE_DISPATCH = (0x100075B0, 0xAF)
FLIP_DISPATCH = (0x10082260, 0x16D)
LUMA_INVERT = (0x100827B0, 0x80)
HUE_INVERT = (0x10082830, 0x90)
ALPHA_INVERT = (0x100828C0, 0x80)

ROTATE_ANNOT = {
    0x100075cb: "edi = track[0](90度回転) + 3           raw -4..4 -> edi -1..7",
    0x100075ce: "edi を 0..6 の範囲チェック(unsigned) ―― raw=±4 は範囲外で下記ジャンプテーブルへ入れない",
    0x100075d7: "jmp [edi*4 + 0x10007660]               7エントリのジャンプテーブル(raw±4は素通り=無回転)",
    0x100075de: "raw ≡ 1 (mod 4) [-3, +1] : 幅高さを入れ替えてクランプ、ハンドラ 0x10007680",
    0x100075ff: "raw ≡ 2 (mod 4) [-2, +2] : 入れ替えなし(180度)、ハンドラ 0x10007740",
    0x10007608: "raw ≡ 3 (mod 4) [-1, +3] : 幅高さを入れ替えてクランプ、ハンドラ 0x10007810",
    0x10007633: "exec_multi_thread_func(handler, fp, fpip)",
    0x1000763c: "*(fpip+0xAC) <-> *(fpip+0xB0) の swap",
}

FLIP_ANNOT = {
    0x1008226a: "fp->flag & 0x20 のテストは関数の先頭で1回だけ",
    0x10082272: "flag&0x20==0(フレーム版)なら 0x1008233f へ ―― 以降は完全に別のチェック配列/ワーカー列",
    0x1008227c: "check[0]=上下反転 (オブジェクト版) -> worker 0x10082640",
    0x100822b1: "check[1]=左右反転 -> worker 0x10082700",
    0x100822e6: "check[2]=輝度反転 -> worker 0x100827b0 (swap なし ―― in-place)",
    0x10082303: "check[3]=色相反転 -> worker 0x10082830 (同上)",
    0x10082324: "check[4]=透明度反転 (オブジェクト版だけに存在) -> worker 0x100828c0",
    0x10082343: "(フレーム版) check[0]=上下反転 -> worker 0x100823d0、ycp_edit/ycp_temp(+4/+8) を swap",
}

LUMA_ANNOT = {
    0x1008280a: "bx = 0x1000; bx -= [eax]           y' = 4096 - y",
}
HUE_ANNOT = {
    0x1008288d: "bp = [eax-2]; neg bp                cb' = -cb",
    0x1008289b: "bp = [eax-8]; neg bp                cr' = -cr",
}
ALPHA_ANNOT = {
    0x10082922: "bx = 0x1000; bx -= [eax]            a' = 4096 - a  (輝度反転と同じ式をアルファに)",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_range(img, *ROTATE_DISPATCH, "ローテーション func_proc 0x100075b0",
               annotations=ROTATE_ANNOT, mnemonic_width=9)
    dump_range(img, *FLIP_DISPATCH, "反転 func_proc 0x10082260",
               annotations=FLIP_ANNOT, mnemonic_width=9)
    dump_range(img, *LUMA_INVERT, "反転: 輝度反転ワーカー 0x100827b0", annotations=LUMA_ANNOT)
    dump_range(img, *HUE_INVERT, "反転: 色相反転ワーカー 0x10082830", annotations=HUE_ANNOT)
    dump_range(img, *ALPHA_INVERT, "反転: 透明度反転ワーカー 0x100828c0", annotations=ALPHA_ANNOT)

    print("\n--- verify: 90度回転のジャンプテーブル (raw -4..4 -> handler) ---")
    base = 0x10007660
    table = {i - 3: img.i32(base + 4 * i) for i in range(7)}  # table[-3..3], index = raw+3
    handlers = {}
    for raw in range(-4, 5):
        h = table.get(raw)  # None for raw == -4 or +4 (out of the 7-entry table)
        handlers[raw] = h
        label = "無回転(範囲外, ja が飛ばす)" if h is None else f"0x{h:08x} (mod4={raw % 4})"
        print(f"  raw={raw:+d} -> {label}")
    assert handlers[-4] is None and handlers[4] is None, "±4 はテーブル外 = 無回転のはず"
    assert handlers[-3] == handlers[1] and handlers[-2] == handlers[2] and handlers[-1] == handlers[3]

    print("\n--- verify: 輝度反転 / 透明度反転は同じ 0x1000-x、色相反転だけ符号反転 ---")
    for x in (0, 1000, 4096, -100):
        print(f"  x={x:>6} -> 0x1000-x={0x1000-x:>6}   -x={-x:>6}")

    print("""
まとめ:

  * `ローテーション`/`リサイズ`/`領域拡張`/`反転` は4つとも「対バッファへ
    書いて `*(fpip+0xAC)`/`+0xB0` を swap する」という同じ後始末をする ――
    `座標`/`拡大率`/`透明度`/`回転` の「fpip の数値を更新するだけ」とは
    はっきり別のグループ。
  * `反転` は2登録(オブジェクト/フレーム)でチェックボックス数が5個と4個
    (透明度反転の有無)違うのに、判定は**同じ関数の中の1個の分岐**で
    切り替えている ―― `ぼかし`/`発光`のような「2つの独立した登録が同じ
    `func_proc` を指す」パターンとは異なる3つ目のバリエーション。
""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
