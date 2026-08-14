"""func_proc (0x10090490) の全命令に注釈を付ける ―― 進捗ランプ・3つの出口・
パターン分岐・ぼかし・最終合成の骨格をここで確定する。

`フェード` と骨格はそっくりだが3点違う:

  1. `t` の式に `fpip+0x118`(サブオブジェクト遅延)が乗らない
     (`t = fpip+0xA8 - fp+0x118` だけ)。
  2. 出した `progress` を**そのまま画素に掛ける**のではなく、`ex_data` の
     パターン種別ごとの生成関数(ワーカー)に食わせて 0/gradient/0x1000 の
     マスクを作り、それを対象画像のアルファに掛ける。
  3. `反転(イン)`/`反転(アウト)` チェックボックスの値が、①`progress` の
     符号反転(`g = 0x1000-g`)と②各パターンワーカー内の比較演算子の入れ替え
     の**両方**に効く。同じグローバル `[0x1024e0b0]` を2箇所が読むので、
     チェックを入れると「進む向き」と「どちら側が見えるか」が同時に変わる。

Run via main.py:
    uv run main.py inspect/wipe/disasm_params.py
"""

from tools.disasm import dump_range
from tools.pe_image import PEImage

FUNC_PROC = (0x10090490, 0x1AF)  # 0x10090490 .. 0x1009063e (ret)

ANNOTATIONS = {
    0x1009049d: "eax = fp->track[2] ... 実際は次の mov で ebp に既定値0x1000を積むほう",
    0x100904a0: "ebp = g = 0x1000  (フェードの g と同じ役: 4096 = フルオープン)",
    0x100904a5: "g_1024df80 = 0x1000  (進捗の既定値。ワーカー全員がここを読む)",
    0x100904ab: "g_1024e0b0 = 0  (反転フラグの既定値)",
    0x100904c1: "ebx = fp->track[]  (esi+0x44 は filter_registration.md #4 の track ポインタ)",
    0x100904ce: "track[0] = イン (生値, 0..1000)",
    0x100904d4: "sub_10091ad8 = _ftol。in_frames = trunc(イン*rate/(scale*100))  (object_time.md #4 と同型)",
    0x100904d9: "track[1] = アウト (生値, 0..1000)",
    0x100904e4: "out_frames = trunc(アウト*rate/(scale*100))",
    0x100904e9: "edx = fp->0x118  (オブジェクト全体の開始フレーム)",
    0x100904f1: "eax = fpip->0xA8  (現在の絶対フレーム)",
    0x100904f7: "t = 現在 - 開始。fpip->0x118(サブオブジェクト遅延)は引かない ―― フェードと違う点1",
    0x10090503: "t >= in_frames なら『イン』ランプは無効 (g は既定 0x1000 のまま)",
    0x1009050d: "a = ((t+1) << 12) / (in_frames + 1)   (フェードの分子・分母 +1 と同じ式)",
    0x10090511: "a >= 4096 なら効果なし (フェード同様、実際には到達しない死んだガード)",
    0x10090513: "g = a",
    0x1009051b: "edx = fp->check[]  (esi+0x48)",
    0x1009051e: "check[0] = 反転(イン)",
    0x10090520: "g_1024e0b0 = 反転(イン) の値  ―― この後ワーカーが読む『反転フラグ』",
    0x10090525: "u = fp->0x11C(全体終了フレーム) - fpip->0xA8(現在)",
    0x10090541: "g がすでに『アウト』ランプの値以下なら上書きしない (2本のランプの min)",
    0x10090543: "g = a  (アウト側が勝った)",
    0x1009054b: "edx = fp->check[]",
    0x1009054e: "check[1] = 反転(アウト)",
    0x10090551: "g_1024e0b0 = 反転(アウト) の値 に差し替え ―― 勝ったランプの反転チェックだけが効く",
    0x1009055d: "g >= 0x1000  -> return 1  (出口1: 何もせず全域不透明のまま)",
    0x10090565: "g > 0 か? (0 以下なら出口2)",
    0x1009056a: "出口2: g <= 0  -> return 0  (フェード/グローと同じ『描画自体をやめる』系統)",
    0x10090574: "g_1024e0b0 (勝った側の反転チェック) を読み直す",
    0x10090576: "反転していなければ progress の符号反転はスキップ",
    0x1009057d: "g = 0x1000 - g  ―― 反転①: 時間方向を裏返す",
    0x10090581: "g_1024df80 に書き戻す (以後ワーカーが読むのはこの値)",
    0x10090587: "ecx = fp->ex_data_ptr  (esi+0x4c)",
    0x1009058b: "dl = ex_data+4 の先頭バイト = カスタムパターン名の先頭文字",
    0x10090593: "空文字列 (先頭が0) なら組み込みパターン経路へ",
    0x10090595: "ecx = fp->track[]",
    0x1009059b: "edx = track[2] = ぼかし (生値 0..100)",
    0x100905a0: "sub_10091100(progress, ぼかし, fp, fpip, ex_data+4) ―― カスタムPNGパターン一括処理。戻ったら return 1",
    0x100905b3: "eax = ex_data[0]  (組み込みパターン種別、既定0=円)",
    0x100905b6: "== 1 ? -> 四角(0x10090c00)",
    0x100905bc: "eax = fp->exfunc  (esi+0x60)",
    0x100905c4: "call [eax+0xcc] = EXFUNC::exec_multi_thread_func(四角のワーカー, fp, fpip)  cdecl(呼び出し側が畳む)",
    0x100905cc: "== 2 ? -> 時計(0x10090a60)",
    0x100905d8: "== 3 ? -> 横(0x10090ec0)",
    0x100905ed: "== 4 ? -> 縦(0x10090f90)",
    0x10090602: "それ以外(既定0を含む) -> 円(0x10090d50)",
    0x10090610: "edx = fp->track[]",
    0x10090613: "add esp,0xc ―― 直前の3プッシュ(worker,fp,fpip)をここでまとめて畳む(cdecl)",
    0x10090616: "eax = track[2] = ぼかし",
    0x1009061c: "sub_10090640(fp, fpip, ぼかし) ―― ぼかし>0ならパターンのアルファ面(fpip+0xB0)を箱ぼかし",
    0x10090621: "ecx = fp->exfunc",
    0x1009062b: "exec_multi_thread_func(sub_10091050, fp, fpip) ―― 最終合成: objAlpha *= patternAlpha >> 12",
    0x10090637: "return 1",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_range(img, *FUNC_PROC, label="func_proc 0x10090490", annotations=ANNOTATIONS)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
