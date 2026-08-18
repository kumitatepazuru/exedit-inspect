"""`方向ブラー` の `func_proc` 2本とワーカー3本の全命令に注釈を付けて出力する。

  §1 オブジェクト版 `func_proc`(0x1000c200)
       角度 → Q16 ベクトル → 拡張矩形 → 上限で削る → サンプル数と歩幅の
       4分岐 → 描画品質のクランプ → `サイズ固定` でワーカーを選ぶ
  §2 `サイズ固定` OFF のワーカー(0x1000c4a0)
       ±N·v の 2N+1 サンプルを取り、アルファを**カーネル幅 2N+1** で割る
  §3 `サイズ固定` ON のワーカー(0x1000c720)
       同じ形だが、枠内に落ちたサンプルの**個数**で割る(差はここだけ)
  §4 フレーム版 `func_proc`(0x1000c9b0)とワーカー(0x1000cb10)
       キャンバスの矩形計算が丸ごと無い。除数は生存サンプル数
  §5 参照する定数

Run via main.py:
    uv run main.py inspect/directional_blur/disasm_params.py
"""

from tools.disasm import dump_range
from tools.pe_image import PEImage

FUNC_PROC_OBJ = 0x1000C200
WORKER_GROW = 0x1000C4A0
WORKER_FIXED = 0x1000C720
FUNC_PROC_FRAME = 0x1000C9B0
WORKER_FRAME = 0x1000CB10

NOTES = {
    # --- §1 func_proc (object) ---------------------------------------------
    0x1000C206: "fp->track (+0x44)",
    0x1000C209: "esi = track[0] = 範囲(以降 N として使い回される)",
    0x1000C20D: "範囲 == 0 なら何もせず return 1",
    0x1000C213: "g_e0 = 範囲",
    0x1000C21E: "track[1] = 角度 の生値(1/10 度単位)",
    0x1000C221: "+pi/1800 ―― angle_vector.md §1 の定型",
    0x1000C229: "sin 側に **-65536.0** ―― 凸エッジ / フレームバッファ と同じ符号系",
    0x1000C22F: "_ftol(0方向切り捨て)",
    0x1000C236: "g_cc = vx = trunc(sin(θ)·(-65536))",
    0x1000C24A: "cos 側は +65536.0",
    0x1000C25D: "g_d0 = vy = trunc(cos(θ)·65536)",
    0x1000C267: "g_e4 = y0 = -範囲",
    0x1000C26C: "g_dc = x0 = -範囲",
    0x1000C27C: "g_d4 = x1 = w + 範囲  ―― 角度によらず四方に 範囲 画素ずつ広げる",
    0x1000C293: "g_d8 = y1 = h + 範囲",
    0x1000C289: "最大キャンバス幅 0x10196748",
    0x1000C29B: "上限を超える間、左右から1画素ずつ対称に削る",
    0x1000C2C1: "同じことを縦に(最大キャンバス高 0x101920e0)",
    0x1000C2E4: "ここからサンプル数 N と歩幅 v の付け替え4分岐",
    0x1000C2E7: "範囲 < 16 → v /= 4, N *= 4",
    0x1000C309: "範囲 < 32 → v /= 2, N *= 2",
    0x1000C325: "範囲 <= 128 → 何もしない(32..128 はそのまま)",
    0x1000C332: "範囲 > 128 → v = v·範囲/128, N = 128",
    0x1000C34C: "g_cc / g_d0 / g_e0 を書き戻す",
    0x1000C364: "fpip->flag & 0x200 = 描画品質を落としてよい",
    0x1000C369: "N > 50 のときだけ",
    0x1000C374: "マジック 0x51eb851f + sar 4 = /50",
    0x1000C379: "N = 50。v も 50/N 倍される(走行距離は不変)",
    0x1000C3AE: "N <= 1 なら何もせず return 1",
    0x1000C3BF: "fp->check (+0x48)",
    0x1000C3C2: "check[0] = サイズ固定",
    0x1000C3C6: "ON: 矩形を (0,0,w,h) に戻し、生存サンプル数で割るワーカーへ",
    0x1000C3D8: "ワーカー 0x1000c720(サイズ固定 ON)",
    0x1000C3FD: "ワーカー 0x1000c4a0(サイズ固定 OFF)",
    0x1000C3F2: "[fp+0x60]+0xCC = EXFUNC::exec_multi_thread_func",
    0x1000C420: "+0xAC と +0xB0 を入れ替え",
    0x1000C444: "(w - x1 - x0) << 11 = 半画素単位の中心補正",
    0x1000C47C: "fpip->B4 = x1 - x0",
    0x1000C48E: "fpip->B8 = y1 - y0",
    0x1000C497: "常に return 1",
    # --- §2 worker (grow) ---------------------------------------------------
    0x1000C4AA: "y1",
    0x1000C4B1: "y0",
    0x1000C4C4: "hi = (tid+1)*(y1-y0)/thread_num",
    0x1000C4F0: "行幅 *(fpip+0xEC)",
    0x1000C4FA: "**カーネル幅 = 2N + 1** ―― 窓は自分を中心に対称",
    0x1000C51F: "lo = tid*(y1-y0)/thread_num。ガード(A)は無い",
    0x1000C551: "dst = *(fpip+0xB0) + (y - y0)*行幅*8",
    0x1000C577: "列ループの先頭",
    0x1000C57D: "N * vy",
    0x1000C582: "N * vx",
    0x1000C58B: "開始 y = (y << 16) - N*vy",
    0x1000C58D: "開始 x = (x << 16) - N*vx",
    0x1000C597: "+0x8000 ―― 以降の sar 16 が四捨五入になる",
    0x1000C5BF: "サンプルループ: 現在位置を取り出してから v を足す",
    0x1000C5CB: "sar 16 = floor",
    0x1000C5D3: "枠外のサンプルは足さない(除数も減らさない)",
    0x1000C5F3: "src.a",
    0x1000C604: "a >= 4096 は掛け算を省く近道",
    0x1000C609: "(y*a) >> 12 ―― アルファ加重(プリマルチプライ)累積",
    0x1000C63A: "sum_a += a",
    0x1000C651: "2N+1 回",
    0x1000C665: "sum_a == 0 なら色を書かない",
    0x1000C66F: "色は sum_a で割る(x87 の double 除算)",
    0x1000C6B4: "**アルファはカーネル幅 2N+1 で割る** ―― 枠外は透明として数える",
    0x1000C6CA: "dst.a",
    # --- §3 worker (size fixed) ---------------------------------------------
    0x1000C77A: "カーネル幅 2N+1(ここまでは OFF 版と同じ)",
    0x1000C825: "[esp+0x10] = 枠内に落ちたサンプルの本数。OFF 版に無い唯一の変数",
    0x1000C87B: "a == 0 でもカウンタは進む(枠内なら数える)",
    0x1000C8CC: "枠内サンプルのカウンタ ++",
    0x1000C8D0: "枠外はここへ飛ぶのでカウンタは進まない",
    0x1000C8ED: "カウンタ 0 → アルファ 0 を書いて終わり",
    0x1000C8F5: "sum_a == 0 → 色を書かず、アルファだけ",
    0x1000C941: "**アルファは生存サンプル数で割る** ―― 端で正規化し直す",
    0x1000C94B: "カウンタ 0 のときの dst.a = 0",
    # --- §4 frame -----------------------------------------------------------
    0x1000C9CE: "フレーム版も同じ +pi/1800 → ±65536 の定型",
    0x1000CA07: "サンプル数の4分岐もオブジェクト版と1命令ずつ同じ",
    0x1000CA8D: "描画品質フラグ",
    0x1000CADC: "ワーカーは1本だけ。矩形の計算がそもそも無い",
    0x1000CAF5: "ycp_edit と ycp_temp を入れ替え",
    0x1000CB5A: "カーネル幅 2N+1",
    0x1000CC64: "枠内サンプルのカウンタ ++",
    0x1000CC7A: "カウンタ 0 なら書き込みそのものをしない",
    0x1000CC7D: "3チャンネルとも生存サンプル数で割る(idiv = 0方向切り捨て)",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print(__doc__)

    print("\n" + "=" * 74)
    print("§1 オブジェクト版 func_proc")
    print("=" * 74)
    dump_range(img, FUNC_PROC_OBJ, 0x2A0, "func_proc (object)", annotations=NOTES)

    print("\n" + "=" * 74)
    print("§2 ワーカー(サイズ固定 OFF)―― 除数はカーネル幅 2N+1")
    print("=" * 74)
    dump_range(img, WORKER_GROW, 0x273, "worker (grow)", annotations=NOTES)

    print("\n" + "=" * 74)
    print("§3 ワーカー(サイズ固定 ON)―― 除数は生存サンプル数")
    print("=" * 74)
    dump_range(img, WORKER_FIXED, 0x28B, "worker (size fixed)", annotations=NOTES)

    print("\n" + "=" * 74)
    print("§4 フレーム版")
    print("=" * 74)
    dump_range(img, FUNC_PROC_FRAME, 0x155, "func_proc (frame)", annotations=NOTES)
    dump_range(img, WORKER_FRAME, 0x26E, "worker (frame)", annotations=NOTES)

    print("\n" + "=" * 74)
    print("§5 参照している定数・共有アドレス")
    print("=" * 74)
    for va, what in (
        (0x1009A410, "+pi/1800 ―― 1/10度 → ラジアン(7エフェクトが共有)"),
        (0x1009A408, "-65536.0(sin 側)"),
        (0x1009A3E8, "+65536.0(cos 側)"),
        (0x1009A3A0, "4096.0 ―― 色を sum_a で割るときのスケール"),
    ):
        print(f"  0x{va:08x}  f64 = {img.f64(va)!r:<22} {what}")
    for va, what in (
        (0x10091AD8, "CRT _ftol(0方向切り捨て)"),
        (0x10196748, "最大キャンバス幅(共有)"),
        (0x101920E0, "最大キャンバス高(共有)"),
    ):
        print(f"  0x{va:08x}  {what}")
    print("\n  グローバル(全部このエフェクト専用、0x100d75cc-0x100d75e4 に連続):")
    for va, what in (
        (0x100D75CC, "vx = trunc(sin(θ)·(-65536))"),
        (0x100D75D0, "vy = trunc(cos(θ)·65536)"),
        (0x100D75D4, "x1 = w + 範囲"),
        (0x100D75D8, "y1 = h + 範囲"),
        (0x100D75DC, "x0 = -範囲"),
        (0x100D75E0, "N(片側のサンプル数。カーネル幅は 2N+1)"),
        (0x100D75E4, "y0 = -範囲"),
    ):
        print(f"  0x{va:08x}  {what}")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
