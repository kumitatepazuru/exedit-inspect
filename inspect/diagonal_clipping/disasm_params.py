"""`func_proc` と2つのワーカーの全命令に注釈を付ける。

`斜めクリッピング` は `0x1005cab0`〜`0x1005cea7` の **1016バイト・3関数**で
全部である。`func_init` も `func_WndProc` も `ex_data` もチェックボックスも
無いので、ここに出てくる命令列がエフェクトのすべてになる。

構成:

  1. `func_proc` (`0x1005cab0`, 183バイト) ―― トラックバー5本をグローバル
     5個に畳んで、`幅` の値で2つのワーカーのどちらかを起動するだけ。
     画素には一切触らない。早期リターンも無く常に `return 1`。
  2. `sub_1005cb70` (`0x1005cb70`, 309バイト) ―― `幅 == 0` のワーカー。
     直線の片側を消す(半平面クリップ)。
  3. `sub_1005ccb0` (`0x1005ccb0`, 504バイト) ―― `幅 != 0` のワーカー。
     `幅 > 0` / `幅 < 0` の2変種が1関数に同居していて、直線を挟む帯を
     残す/消す。

読みどころは3つ:

  * **角度 → Q16 の方向ベクトル**(`0x1005caf1`〜`0x1005cb1d`)。
    [`angle_vector.md`](../common/angle_vector.md) の定型そのままで、
    `(vx, vy) = (sin θ·65536, cos θ·(-65536))`。
  * **符号付き距離の漸化式**。ワーカーは `s = vx*(x-cx) + vy*(y-cy)` を
    行頭で1回組み立て、あとは列ごとに `add ecx, vx` するだけ。浮動小数点は
    帯幅を作る `fsqrt` の1回きりで、画素ループは完全に整数。
  * **帯幅 `band = _ftol(sqrt(vx² + vy²) * (ぼかし+1))`**。65536 を決め打ち
     せず `_ftol` 後の成分から長さを取り直すので、`s` と `band` の単位が
     必ず揃う ―― これが「どの角度でもぼかし幅が `ぼかし+1` 画素ちょうど」に
     なる理由(`verify_direction.py` §4)。

注釈が主張で、その横の命令が根拠である。

Run via main.py:
    uv run main.py inspect/diagonal_clipping/disasm_params.py
    uv run main.py inspect/diagonal_clipping/disasm_params.py --only halfplane
"""

import argparse

from tools.disasm import dump_all
from tools.pe_image import PEImage

FUNC_PROC = (0x1005CAB0, 0xB7)
WORKER_HALFPLANE = (0x1005CB70, 0x135)
WORKER_BAND = (0x1005CCB0, 0x1F8)

ANNOTATIONS = {
    # ------------------------------------------------------------- func_proc
    0x1005CAB1: "esi = fp",
    0x1005CAB6: "edi = fpip",
    0x1005CABA: "ecx = fp->track (+0x44): 中心X 中心Y 角度 ぼかし 幅 の5本",
    0x1005CABD: "eax = *(fpip+0xB4) = オブジェクトの幅 w",
    0x1005CAC3: "cdq/sub/sar = 0方向切り捨ての /2 (integer_semantics.md §1)",
    0x1005CAC6: "edx = track[0] = 中心X",
    0x1005CACC: "g_101b20c8 = w/2 + 中心X ―― 直線が通る点の x [画素]",
    0x1005CAD1: "eax = *(fpip+0xB8) = 高さ h",
    0x1005CADF: "+ track[1] = 中心Y",
    0x1005CAE2: "g_101b20cc = h/2 + 中心Y ―― 同じく y [画素]",
    0x1005CAEA: "st0 = track[2] = 角度(生値。表示スケール10 なので 1/10 度単位)",
    0x1005CAED: "eax = track[3] = ぼかし (生値 0..2000)",
    0x1005CAF0: "+1 ―― ぼかし=0 でも 1画素の階調が残る。斜め線が常にアンチ",
    0x1005CAF1: "    エイリアスされるのはこの inc のおかげ。×pi/1800 でラジアンへ",
    0x1005CAF7: "g_101b20d8 = ぼかし + 1",
    0x1005CAFC: "fld st(0): 角度を fild 1回で済ませる書き方(凸エッジと同型)",
    0x1005CAFE: "st0 = sin(θ)  (複製したほうを消費する)",
    0x1005CB00: "× +65536.0 ―― Q16 へ",
    0x1005CB06: "_ftol: 0方向切り捨て (integer_semantics.md §3)",
    0x1005CB0B: "残っていた θ に fcos",
    0x1005CB0D: "g_101b20d0 = vx = trunc(sin(θ)·65536)",
    0x1005CB12: "× -65536.0 ―― y だけ符号が逆(angle_vector.md §2 の +sin/-cos 系)",
    0x1005CB1D: "g_101b20d4 = vy = trunc(cos(θ)·(-65536))",
    0x1005CB25: "exec_multi_thread_func の param2 = fpip",
    0x1005CB26: "                       param1 = fp (ワーカーは読まない)",
    0x1005CB27: "edx = track[4] = 幅",
    0x1005CB2A: "<<15 = Q16 での 幅/2。g_101b20c4 は「半値幅」であって幅ではない",
    0x1005CB2D: "g_101b20c4 = 幅 << 15",
    0x1005CB33: "ZF は直前の shl のもの ―― 幅 == 0 のときだけ半平面ワーカーへ",
    0x1005CB35: "幅 != 0: 帯ワーカー sub_1005ccb0",
    0x1005CB3D: "[fp+0x60]+0xCC = EXFUNC::exec_multi_thread_func",
    0x1005CB46: "return 1。3出口を持つ フェード/ワイプ と違い、抜ける道は無い",
    0x1005CB4E: "幅 == 0: 半平面ワーカー sub_1005cb70",
    0x1005CB5F: "こちらも return 1",
    # ---------------------------------------------- worker: 幅 == 0 (半平面)
    0x1005CB73: "ecx = fpip (param2)。fp (param1) はこの関数で一度も読まれない",
    0x1005CB78: "ebx = tid",
    0x1005CB84: "esi = h",
    0x1005CB8A: "引数スロットを潰して w を置く",
    0x1005CB90: "ebp = thread_num",
    0x1005CB94: "eax = h * tid",
    0x1005CB97: "st0 = vy",
    0x1005CB9D: "st0 = vx, st1 = vy",
    0x1005CBA5: "st0 = vx*vx",
    0x1005CBA9: "st0 = vy*vy",
    0x1005CBAC: "st0 = vx*vx + vy*vy",
    0x1005CBAE: "y0 = h*tid / thread_num (thread_split.md の (B) だけの形)",
    0x1005CBB0: "st0 = sqrt(vx²+vy²) ―― 65536 を決め打ちせず _ftol 後の成分から",
    0x1005CBB5: "    取り直す。これで s と band の単位が必ず一致する",
    0x1005CBBB: "× (ぼかし+1)",
    0x1005CBC2: "y1 = h*(tid+1) / thread_num",
    0x1005CBC4: "ebp = *(fpip+0xEC) = 行幅 [画素]",
    0x1005CBD3: "eax = *(fpip+0xAC) = オブジェクトの画像 (8バイト/画素 PIXEL_YCA)",
    0x1005CBD9: "esi = &pixel[y0][0]",
    0x1005CBDC: "_ftol → ebx = band = trunc(|v| · (ぼかし+1))",
    0x1005CBE3: "ecx = 中心Y * vy",
    0x1005CBF0: "x87 スタックを空にする(以降は完全に整数演算)",
    0x1005CBFA: "band を引数スロット(param1 = fp)へ退避 ―― fp は最後まで参照されない",
    0x1005CBF4: "band + 255 ...",
    0x1005CBFE: "    ... を 0方向切り捨てで /256 = ceil(band/256)。",
    0x1005CC0D: "    この切り上げがテーブル添字を 4095 以下に抑える唯一のガード",
    0x1005CC10: "[esp+0x10] = div = ceil(band/256)",
    0x1005CC1C: "ebx = band/2",
    0x1005CC26: "  - 中心Y*vy",
    0x1005CC28: "  - 中心X*vx  →  base。半平面版は band/2 を引き戻さない = 階調帯が",
    0x1005CC2A: "                 直線の上に「centered」に乗る",
    0x1005CC32: "行末から次の行頭までの画素数 ...",
    0x1005CC34: "    ... × 8バイト",
    0x1005CC3B: "行ループ: ecx = vy*y + base",
    0x1005CC4C: "ecx >= band ? → 触らない(完全に見える側)",
    0x1005CC50: "                この分岐が「アルファを減らすことしかしない」を保証する",
    0x1005CC52: "ecx <= 0 ?",
    0x1005CC56: "  → アルファ0(消える側)。y/cb/cr は読みも書きもしない",
    0x1005CC5E: "階調帯の中: ecx * 16 ...",
    0x1005CC64: "    ... / div  ≒ ecx * 4096 / band",
    0x1005CC6C: "0x101dcf78 = 1-cos イージング表 (lut_tables.md §2)",
    0x1005CC74: "alpha *= table[i] ...",
    0x1005CC77: "    ... >> 12 (sar = floor)",
    0x1005CC7A: "書き戻すのは +6 のアルファだけ",
    0x1005CC82: "次の画素へ(8バイト)",
    0x1005CC85: "ecx += vx ―― 列方向は加算だけ。乗算も丸めも入らないので誤差ゼロ",
    # -------------------------------------------- worker: 幅 != 0 (帯)
    0x1005CCB3: "ecx = fpip。ここも fp は読まない",
    0x1005CCC7: "edi = tid",
    0x1005CCD4: "半平面版と同じ prologue: |v| と band を作る",
    0x1005CCEF: "y0 = h*tid / thread_num",
    0x1005CD08: "y1 = h*(tid+1) / thread_num",
    0x1005CD1C: "_ftol → ebp = band",
    0x1005CD34: "div = ceil(band/256)、半平面版と同一",
    0x1005CD48: "edx = band/2 ...",
    0x1005CD53: "    ... - 中心Y*vy ...",
    0x1005CD67: "    ... - 中心X*vx = base。帯版はこの band/2 を行ごとに引き戻す",
    0x1005CD62: "eax = g_101b20c4 = 幅<<15 (半値幅 hw)",
    0x1005CD73: "hw <= 0 ? → 幅 < 0 の変種へ。幅 == 0 はここへ来ない(func_proc が分岐済み)",
    0x1005CD8C: "【幅 > 0】行ループ: ecx = vy*y + base",
    0x1005CD9F: "band/2 を引き戻して ecx = s (符号付き距離、Q16)",
    0x1005CDAC: "列ループ: eax = s ...",
    0x1005CDAF: "    ... の絶対値 (cdq/xor/sub)",
    0x1005CDBA: "m = hw - |s| ―― 直線に近いほど大きい = 帯の内側を残す",
    0x1005CDBE: "m >= band → 触らない",
    0x1005CDC2: "m <= 0 → アルファ0",
    0x1005CDCC: "階調: m*16 / div でテーブルを引く。階調帯は |s| = hw の内側だけに",
    0x1005CDD4: "    乗る(半平面版と違って centered ではない)",
    0x1005CDF1: "ecx += vx",
    0x1005CE11: "【幅 < 0】ここから下は同じ形で m の作り方だけが違う",
    0x1005CE24: "行ループ: ecx = vy*y + base",
    0x1005CE37: "band/2 を引き戻して s",
    0x1005CE44: "列ループ: |s| ...",
    0x1005CE4B: "    ... + hw (hw は負) = |s| - |幅|/2 ―― 直線から遠いほど大きい",
    0x1005CE51: "    = 帯の内側を消す。幅>0 とちょうど裏返し",
    0x1005CE55: "m >= band → 触らない",
    0x1005CE59: "m <= 0 → アルファ0",
    0x1005CE6B: "階調帯は |s| = |hw| の外側に乗る",
}

TARGETS = {
    "func_proc                     0x1005cab0": FUNC_PROC,
    "worker: halfplane (幅 == 0)   0x1005cb70": WORKER_HALFPLANE,
    "worker: band      (幅 != 0)   0x1005ccb0": WORKER_BAND,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="disasm_params")
    parser.add_argument("--only", help="ラベルの部分一致でダンプ対象を絞る")
    args = parser.parse_args(argv or [])

    targets = TARGETS
    if args.only:
        targets = {k: v for k, v in TARGETS.items() if args.only in k}
        if not targets:
            print(f"no target label contains {args.only!r}; known: {list(TARGETS)}")
            return

    img = PEImage(dll_path)
    dump_all(img, targets, annotations=ANNOTATIONS, mnemonic_width=9)

    print("\n斜めクリッピングの全実体は 0x1005cab0-0x1005cea7 の 1016 バイト。")
    print("この3関数のほかに func_init / func_WndProc / ex_data は存在しない")
    print("(verify_registration.py)。")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
