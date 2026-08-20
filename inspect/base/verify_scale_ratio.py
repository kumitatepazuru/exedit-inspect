"""拡大率 (0x100078c0, 420 bytes) ―― fpip+0xE0/+0xE4 の縮小分数エンコーディング。

`拡大率`/`X`/`Y` の3本のトラックバーは、それぞれ**100%(raw==10000)なら
まるごとスキップ**される(0x1000794f/0x10007991/0x1000799c の3つの `cmp ..,0x2710`)。
関わったものだけを x87 で `_ftol`(0方向切り捨て)しながら fpip+0xE0(前回の値)
に掛け込んでいく ―― ここまでは disasm 上明確。

**この関数だけは「未確定」を残す**: 前段(0x100078ca-0x1000793e)は
`fpip+0xE4` の符号で分岐し、2つの候補値(disasm 上の `edi`/`esi`)を作るが、
どちらのスタックスロットがどちらの候補に対応するかを ESP オフセットの
手計算だけで確定させるのは事故りやすいので、ここでは踏み込まない
(fade/README.md §10 の「未確定事項」と同じ立場)。

**確定しているのは末尾(0x100079de-0x10007a63)の不変条件**で、angr の
デコンパイル(`decompile_base.py --only 拡大率`)でも同じ形が出る:

    if edi == esi:
        fpip.field_e0, fpip.field_e4 = edi, 0
    elif edi < esi:                      # esi が大きい
        fpip.field_e0 = esi
        fpip.field_e4 = round_toward_zero(65536 * (edi - esi) / esi)   # < 0
    else:                                 # edi が大きい(または等しくない)
        fpip.field_e0 = edi
        fpip.field_e4 = round_toward_zero(65536 * (esi - edi) / edi)   # < 0

`field_e0` は常に**2候補の大きい方**、`field_e4` は**小さい方が大きい方に対して
どれだけ欠けているか**を Q16(65536=100%)の符号付きで持つ。`field_e4 == 0` が
「2候補が一致 = まだ何も足されていない/割り切れる状態」を意味し、これが
関数冒頭の `test eax,eax` (`fpip+0xE4`) の分岐と対応する。

`標準描画`(0x1008a020)が `[reg+0xE4]` を関数全域で15回読んでいることは
`grep -E "0xe4\\]" <(uv run main.py tools.disasm --addr 0x1008a020 --size 0x4000 --no-resolve)`
で確認できる(README 本文に生ログを掲載)。

Run via main.py:
    uv run main.py inspect/base/verify_scale_ratio.py
"""

from tools.disasm import dump_range
from tools.pe_image import PEImage

FUNC = (0x100078C0, 0x1A4)

ANNOT = {
    0x100078ca: "eax = *(fpip+0xE4)  既存の「相対差分」候補(Q16, 符号付き)",
    0x100078d2: "!= 0 なら分岐(前段の詳細は未確定 ―― docstring 参照)",
    0x1000794c: "eax = fp->track[0] = 拡大率 (raw, 0..500000, scale=100)",
    0x1000794f: "== 0x2710(10000 = 100.00%) ならこの軸はまるごとスキップ",
    0x10007991: "eax = fp->track[1] = X。== 10000 ならスキップ。以下 拡大率 と同型",
    0x1000799c: "track[1](X) を掛け込む(0x1009a3e0 = 0.0001 = /10000)",
    0x100079bc: "ebp = fp->track[2] = Y。== 10000 ならスキップ。以下も同型",
    0x100079de: "cmp edi, esi           2候補を比較 ―― ここから先が確定した不変条件",
    0x100079e2: "等しい: *(fpip+0xE0)=edi, *(fpip+0xE4)=0  (差分なし)",
    0x100079fe: "jge 0x10007a33         edi>=esi なら「edi が大きい」側の枝",
    0x10007a00: "esi<edi: eax=esi-edi (<0)",
    0x10007a08: "fild/fmul 65536.0/fidiv esi/_ftol      Q16 の相対差分",
    0x10007a1b: "*(fpip+0xE0)=esi(大きい方), *(fpip+0xE4)=差分",
    0x10007a33: "edi>=esi: esi-=edi (<=0)",
    0x10007a3d: "fild/fmul 65536.0/fidiv edi/_ftol",
    0x10007a4c: "*(fpip+0xE0)=edi(大きい方), *(fpip+0xE4)=差分",
}


def tail_reduce(edi: int, esi: int) -> tuple[int, int]:
    """0x100079de-0x10007a63 を Python に直訳したもの(確定パート)。"""
    if edi == esi:
        return edi, 0
    if edi >= esi:
        diff = esi - edi  # <= 0
        e4 = int(diff * 65536 / edi) if edi else 0  # _ftol: truncate toward zero
        return edi, e4
    diff = edi - esi  # < 0
    e4 = int(diff * 65536 / esi) if esi else 0
    return esi, e4


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_range(img, *FUNC, "拡大率 0x100078c0", annotations=ANNOT, mnemonic_width=9)

    print("\n--- verify: tail invariant (field_e0 = max, field_e4 = signed Q16 gap) ---")
    for edi, esi in ((100, 100), (100, 200), (200, 100), (65536, 32768), (1, 1000000), (0x10000, 0x8000)):
        e0, e4 = tail_reduce(edi, esi)
        assert e0 == max(edi, esi)
        assert e4 <= 0
        assert (e4 == 0) == (edi == esi)
        print(f"  edi={edi:>8} esi={esi:>8} -> field_e0={e0:>8} field_e4={e4:>8}"
              f"  (小さい方は大きい方の {(1+e4/65536)*100:6.2f}%)")

    print("""
まとめ (確定分のみ):

  * `拡大率`/`X`/`Y` は raw==10000(100.00%) のとき**その軸の計算を丸ごと
    スキップ**する ―― 3本とも 100% なら x87 命令が1つも実行されない
    高速経路がある(`透明度` の raw==0 早期リターンと同じ発想)。
  * 最終的に fpip+0xE0/+0xE4 に残るのは「2つの候補のうち大きい方」と
    「小さい方が何%欠けているか(Q16, 0 以下)」という組。`+0xE4 == 0` は
    「今回、前回の値から変化しなかった」を意味し、次にこの関数が呼ばれた
    ときの `test eax,eax` 分岐に直結する。
  * 前段(2候補 edi/esi を作る部分)は x87 + ESP 相対アドレッシングが
    絡み合っていて、このスクリプトでは断定していない。`decompile_base.py --only 拡大率`
    で angr の出力(整数部分は一致、x87 部分は unsupported)を確認できる。
""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
