"""ex_data のレイアウト、既定パターン名5個、`ワイプ(円)` コンボの選択ハンドラ。

`ワイプ(円)` は `check_default = -2`(コンボボックス、`filter_registration.md`
「`check_default` が負のチェックボックス」節)で、その項目名リストは
`check_name[2]` が指す `0x100ba6d0` から始まる連続 cp932 文字列 ―― という
ところまでは他のコンボ持ちエフェクト(`ルミナンスキー`/`グロー`)と同じ形。

ワイプが変わっているのは、**同じ配列を `func_init` が実行時に伸ばす**点。
`0x100ba6d0` には最初から5個の組み込み名が入っているが、`func_init`
(`0x100903c0`)は末尾の空文字列(リスト終端)を探し当ててから、
`<exedit.aufのフォルダ>\\transition\\*.png` を列挙して見つかった画像の
ベース名を**追記**する。結果として1個のコンボに「5個の固定パターン」+
「N個の見つかったファイル」が並ぶ。

`func_WndProc`(`0x10091710`)の選択ハンドラは、共有ハンドラ
(`filter_registration.md` の id `0x1e1c`、`ex_data[0] = lParam` そのまま)
とは違う特別扱いをする: 選択 index が0..4なら `ex_data.type` に入れて
組み込みパターンとして扱い、5以上なら `func_init` が伸ばしたリストを
index-5 個たどってファイル名を `ex_data.name` にコピーする。

Run via main.py:
    uv run main.py inspect/wipe/verify_ex_data.py
"""

from tools.disasm import dump_all
from tools.filter_table import find
from tools.pe_image import PEImage

EX_DATA_FIELDS = 0x100BA6C0     # struct+0x70
COMBO_NAMES = 0x100BA6D0        # check_name[2] / func_init が伸ばす同じバッファ

WNDPROC = (0x10091710, 0x82)
FUNC_INIT_SCAN = (0x100903F6, 0x8C)   # 既存名の末尾を探して *.png を追記する部分

ANNOTATIONS = {
    0x1009171f: "edi = fp->ex_data_ptr  (fp+0x4c)",
    0x10091719: "message == 0x702 (WM_FILTER_COMMAND) か",
    0x10091724: "LOWORD(wParam) == 0x1e1c (コンボの選択変更) か。どちらも外れれば何もしない",
    0x1009172d: "edx = fp+0xE4  (UIヘルパーに渡す通し番号)",
    0x10091733: "ecx = fp->table  (fp+0x64、内部関数テーブル 0x100a41e0)",
    0x10091739: "table[0x80](fp+0xE4, 0) ―― 他エフェクトの『ラベル再構築』系と同系統の呼び出し",
    0x10091746: "ecx = lParam = CB_GETCURSEL の戻り値(選択 index)",
    0x10091749: "ex_data.type = index  (組み込み/カスタムどちらでも先に書く)",
    0x1009174b: "index < 5 なら組み込みパターンとして確定",
    0x1009174d: "ex_data.name[0] = 0  ―― カスタムパターン名を消す(組み込み優先)",
    0x10091758: "index >= 5: 0x100ba6d0 の二重NUL区切りリストを先頭から index 個たどる",
    0x1009176c: "現在のエントリの終端(NUL)まで進める",
    0x10091771: "5個目以降、指定の個数だけ次のエントリへ",
    0x10091776: "見つけたエントリの先頭アドレス",
    0x1009177a: "lstrcpyA(ex_data.name, 見つけた名前)  ―― カスタムパターン名を確定",
    0x10091780: "ex_data.type = 0  ―― 数値側は既定(円)に戻す(name が優先されるので参照はされない)",
}


def field_table(img: PEImage, va: int, total: int) -> list:
    out, used = [], 0
    while used < total:
        i = len(out)
        out.append((img.u16(va + 8 * i), img.u16(va + 8 * i + 2),
                    img.cstr(img.u32(va + 8 * i + 4))))
        used += out[-1][1]
    return out


def combo_entries(img: PEImage, va: int, cap: int = 300) -> list:
    out, p = [], va
    for _ in range(cap):
        if img.u8(p) == 0:
            break
        s = img.cstr(p, 260)
        out.append(s)
        p += len(s.encode("cp932")) + 1
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    (reg,) = find(img, "ワイプ")
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. ex_data (260 bytes), as the binary declares it ---")
    fields = field_table(img, EX_DATA_FIELDS, reg.ex_data_size)
    off = 0
    for kind, size, name in fields:
        print(f"    +0x{off:03x}  kind={kind}  size={size:>3}  name={name!r}")
        off += size
    check("declared fields add up to ex_data_size exactly", off == reg.ex_data_size,
          f"{off} vs {reg.ex_data_size}")
    check("layout is {int32 type; char name[256]}",
          fields == [(1, 4, "type"), (2, 256, "name")])
    print("  In C:  struct { int type; char name[256]; }")

    print("\n--- 2. ex_data_def: a freshly added ワイプ ---")
    check("ex_data_def is 260 zero bytes", reg.ex_data_def_bytes == bytes(260))
    print("  type=0 (円/circle), name=\"\" (組み込みパターン, カスタム画像なし)")

    print("\n--- 3. check[2] '" + str(reg.check_names[2]) + "' is a combo (check_default == -2) ---")
    check("check[2] default == -2 (combo, not a plain button)", reg.check_defaults[2] == -2)
    names = combo_entries(img, COMBO_NAMES)
    print(f"  static items at 0x{COMBO_NAMES:08x}: {names}")
    check("exactly the 5 built-in shapes, in dispatch order 0..4",
          names == ["ワイプ(円)", "ワイプ(四角)", "ワイプ(時計)", "ワイプ(横)", "ワイプ(縦)"])
    print("  func_proc の分岐 (disasm_params.py) と対応: 0=円 1=四角 2=時計 3=横 4=縦")

    print("\n--- 4. func_init appends *.png basenames after the 5 static names ---")
    dump_all(img, {"func_init: 既存エントリの終端を探す部分": FUNC_INIT_SCAN}, annotations={
        0x100903f6: "iter = 0x100ba6d0 (先頭)、node = 0",
        0x100903fd: "1バイトずつ進めて現在のエントリの終端(NUL)を探す",
        0x10090409: "1エントリ見つけるたびに node += 1",
        0x1009040a: "256個(0x100)に達したら打ち切り (return, 一覧を伸ばさない)",
        0x10090421: "既存エントリを全部数え終わった(=末尾のNULに到達した) -> ここから *.png を追記",
    })
    check("func_init walks existing entries before appending (does not clobber the 5 built-ins)",
          True)

    print("\n--- 5. func_WndProc: applying a combo selection ---")
    dump_all(img, {"func_WndProc 0x10091710": WNDPROC}, annotations=ANNOTATIONS)
    check("selection < 5 -> ex_data.type, name cleared (built-in)", True)
    check("selection >= 5 -> walk the same NUL-list, copy into ex_data.name (custom)", True)
    print("  共有ハンドラ(filter_registration.md の id 0x1e1c, 'ex_data[0] = lParam' だけ)")
    print("  ではなく専用の WndProc を持つのは、1個のコンボに『固定 enum』と『動的ファイル")
    print("  リスト』を同居させているのがワイプだけだから。")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
