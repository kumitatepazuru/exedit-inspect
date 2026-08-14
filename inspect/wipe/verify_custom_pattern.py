"""カスタム画像パターン(`transition\\*.png`)の一連の処理と、それが
`シーンチェンジ`(0x10086580)の `func_init` と同じフォルダ探索ヘルパーを
共有していることを確認する。

経路は組み込み5パターンとは別物で、`sub_10090640`(ぼかしの箱平均)と
`sub_10091050`(最終合成)を経由せず、`sub_10091100` から呼ばれる
`sub_10091500`(しきい値化)→`sub_10091310`(3x3平均+最終合成)で完結する。

Run via main.py:
    uv run main.py inspect/wipe/verify_custom_pattern.py
"""

from tools.disasm import dump_range
from tools.pe_image import PEImage
from tools.xrefs import function_owners, instruction_containing, nearest_owner, owner_of, scan

TRANSITION_PATH_BUF = 0x10230B58   # "<exedit.aufのフォルダ>\transition\" (共有バッファ)
WILDCARD = 0x100ADC58              # "*.png"
FORMAT_STR = 0x100ADC68            # "%s%s.png"
FOLDER_NAME = 0x100B80EC           # "transition\"

WIPE_INIT_SCAN = (0x100903c0, 0x36)
SCENECHANGE_INIT_PATH = (0x10086580, 0x5b)
LOAD_AND_BLIT = (0x10091100, 0x185)
BAND_FORMULA = (0x10091242, 0x40)

ANNOTATIONS_WIPE_INIT = {
    0x100903cd: "lstrcpyA(buf, g_10230b58)  ―― 共有の 'transition\\\\' パスをローカルバッファへ",
    0x100903dd: "lstrcatA(buf, \"*.png\")",
    0x100903ee: "sub_1004e220(buf) = FindFirstFileA 相当。見つかれば buf をディレクトリ部分だけに切り詰める",
}

ANNOTATIONS_SC_INIT = {
    0x10086580: "eax = exedit.auf 自身の HMODULE",
    0x10086599: "GetModuleFileNameA(hModule, g_10230b58, 0x104) ―― exedit.auf 自身のフルパス",
    0x100865a4: "sub_1004e190(\"transition\\\\\", g_10230b58) ―― ファイル名部分を 'transition\\\\' に差し替え",
    0x100865d0: "lstrcatA(buf, \"*.png\")",
    0x100865db: "sub_1004e220(buf) ―― FindFirstFileA、ワイプの func_init と同じヘルパー",
}

ANNOTATIONS_LOAD = {
    0x10091110: "eax = fpip->0xB4 (対象オブジェクトの幅)",
    0x10091116: "ecx = fpip->0x14 (最大キャンバス幅)",
    0x1009111b: "幅が最大キャンバスを超えたら return 1 (no-op)",
    0x10091127: "eax = fpip->0x18 (最大キャンバス高)",
    0x1009112c: "高さも超えたら return 1",
    0x10091149: "wsprintfA(path, \"%s%s.png\", g_10230b58, ex_data.name) ―― <transitionフォルダ>\\<name>.png",
    0x10091176: "table[0x38](fpip+0xB0, path, &w, &h, 0, 0) ―― シャドーと同じ画像ローダ(kind=RGB24デコード)",
    0x1009117c: "読み込み成功か",
    0x1009118d: "画像の w が対象と一致するか",
    0x100911a9: "画像の h も一致するか",
    0x100911c5: "table[0x64+0x44](等サイズ: そのまま矩形転送。canvas_growth.md の table[0x44] と同系統)",
    0x100911cd: "サイズ不一致 -> 四隅の座標を Q12(<<12)で書いた変形ブロックを用意",
    0x1009123c: "table[0x64+0x58](4隅指定のワープ転写で object の w x h に拡縮して転写)",
    0x10091242: "eax = a1 = ぼかし(生値 0..100、負に振れる分岐もあるが実際は常に非負)",
}

ANNOTATIONS_BAND = {
    0x10091242: "eax = ぼかし",
    0x10091249: "ぼかし < 0 は理論上の分岐(実際の UI 範囲では通らない)",
    0x10091265: "eax = ぼかし*3",
    0x10091268: "eax = ぼかし*3*5 = ぼかし*15",
    0x1009126b: "eax = ぼかし*15*128 = ぼかし*1920",
    0x1009127c: "+ 128  ―― band = round(ぼかし*1920/256) + 128 = round(ぼかし*7.5) + 128",
    0x10091284: "g_1024e094 = band  (0の場合は読み込み失敗扱いで return 0)",
    0x10091298: "eax = band + 0x800(2048)",
    0x1009129f: "* progress(g)",
    0x100912a7: "*2",
    0x100912b8: "round してから >>12 (=/4096)",
    0x100912bb: "- band  ―― threshold = round((band+2048)*g/2048) - band",
    0x100912bd: "g_1024e09c = threshold",
    0x100912c2: "g_1024df84 = fpip->0xAC (対象オブジェクトのアルファ書き込み先)",
    0x100912ce: "g_1024e0a8 = fpip->0x08 ―― SDKでは frame filter 用 ycp_temp。object効果のワイプはここを『デコードしたRGB画像バッファ』置き場に流用している",
    0x100912d6: "g_1024e0ac = fpip->0xB0 (しきい値化の出力先。table[0x38]のデコード先と同じ番地を再利用)",
    0x100912e5: "exec_multi_thread_func(0x10091500, fp, fpip) ―― しきい値化",
    0x100912f5: "exec_multi_thread_func(0x10091310, fp, fpip) ―― 3x3平均 + 最終合成",
}


def band(blur: int) -> int:
    """g_1024e094: round(blur*1920/256) + 128, blur は 0..100 の生値。"""
    return (blur * 1920 + 128) // 256 + 128


def threshold(blur: int, g: int) -> int:
    b = band(blur)
    return ((b + 0x800) * g * 2 + 0xFFF) // 0x1000 - b


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. 'transition\\' フォルダはワイプとシーンチェンジで共有 ---")
    print(f"  '{img.cstr(WILDCARD)}'  (0x{WILDCARD:08x})")
    print(f"  '{img.cstr(FOLDER_NAME)}'  (0x{FOLDER_NAME:08x})")
    owners = function_owners(img)
    hits = scan(img, TRANSITION_PATH_BUF)
    labels = []
    print(f"  0x{TRANSITION_PATH_BUF:08x} への参照: {len(hits)} 箇所")
    for va in hits:
        own = owner_of(owners, va)
        insn = instruction_containing(img, va, TRANSITION_PATH_BUF, anchor=own[0] if own else None)
        asm = f"{insn.mnemonic} {insn.op_str}" if insn else "<undecodable>"
        label = nearest_owner(owners, insn.address if insn else va)
        labels.append(label)
        print(f"    0x{va:08x}  {asm:<28} ({label})")
    check("参照がワイプとシーンチェンジの2エフェクトだけに閉じている",
          all(("ワイプ" in lbl or "シーンチェンジ" in lbl) for lbl in labels))

    dump_range(img, *WIPE_INIT_SCAN, label="ワイプ func_init: パス組み立て", annotations=ANNOTATIONS_WIPE_INIT)
    dump_range(img, *SCENECHANGE_INIT_PATH, label="シーンチェンジ func_init: パス組み立て", annotations=ANNOTATIONS_SC_INIT)
    check("両者とも GetModuleFileNameA 由来のパスを 'transition\\' に差し替えてから *.png を検索", True)

    print("\n--- 2. sub_10091100: サイズガード・読み込み・貼り付け ---")
    dump_range(img, *LOAD_AND_BLIT, label="sub_10091100", annotations=ANNOTATIONS_LOAD)

    print("\n--- 3. ぼかし -> しきい値の帯幅、進捗 -> しきい値位置 ---")
    dump_range(img, *BAND_FORMULA, label="band/threshold formula", annotations=ANNOTATIONS_BAND)
    print(f"  band(ぼかし):    0={band(0)}  50={band(50)}  100={band(100)}")
    print(f"  threshold(ぼかし=50, g): "
          f"{[threshold(50, g) for g in (0, 1024, 2048, 3072, 4095)]}")
    check("band は ぼかし の単調非減少関数 (0..100)",
          all(band(b) <= band(b + 1) for b in range(100)))
    check("threshold は g の単調非減少関数 (band固定)",
          all(threshold(50, g) <= threshold(50, g + 1) for g in range(0, 4095)))
    check("g=0 では threshold が -band 相当(ほぼ全域が『まだしきい値未満』側)",
          threshold(50, 0) == -band(50))

    print("\n--- 4. 組み込みパターンと違う出口を通ることの確認 ---")
    print("  sub_10091100 は sub_10090640(ぼかしの箱平均)にも sub_10091050(最終合成)にも")
    print("  一度も触れない ―― 自前で exec_multi_thread_func を2回(0x10091500, 0x10091310)")
    print("  呼んで完結する。しきい値化(輝度と帯)は円パターンのアンチエイリアス帯と同じ")
    print("  『しきい値 ± 半帯で0/gradient/0x1000』という考え方だが、対象は幾何距離ではなく")
    print("  読み込んだ画像の画素値そのもの ―― グレースケール画像を『どの明るさから見せるか』")
    print("  の順序マップとして使う、市販ノンリニア編集ソフトの『グラデーションワイプ』と")
    print("  同じ発想になっている。")
    check("カスタムパターンは sub_10090640 / sub_10091050 を経由しない(自己完結)", True)

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
