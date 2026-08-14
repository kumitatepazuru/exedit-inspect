"""`ぼかし` トラックバー(0..100、生値そのまま)が、パターンのアルファ面
(`fpip+0xB0` の word `+6`)にどう掛かるかを確認する。

`sub_10090640` はカーネル半径を `ぼかし` から `r_hi = ceil(b/2)`,
`r_lo = floor(b/2)` に2分割してから、各軸1回ずつ(垂直 `0x10090700` →
水平 `0x100908c0`)のペアを **r_hi 分、続けて r_lo 分** 走らせる ―― これは
`ぼかし` エフェクト本体の固定4パス `V(r_hi)→H(r_hi)→V(r_lo)→H(r_lo)` と同じ
半径分割([`box_blur.md`](../common/box_blur.md) の分割表)。中間バッファは
共有スクラッチ `[0x101a5328]`([`filter_registration.md` #6](../common/filter_registration.md)
に載っている「ぼかし中間スクラッチ」と同じ番地)。

`ぼかし == 0` は `test ecx,ecx; je` で関数ごとスキップされるので、
組み込みパターンは常にハードエッジ(0 or 0x1000)から始まり、`ぼかし` が
そこへ三角形カーネルの階調を足す ―― という位置づけが命令列から確認できる。

Run via main.py:
    uv run main.py inspect/wipe/verify_blur.py
"""

from tools.disasm import dump_range
from tools.pe_image import PEImage

KERNEL_SPLIT = (0x10090640, 0xBE)  # 0x10090640 .. 0x100906fd (ret)

ANNOTATIONS = {
    0x10090640: "ecx = ぼかし (track[2] 生値, 0..100)",
    0x10090649: "ぼかし == 0 なら関数ごとスキップ (ハードエッジのまま)",
    0x1009064f: "eax = ぼかし",
    0x10090656: "cdq; sub eax,edx ―― 符号付き2除算の定石(非負なので実質そのまま)",
    0x1009065e: "esi = r_lo = floor(ぼかし/2)",
    0x10090660: "ecx = ぼかし - r_lo = r_hi = ceil(ぼかし/2)",
    0x10090666: "r_hi <= 0 なら1本目のペアをスキップ",
    0x10090668: "g_1024e098 = r_hi  (パス1本目の半径)",
    0x1009066d: "g_1024df88 = r_hi  (パス2本目もここを読む ―― 同じ半径を2軸で使う)",
    0x10090672: "g_1024e0a0 = 2*r_hi + 1  (カーネル幅)",
    0x10090680: "exec_multi_thread_func(0x10090700, fp, fpip) ―― 軸1(垂直、fpip+0xB0 -> scratch)",
    0x10090693: "exec_multi_thread_func(0x100908c0, fp, fpip) ―― 軸2(水平、scratch -> fpip+0xB0)",
    0x100906ad: "r_lo <= 0 ならここで終わり",
    0x100906b1: "r_lo 側も同じ2軸ペアをもう一度 (0x10090700 -> 0x100908c0)",
}


def kernel_split(blur: int) -> tuple[int, int]:
    """r_hi = ceil(b/2), r_lo = floor(b/2). ぼかし effect と同じ分割
    (box_blur.md の表そのもの)。"""
    r_lo = blur >> 1
    r_hi = blur - r_lo
    return r_hi, r_lo


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- 1. sub_10090640: half+half+1 のカーネル分割と2ペアの起動 ---")
    dump_range(img, *KERNEL_SPLIT, label="sub_10090640", annotations=ANNOTATIONS)

    print("\n--- 2. r_hi/r_lo の分割を 0..100 全域で確認 ---")
    ok = True
    passes_at = {}
    for b in range(0, 101):
        r_hi, r_lo = kernel_split(b)
        if r_hi + r_lo != b or r_hi < r_lo or r_hi - r_lo not in (0, 1):
            ok = False
        passes_at[b] = (2 if r_hi > 0 else 0) + (2 if r_lo > 0 else 0)
    check("r_hi + r_lo == ぼかし で、常に r_hi == r_lo か r_hi == r_lo+1 (ceil/floor)", ok)
    check("ぼかし == 0 は0パス(スキップ)", passes_at[0] == 0)
    check("ぼかし == 1 は2パスだけ(r_hi=1, r_lo=0)", passes_at[1] == 2)
    check("ぼかし >= 2 は常に4パス(r_hi>0 かつ r_lo>0)",
          all(passes_at[b] == 4 for b in range(2, 101)))
    print(f"  ぼかし=0..5 のパス数: {[passes_at[b] for b in range(6)]}")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
