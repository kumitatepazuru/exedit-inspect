"""The one-pixel frame, and how the rows are split between threads.

A 3x3 neighbourhood has nothing to stand on at the edge of the image, and
エッジ抽出 does not clamp or mirror - it writes the picked colour with **alpha
0** into the whole outermost ring and never looks at those pixels again:

    row 0        filled by whichever thread's first row is 0
    row h-1      filled by whichever thread's last row is h
    column 0     filled at the top of every row loop
    column w-1   filled at the bottom of every row loop

so the object loses its outermost pixel unconditionally. On a shape that already
reaches the edge of its bounding box - a 図形 rectangle, a フレームバッファ, an
image file - the outline along that edge is simply missing, and the fix is to
give the object a margin first (領域拡張 or a サイズ固定-less blur).

Section 1 counts the four fills mechanically: a fully transparent pixel is the
only place any worker stores a literal 0 into the alpha word, so
`mov word ptr [.. + 6], 0` counts them exactly.

Section 3 is about the thread split. The guards are on the *row numbers*, not on
the thread id:

    y0 = h * tid / n        `test y0, y0`  decides who fills row 0
    y1 = h * (tid+1) / n    `cmp y1, h`    decides who fills row h-1

which matters when `h < thread_num`: several threads then share `y0 == 0` and
all of them fill row 0. They write identical bytes, so the result is correct -
this is the same shape of harmless overlap as モザイク's `h < thread_num`
([`モザイク` §4](../mozaic/README.md)), and unlike it there is no arithmetic
involved that could differ.

Run via main.py:
    uv run main.py inspect/edge_extraction/verify_border.py
"""

from tools.disasm import disasm_range, dump_all
from tools.pe_image import PEImage

WORKERS = {
    "色エッジ": (0x10022E30, 0x100234BF),
    "輝度エッジ": (0x100234C0, 0x1002387C),
    "透明度エッジ": (0x10023880, 0x10023AE6),
}

PROLOGUE = (0x10022E30, 0x10022F7C - 0x10022E30)
ROW_TAIL = (0x10023465, 0x100234BF - 0x10023465)

ANNOTATIONS = {
    0x10022E35: "arg1 = thread id",
    0x10022E3B: "arg4 = fpip",
    0x10022E3F: "arg2 = thread_num  (arg3, fp, is never touched)",
    0x10022E43: "esi = h  = *(fpip+0xB8)",
    0x10022E49: "ebx = w  = *(fpip+0xB4)",
    0x10022E51: "h * tid ...",
    0x10022E55: "... / thread_num = y0",
    0x10022E5E: "h * (tid+1) ...",
    0x10022E66: "... / thread_num = y1",
    0x10022E68: "ebp = row stride in pixels = *(fpip+0xEC)",
    0x10022E6E: "**y0**, not the thread id",
    0x10022E74: "  nonzero -> somebody else owns row 0",
    0x10022E76: "ecx = *(fpip+0xB0), the output buffer",
    0x10022E84: "row 0: colour Y ...",
    0x10022E8E: "... Cb ...",
    0x10022E99: "... Cr ...",
    0x10022EA8: "... and alpha 0. A whole transparent row",
    0x10022EB8: "start the real work at row 1",
    0x10022EC0: "y1 == h ?",
    0x10022EC4: "  yes: this thread owns the last row, so shorten its range ...",
    0x10022ED9: "  ... and fill row h-1 the same way",
    0x10022F05: "nothing left to do -> return",
    0x10022F11: "row byte offset = stride * y0 * 8",
    0x10022F13: "ebx = w-1: the last column is not processed either",
    0x10022F2F: "top of the row loop: eax = out row, ecx = src row",
    0x10022F35: "column 0 gets the colour ...",
    0x10022F63: "... with alpha 0",
    0x10022F6F: "w-1 <= 1 -> the row is nothing but border",
    0x10022F76: "  -> straight to the column w-1 write",
    # ---- the row tail ---------------------------------------------------
    0x10023475: "column w-1: colour ...",
    0x1002349C: "... alpha 0",
    0x100234A6: "advance one row",
    0x100234B1: "next row",
    0x100234B7: "done",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("--- 1. how many transparent fills does each worker have? ---")
    print(f"  {'worker':<14}{'`mov word ptr [..+6], 0`':>28}   at")
    for name, (lo, hi) in WORKERS.items():
        hits = [i.address for i, _ in disasm_range(img, lo, hi - lo, resolve=False)
                if i.mnemonic == "mov" and i.op_str.endswith(", 0")
                and "word ptr" in i.op_str and "+ 6]" in i.op_str]
        print(f"  {name:<14}{len(hits):>28}   " + ", ".join(f"0x{a:08x}" for a in hits))
    print("  -> four in every worker: row 0, row h-1, column 0, column w-1.")
    print("     Nothing else in any worker writes a constant alpha.")

    print("\n--- 2. the prologue and the four fills, annotated (色エッジ) ---")
    dump_all(img, {"prologue + row 0 + row h-1 + column 0": PROLOGUE,
                   "row tail + column w-1": ROW_TAIL}, annotations=ANNOTATIONS)

    print("\n--- 3. the row split, and what happens when h < thread_num ---")
    for h, n in ((8, 4), (3, 4), (1, 4), (2, 8)):
        rows = [(t, h * t // n, h * (t + 1) // n) for t in range(n)]
        fills0 = [t for t, y0, _ in rows if y0 == 0]
        fills_last = [t for t, _, y1 in rows if y1 == h]
        interior = sorted({y for _, y0, y1 in rows
                           for y in range(max(y0, 1), y1 - (1 if y1 == h else 0))})
        print(f"  h={h} threads={n}:  ranges " +
              " ".join(f"[{y0},{y1})" for _, y0, y1 in rows))
        print(f"     row 0 filled by thread(s) {fills0}, row {h - 1} by {fills_last}, "
              f"interior rows actually convolved: {interior}")
    print("  -> every interior row is covered exactly once; the duplicates are only")
    print("     ever on the two constant rows, where each thread writes the same bytes.")
    print("  -> for h <= 2 there are no interior rows at all and the output is entirely")
    print("     transparent, the same way w <= 2 makes every row entirely border.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
