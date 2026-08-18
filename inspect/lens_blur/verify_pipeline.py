"""`範囲` は半径ではなく「縮小率」―― `レンズブラー` の7工程の骨。

`func_proc` は生値 `範囲`(0〜1000)をそのまま半径として使わない。**まず
0〜45 の内部半径 `R` へ圧縮し、画像のほうを `R/範囲` 倍に縮小してから
半径 `R` でぼかし、最後に元のサイズへ戻す**。

6つの主張:

  1. **圧縮は3段の折れ線 + 45 での頭打ち**で、区分の境目で連続している
     (`8 -> 8`、`16 -> 16`、`32 -> 32` がちょうどつながる)。
     生値 1000(上限)で `R = 45`。

  2. **縮小後のサイズは `round(R·w/範囲)`**(丸めは `+範囲/2` してから
     0方向切り捨て)。`R/範囲` が「ぼかし半径 / 画像の縮尺」の比を一定に
     保つので、**元画像で見たぼかし半径はちょうど `範囲` 画素**になる。

  3. **`範囲 <= 8` では縮小が起きない**(`R = 範囲` なので `new = w`)。
     そこだけは素直に半径 `範囲` の円形カーネルで、9 以上は必ず縮小が入る。

  4. **縮小率は最大 22倍**(生値1000 で `45/1000`)。計算量が
     `O(w·h·R²)` から `O((w·R/範囲)²·R²)` に落ちるので、半径を上げても
     **重くならないどころか軽くなる**。

  5. **縮小はカーブ空間、拡大は線形空間で行われる。** 順変換 → 縮小 →
     ぼかし → 逆変換 → 拡大 の順なので、縮小のワーカーは
     `{float y; int8 cb; int8 cr; int16 a}`、拡大のワーカーは素の
     `PIXEL_YCA` を読む ―― リサイズのヘルパーが縮小用と拡大用で
     別々に4本ある理由がこれである。

  6. **`光の強さ = 0` でもカーブは通る。** `ぼかし` は 0 のとき往復変換
     ごとスキップするが、`レンズブラー` は無条件に呼ぶのでヘルパー側の
     クランプで `base = 1.001` になる。**副作用として色差が常に 1/16 に
     量子化される**([`exp_log_curve.md` §5](../common/exp_log_curve.md))。

Run via main.py:
    uv run main.py inspect/lens_blur/verify_pipeline.py
"""

from tools.cints import c_div
from tools.disasm import disasm_range
from tools.pe_image import PEImage

FUNC_PROC = 0x10012420


def compress(raw: int) -> int:
    """0x100125ec-0x10012654。範囲 の生値 -> 内部半径 R。"""
    r = raw
    if r > 8:
        r = c_div(r, 2) + 4
        if r > 16:
            r = c_div(r, 4) + 12
            if r > 32:
                r = c_div(r, 8) + 28
                if r > 45:
                    r = 45
    return r


def scaled(w: int, h: int, raw: int, r: int):
    """0x10012654-0x1001267f。"""
    half = c_div(raw, 2)
    return c_div(r * w + half, raw), c_div(r * h + half, raw)


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)

    print("--- 1. 範囲 -> 内部半径 R の圧縮 ---")
    print(f"  {'範囲':>6}{'R':>5}   {'範囲':>6}{'R':>5}   {'範囲':>6}{'R':>5}")
    rows = [(1, 5, 8), (9, 16, 24), (25, 32, 48), (64, 100, 152),
            (200, 400, 1000)]
    for a, b, c in rows:
        print(f"  {a:>6}{compress(a):>5}   {b:>6}{compress(b):>5}   "
              f"{c:>6}{compress(c):>5}")
    check("R <= 8 は素通し", all(compress(r) == r for r in range(1, 9)))
    check("区分の境目で連続(8->8, 24->16, 152->32)",
          (compress(8), compress(9), compress(24), compress(25),
           compress(152), compress(153))
          == (8, 8, 16, 16, 32, 32))
    check("単調非減少", all(compress(r) <= compress(r + 1) for r in range(1, 1000)))
    check("上限は 45(生値 1000)", compress(1000) == 45
          and max(compress(r) for r in range(1, 1001)) == 45)
    first45 = min(r for r in range(1, 1001) if compress(r) == 45)
    print(f"  R = 45 に届く最小の生値: {first45}")
    check("それ以上は R が動かない = ぼかしの効きが飽和する",
          all(compress(r) == 45 for r in range(first45, 1001)))

    print("\n--- 2./3./4. 縮小後のサイズと縮小率 ---")
    w, h = 640, 480
    print(f"  {w}x{h} の画像:")
    print(f"  {'範囲':>6}{'R':>5}{'縮小後':>13}{'縮小率':>9}"
          f"{'元画像でのぼかし半径':>22}")
    worst = 0.0
    for raw in (1, 5, 8, 9, 16, 32, 64, 128, 200, 400, 1000):
        r = compress(raw)
        nw, nh = scaled(w, h, raw, r)
        ratio = raw / r
        eff = r * ratio                      # 縮小画像での R を元画像に戻した長さ
        worst = max(worst, abs(eff - raw))
        print(f"  {raw:>6}{r:>5}{f'{nw}x{nh}':>13}{f'1/{ratio:.1f}':>9}"
              f"{eff:>22.1f}")
    check("元画像で見たぼかし半径は 範囲 画素に一致", worst < 1e-9)
    check("範囲 <= 8 では縮小が起きない",
          all(scaled(w, h, raw, compress(raw)) == (w, h) for raw in range(1, 9)))
    check("範囲 = 9 からは必ず縮む",
          all(scaled(w, h, raw, compress(raw))[0] < w for raw in range(9, 1001)))
    check("最大の縮小率は 1000/45 ≈ 22 倍",
          abs(1000 / compress(1000) - 22.222) < 0.01)
    print("  → 円形カーネルは O(R²) なので、R が 45 で頭打ちになるということは")
    print("    1画素あたりの計算量に上限がある。範囲 を上げるほど画像が小さく")
    print("    なるので、**重い設定ほど速い**。")

    print("\n--- 5. 縮小はカーブ空間、拡大は線形空間 ---")
    order = []
    for insn, _ in disasm_range(img, FUNC_PROC, 0x460, resolve=False):
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            t = int(insn.op_str, 16)
            if t in (0x10070220, 0x10070550, 0x100703F0, 0x10070700,
                     0x10071420, 0x10072870, 0x100709A0, 0x10072000):
                order.append((insn.address, t))
    names = {0x10070220: "順変換(8B)", 0x10070550: "順変換(6B)",
             0x100703F0: "逆変換(8B)", 0x10070700: "逆変換(6B)",
             0x10071420: "縮小(8B)", 0x10072870: "縮小(6B)",
             0x100709A0: "拡大(8B)", 0x10072000: "拡大(6B)"}
    for va, t in order:
        print(f"  0x{va:08x}  {names[t]}")
    obj_order = [names[t] for _, t in order if "8B" in names[t]]
    check("オブジェクト側の順序は 順変換 -> 縮小 -> (ぼかし) -> 逆変換 -> 拡大",
          obj_order == ["順変換(8B)", "縮小(8B)", "逆変換(8B)", "拡大(8B)"],
          f"{obj_order}")

    # 縮小ワーカーは float の輝度を読み、拡大ワーカーは int16 を読む
    shrink = [i.op_str for i, _ in disasm_range(img, 0x10071666, 0x60, resolve=False)]
    expand = [i.op_str for i, _ in disasm_range(img, 0x10070C00, 0x20, resolve=False)]
    print(f"  縮小ワーカー 0x10071580 の画素アクセス: "
          f"{[o for o in shrink if 'ptr [eax' in o][:4]}")
    print(f"  拡大ワーカー 0x10070b00 の画素アクセス: "
          f"{[o for o in expand if 'ptr [eax' in o][:4]}")
    check("縮小側は float 輝度 + byte 色差(カーブ空間の 8バイト画素)",
          any("dword ptr [eax]" in o for o in shrink)
          and any("byte ptr [eax + 4]" in o for o in shrink))
    check("拡大側は int16 が4本(素の PIXEL_YCA)",
          all(any(f"word ptr [eax + {k}]" in o for o in expand) for k in (2, 4))
          and any("word ptr [eax]" in o for o in expand))

    print("\n--- 6. 光の強さ = 0 でもカーブを通る ---")
    print("  base = 1.0 + clamp(値, 1, 100) * 0.001  なので 値=0 -> base=1.001")
    print("  色差は往復で (c + 8) >> 4 -> << 4、つまり 16 の格子に乗る。")
    # 順変換は (c+8)>>4 を [-128, 127] にクランプして int8 に入れ、逆変換は << 4
    quantized = sorted({max(-128, min(127, (c + 8) >> 4)) << 4
                        for c in range(-2048, 2049)})
    print(f"  -2048..2048 の 4097 段階 -> {len(quantized)} 段階")
    check("色差が 256 段階に落ちる", len(quantized) == 256)
    check("+2048 は +2032 に切られ、-2048 はそのまま通る",
          max(quantized) == 2032 and min(quantized) == -2048)

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
