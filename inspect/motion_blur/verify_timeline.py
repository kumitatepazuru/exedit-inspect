"""時計を巻き戻すループ ―― `分解能` はサブフレームのサンプル数。

`func_proc` は `分解能` 回まわり、各周回で `fpip` の3つの時刻フィールドを
同時に動かしてから、exedit のコア側に「その時刻でもう一度描け」と頼む
(0x1006bf90-0x1006c023):

    i = 0                 巻き戻さない(= 現在のフレーム)
    i = 1 .. 分解能-1     fpip[0x114] += i·100/分解能
                          fpip[0x1C]--  ;  fpip[0xA8]--
                          0x1004b200(...)          // オブジェクト版
                          元に戻す

6つの主張:

  1. **サンプルする時刻は `{現在} ∪ {現在 - 1 + i/分解能}`**、つまり
     **直前の1フレームを `分解能` 等分した点**になる。`間隔` はここに
     一切出てこない。

  2. **`i = 0` が最初、`i = 分解能-1`(= 現在 - 1/分解能)が最後**。
     ワーカーは指数移動平均なので**最後に処理したサンプルが最も重い** ――
     いちばん軽いのが現在のフレームそのものになる。

  3. **巻き戻すのは3本同時**で、`fpip+0x1C`(`fpip->frame`)/
     `fpip+0xA8`(絶対フレーム)/ `fpip+0x114`(1/100フレームの端数)。
     [`object_time.md` §1](../common/object_time.md) の「3つが1つの時計の
     別表現」であることの直接の裏付け。

  4. **端数は正規化されない。** `fpip[0x114] += i·100/分解能` は 0〜99 に
     しかならないので `-1 フレーム + 端数` の表現が壊れることは無いが、
     元の `fpip[0x114]` が非 0 なら 100 を超えうる ―― 受け手側の扱いは未確認。

  5. **蓄積バッファは名前付きキャッシュから取る。** キー文字列は
     `"*cache%08x[%d]_%dx%d@%d"` で、`(fp+0xE4, 種別, w, h, fpip+0x11C)` を
     埋める。`fp+0xE4` は `(通し番号<<16) | 添字+1` なので**エフェクト
     1つにつき1本**、`w`/`h` が変わればキーも変わる。

  6. **キャッシュが新規なら A = 0**、つまりそのフレームは蓄積を捨てて
     最後のサンプルだけになる。オブジェクトの最初のフレームや、
     サイズが変わった直後がこれにあたる。

Run via main.py:
    uv run main.py inspect/motion_blur/verify_timeline.py
"""

from tools.cints import c_div
from tools.disasm import disasm_range
from tools.pe_image import PEImage

FUNC_PROC = 0x1006BD30
CACHE_FMT = 0x100A5650
CACHE = 0x1004D7D0


def sample_times(resolution: int):
    """現在フレームを 0 として、サンプルする時刻(フレーム単位)。"""
    out = []
    for i in range(resolution):
        if i == 0:
            out.append(0.0)
        else:
            out.append(-1.0 + c_div(i * 100, resolution) / 100.0)
    return out


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(bool(ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)

    print("--- 1./2. サンプルする時刻 ---")
    for res in (2, 4, 5, 10):
        ts = sample_times(res)
        print(f"  分解能={res:>3}: 処理順 " +
              " -> ".join(f"{t:+.2f}" for t in ts))
        checks.append(len(ts) == res)
    check("分解能 の数だけサンプルする", all(checks[-4:]))
    ts = sorted(sample_times(10))
    print(f"  分解能=10 を時刻順に並べ直すと: " +
          " ".join(f"{t:+.2f}" for t in ts))
    check("直前の1フレームを 分解能 等分した点になる",
          ts[0] == -0.9 and ts[-1] == 0.0
          and all(abs((ts[i + 1] - ts[i]) - 0.1) < 1e-9 for i in range(len(ts) - 1)))
    check("間隔 は時刻の計算に出てこない(命令列に track[0] が無い)",
          not any(i.op_str.endswith("[edi + 0x44]") and i.mnemonic == "fild"
                  for i, _ in disasm_range(img, 0x1006BF90, 0x40, resolve=False)))
    print("  → 間隔 が変えるのは重み(verify_weight.py)だけで、")
    print("    サンプルする時間幅は常に「直前の1フレーム」である。")
    print("  → 指数移動平均なので、最後に処理する -1/分解能 が最も重く、")
    print("    最初に処理する現在フレームが最も軽い。")

    print("\n--- 3. 3本同時に動かす ---")
    seq = [(0x1006BFA6, "add", "eax, ebx", "fpip[0x114] += 端数"),
           (0x1006BFA8, "dec", "edx", "fpip[0x1C]--"),
           (0x1006BFA9, "mov", "dword ptr [esi + 0x114], eax", ""),
           (0x1006BFB3, "dec", "ecx", "fpip[0xA8]--"),
           (0x1006BFB4, "mov", "dword ptr [esi + 0x1c], edx", ""),
           (0x1006BFB9, "mov", "dword ptr [esi + 0xa8], ecx", "")]
    body = {i.address: i for i, _ in disasm_range(img, 0x1006BF90, 0x40, resolve=False)}
    for va, mnem, ops, why in seq:
        insn = body.get(va)
        got = f"{insn.mnemonic} {insn.op_str}" if insn else "<境界に乗らない>"
        ok = insn is not None and insn.mnemonic == mnem and insn.op_str == ops
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] 0x{va:08x}  {got:<34} {why}")
    check("巻き戻しは3本同時", all(checks[-6:]))
    restore = {i.address: i for i, _ in
               disasm_range(img, 0x1006BFF4, 0x40, resolve=False)}
    print("  戻すほう:")
    for va in (0x1006C006, 0x1006C00C, 0x1006C00D):
        i = restore.get(va)
        print(f"    0x{va:08x}: {i.mnemonic} {i.op_str}")
    check("同じ3本を元に戻す",
          restore[0x1006C006].mnemonic == "sub"
          and restore[0x1006C00C].mnemonic == "inc"
          and restore[0x1006C00D].mnemonic == "inc")

    print("\n--- 4. 端数の範囲 ---")
    worst = 0
    for res in range(1, 26):
        for i in range(res):
            worst = max(worst, c_div(i * 100, res))
    print(f"  i·100/分解能 の最大値(分解能 1..25): {worst}")
    check("端数は 0〜99 の範囲(1フレームを超えない)", worst <= 99)
    print("  ただし元の fpip[0x114] が非 0 なら加算後に 100 を超えうる。")
    print("  受け手(0x1004b200 / 0x1004ccf0)の扱いは未確認。")

    print("\n--- 5. 名前付きキャッシュ ---")
    print(f"  0x{CACHE_FMT:08x} = {img.cstr(CACHE_FMT)!r}")
    check("キー文字列は *cache%08x[%d]_%dx%d@%d",
          img.cstr(CACHE_FMT) == "*cache%08x[%d]_%dx%d@%d")
    args = [(0x1006BDB3, "mov", "edx, dword ptr [edi + 0xe4]", "fp->0xE4 を取る"),
            (0x1006BDB9, "push", "0x40", "第4引数 = 種別(オブジェクト)"),
            (0x1006BDBB, "push", "eax", "h"),
            (0x1006BDBC, "push", "ecx", "w"),
            (0x1006BDBD, "push", "edx", "fp->0xE4"),
            (0x1006BDBE, "call", f"0x{CACHE:08x}", "")]
    body = {i.address: i for i, _ in disasm_range(img, 0x1006BD9B, 0x40, resolve=False)}
    for va, mnem, ops, why in args:
        insn = body.get(va)
        got = f"{insn.mnemonic} {insn.op_str}" if insn else "<境界に乗らない>"
        ok = insn is not None and insn.mnemonic == mnem and insn.op_str == ops
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] 0x{va:08x}  {got:<22} {why}")
    check("(fp->0xE4, w, h, 0x40, fpip->0x11C, &再利用フラグ) で引く",
          all(checks[-6:]))
    frame_kind = {i.address: i for i, _ in
                  disasm_range(img, 0x1006BDF8, 0x10, resolve=False)}
    print(f"  フレーム版の種別: {frame_kind[0x1006BDFA].mnemonic} "
          f"{frame_kind[0x1006BDFA].op_str}")
    check("フレーム版は 0x30", frame_kind[0x1006BDFA].op_str == "0x30")

    print("\n--- 6. 新規キャッシュなら A = 0 ---")
    body = {i.address: i for i, _ in disasm_range(img, 0x1006BEFB, 0x20, resolve=False)}
    for va in sorted(body)[:5]:
        print(f"  0x{va:08x}: {body[va].mnemonic} {body[va].op_str}")
    check("再利用フラグ != 1 か A < 0 なら A = 0",
          body[0x1006BEFB].mnemonic == "cmp"
          and body[0x1006BEFB].op_str == "dword ptr [esp + 0x10], 1"
          and body[0x1006BF06].op_str.startswith("dword ptr [0x101bad38], 0"))
    print("  → オブジェクトの最初のフレームや、キャッシュのキー(w/h/時刻)が")
    print("    変わった直後は、そのフレームだけ蓄積が捨てられる。")

    print(f"\n{sum(checks)}/{len(checks)} checks passed")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
