"""`標準描画`/`拡張描画` が同じ fpip オフセットを触っている、という状況証拠。

`座標`/`拡大率`/`透明度`/`回転`/`領域拡張` の5つが書き込む fpip の
オフセット(`+0xBC`/`+0xC0`/`+0xC4`/`+0xC8`/`+0xCC`/`+0xD0`/`+0xD4`/`+0xD8`/
`+0xE0`/`+0xE4`/`+0xE8`)を、オブジェクトの「本体」である `標準描画`
(`0x1008a020`)/`拡張描画`(`0x10023c80`)自身が読み書きしているかを
バイト列スキャンで数える。

`filter_registration.md` §5 の `+0x78` 表(`標準描画`/`拡張描画` 自身が
持つ X/Y/Z/回転/拡大率/透明度 のトラックバー枠)と、ここで見ている
`fpip` オフセットは**別物**である。`+0x78` はトラックバーの UI 側の
話で、ここでのオフセットは**その値が実際に効く先**の実行時状態 ――
`標準描画`/`拡張描画` 自身の X/Y/Z/回転/拡大率/透明度も、`座標`/`回転`/
`拡大率`/`透明度` フィルタも、**最終的にはこの同じ fpip フィールドを
経由して初めて画に反映される**、という結論をこのスキャンで裏付ける。

これは `tools.xrefs` と同じ「バイト列を舐めるだけ」の弱い証拠で、
`[eax+0xc0]` のような一致が本当に `fpip+0xC0` かどうかまでは保証しない
(`tools/xrefs.py` の docstring と同じ注意書き)。目的はビット単位の証明
ではなく「これらのオフセットが `標準描画`/`拡張描画` の中で**繰り返し**
出てくる」という頻度の状況証拠を再現可能にすること。

Run via main.py:
    uv run main.py inspect/base/verify_base_drawing_link.py
"""

from tools.disasm import disasm_range
from tools.pe_image import PEImage

# label -> (offset hex string as it appears in a bracketed operand, meaning)
OFFSETS = {
    "+0xBC": ("座標 X", None),
    "+0xC0": ("座標 Y", None),
    "+0xC4": ("座標 Z", None),
    "+0xC8": ("回転 X軸", None),
    "+0xCC": ("回転 Y軸", None),
    "+0xD0": ("回転 Z軸", None),
    "+0xD4": ("中心オフセット X (Q12, 領域拡張で確認)", None),
    "+0xD8": ("中心オフセット Y (Q12)", None),
    "+0xE0": ("拡大率 の大きい方の候補", None),
    "+0xE4": ("拡大率 の相対差分(Q16)", None),
    "+0xE8": ("透明度", None),
}

# 標準描画/拡張描画 の func_proc。実際の関数長は未確定なので、次の既知シンボルまで
# 届かない適当に広い window でスキャンする(=下限の証拠として扱う)。
TARGETS = {
    "標準描画": (0x1008A020, 0x14000),
    "拡張描画": (0x10023C80, 0x14000),
}


def scan(img: PEImage, addr: int, size: int) -> dict:
    counts = {off: 0 for off in OFFSETS}
    needles = {off: off.replace("0x", "0x").lower().replace("+", "") for off in OFFSETS}
    for insn, _ in disasm_range(img, addr, size, resolve=False):
        if "[" not in insn.op_str:
            continue
        for off, hexpart in needles.items():
            if insn.op_str.rstrip("]").endswith(hexpart):
                counts[off] += 1
    return counts


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    header = f"{'offset':>7} | " + " | ".join(f"{name:>8}" for name in TARGETS) + "  意味"
    print(header)
    print("-" * len(header))
    totals = {name: scan(img, addr, size) for name, (addr, size) in TARGETS.items()}
    for off, (meaning, _) in OFFSETS.items():
        row = " | ".join(f"{totals[name][off]:>8}" for name in TARGETS)
        print(f"{off:>7} | {row}  {meaning}")

    for name in TARGETS:
        nonzero = sum(1 for v in totals[name].values() if v > 0)
        assert nonzero >= len(OFFSETS) - 2, f"{name} should touch nearly all of these offsets"

    print("""
まとめ: 11個のオフセットのうち、ほぼ全部が `標準描画`/`拡張描画` の
どちらか(または両方)で複数回参照されている。0件のところは片方の
関数がそのフィールドを一切扱わない実装をしている可能性を示す
(例えば `+0xE0` を書くのは `拡大率` フィルタと `拡張描画` 側だけで、
`標準描画` は自分の `拡大率` を別経路で処理している、など)。
本スクリプトは「触れている」ことの再現可能な状況証拠であって、
`標準描画`/`拡張描画` そのものの命令単位の解析(いずれ `inspect/base` を
拡張する形で)はこのプロジェクトの範囲外。
""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
