"""angr decompilation of カラーキー's func_proc, its three workers and its UI code.

The whole effect is one contiguous stretch of .text, `0x100162c0`-`0x100169f3`,
bounded below by 特定色域変換's func_WndProc (`0x10016020`) and above by
拡張色設定's func_proc (`0x10016a00`). The CFG window is pinned to that stretch
rather than derived from `--span`, so angr does not wander into either
neighbour.

Unlike every other effect analysed here, this one decompiles almost cleanly:
カラーキー contains **no floating point at all** - no x87, no `_ftol`, no
`pow` - so there is no `/* unsupported instruction */` hiding the arithmetic.
What the output shows:

  * func_proc has no pixel loop. It early-returns on `ex_data.status != 1`,
    fires the key worker, and - only if `境界補正 != 0` - writes two globals and
    fires three more workers.
  * **the second of those three is the key worker again** (`sub_10016340`
    appears twice in the same function). It is idempotent, so this is a wasted
    full-image pass, not a behavioural difference. verify_dispatch.py makes the
    case from the bytes rather than from angr's rendering.
  * the border-correction workers touch nothing but the alpha field: every
    memory access in them is `field_6` of an 8-byte pixel.
  * func_WndProc and its label routine are the same eyedropper protocol as
    クロマキー's, down to sharing the three cp932 strings.

Two places to distrust the output, both checked properly in disasm_params.py
and verify_border_chain.py:

  * angr reassociates the horizontal pass as `v16 * a0 / v15` where the
    instructions are `avg = sum / kw` **first** and `v = (avg * a) >> 12`
    second. Truncation makes those different numbers.
  * angr renders the `dec reg / jne` priming loops as `while (i != 1)`, i.e.
    one iteration short. `dec` sets ZF after the decrement, so they run r times.

Run via main.py:
    uv run main.py inspect/color_key/decompile_color_key.py
    uv run main.py inspect/color_key/decompile_color_key.py --only worker
"""

from tools.decompile import decompile_cli

REGION = (0x10016000, 0x10016A00)

TARGETS = {
    "func_proc                        0x100162c0": 0x100162C0,
    "worker: the key test             0x10016340": 0x10016340,
    "worker: 境界補正 pass2 (vertical) 0x10016430": 0x10016430,
    "worker: 境界補正 pass3 (horizontal+apply) 0x100165d0": 0x100165D0,
    "func_WndProc                     0x10016850": 0x10016850,
    "settings-window label            0x10016940": 0x10016940,
    "FILTER+0x58 hook                 0x100169e0": 0x100169E0,
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    decompile_cli(dll_path, TARGETS, argv, region=REGION)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
