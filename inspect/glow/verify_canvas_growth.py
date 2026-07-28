"""グロー grows the object twice, for two unrelated reasons, and has no
`サイズ固定` to turn either of them off.

**Growth 1 - make the kernel fit** (0x10054f11-0x10055070, object effect only).
The sliding-window workers need `2r+1 <= dimension`, so if the object is
narrower than the kernel func_proc pre-expands it exactly the way `ぼかし` and
`拡散光` do - method B of [`canvas_growth.md` §3](../common/canvas_growth.md):

    if (2*rx+1 > w || 2*ry+1 > h):
        bx = c_div(2*rx + 2 - w, 2);  by = c_div(2*ry + 2 - h, 2)
        clamp each so that w + 2*(rx+bx) <= max canvas, then to >= 0
        table[0x48](fpip+0xB0, 0, 0, w+2bx, h+2by, 0,0,0, 0, 2)     # fully transparent
        table[0x44](fpip+0xB0, bx, by, fpip+0xAC, 0,0, w, h, 0, 0x13000003)
        swap fpip+0xAC / fpip+0xB0 ;  w += 2*bx ;  h += 2*by

Note the clamp is written against the *final* size, not the pre-grown one - it
subtracts `2*rx` before dividing.

**Growth 2 - room for the glow itself** (0x100554a3-0x100554e3, unconditional).
Whatever happened above, the object ends `2*rx` wider and `2*ry` taller,
because the accumulation buffer was allocated and cleared at that size
(0x1005516c) and every shape worker writes into it offset by `(rx, ry)`.

The frame filter has no canvas, so it takes the other road: instead of growing
anything it clamps the radii to `c_div(dimension-1, 2)` (0x10055072), exactly
like 発光 does.

Section 3 is the one thing here that is not shared with other effects: because
the growth is unconditional and there is no `サイズ固定` checkbox, **拡散 always
changes the object's bounding box**, even at 形状=ライン(横) where the glow is
purely horizontal - the vertical margin is added anyway.

Run via main.py:
    uv run main.py inspect/glow/verify_canvas_growth.py
"""

from tools.cints import c_div
from tools.disasm import disasm_range, dump_all
from tools.filter_table import find
from tools.pe_image import PEImage

GROW = (0x10054F11, 0x60)
CLEAR_AND_COPY = (0x10054FC6, 0x68)
FRAME_CLAMP = (0x10055072, 0x38)
FINAL = (0x1005516C, 0x27)
SWAP = (0x100554A3, 0x46)

ANNOTATIONS = {
    0x10054F11: "eax = rx",
    0x10054F20: "2*rx + 1 vs w ...",
    0x10054F34: "... and 2*ry + 1 vs h. either being too big triggers the growth",
    0x10054F40: "eax = 2*rx + 2 - w",
    0x10054F4C: "cdq / sub / sar 1 = c_div(.., 2) -> bx",
    0x10054F58: "the same for by",
    0x10054F71: "w + (rx + bx)*2 vs max canvas width 0x10196748 ...",
    0x10054F83: "... too big: bx = c_div(max_w - 2*rx - w, 2)",
    0x10054F9B: "same check on the height",
    0x10054FBA: "bx < 0 -> 0",
    0x10054FC2: "by < 0 -> 0",
    0x10054FFB: "table[0x48]: clear fpip+0xB0 at (w+2bx, h+2by), alpha argument 0",
    0x1005502A: "table[0x44]: copy fpip+0xAC into it at (bx, by), mode 0x13000003",
    0x10055043: "swap fpip+0xAC ...",
    0x1005504F: "... and fpip+0xB0",
    0x10055060: "w += 2*bx",
    0x1005506A: "h += 2*by",
    0x10055072: "frame filter: no canvas to grow ...",
    0x1005507B: "... 2*rx+1 vs w ...",
    0x10055087: "... so clamp rx = c_div(w-1, 2) instead",
    0x100550A1: "and ry = c_div(h-1, 2)",
    0x1005516E: "alpha argument 0x1000: the accumulation buffer starts OPAQUE black",
    0x1005518F: "table[0x48] over the full (w+2rx, h+2ry)",
    0x100554A3: "swap the accumulation buffer in as the current image ...",
    0x100554C7: "... and grow the object by 2*ry ...",
    0x100554DE: "... and 2*rx. unconditional: there is no サイズ固定 here",
}


def pre_growth(w: int, h: int, rx: int, ry: int, max_w: int, max_h: int) -> tuple:
    """Replay of 0x10054f11-0x10054fc6. Returns (bx, by)."""
    if 2 * rx + 1 <= w and 2 * ry + 1 <= h:
        return 0, 0
    bx = c_div(2 * rx + 2 - w, 2)
    by = c_div(2 * ry + 2 - h, 2)
    if w + (rx + bx) * 2 > max_w:
        bx = c_div(max_w - 2 * rx - w, 2)
    if h + (ry + by) * 2 > max_h:
        by = c_div(max_h - 2 * ry - h, 2)
    return max(bx, 0), max(by, 0)


def final_size(w: int, h: int, spread: int, max_w: int, max_h: int) -> tuple:
    """The object's bounding box after func_proc returns."""
    rx = ry = spread
    if w + 2 * rx > max_w:
        rx = c_div(max_w - w, 2)
    if h + 2 * ry > max_h:
        ry = c_div(max_h - h, 2)
    bx, by = pre_growth(w, h, rx, ry, max_w, max_h)
    return w + 2 * bx + 2 * rx, h + 2 * by + 2 * ry


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_all(PEImage(dll_path), {
        "growth 1: does the kernel fit?": GROW,
        "growth 1: clear, copy, swap": CLEAR_AND_COPY,
        "frame filter: clamp instead of grow": FRAME_CLAMP,
        "the accumulation buffer, cleared to OPAQUE black": FINAL,
        "growth 2: unconditional +2rx / +2ry": SWAP,
    }, annotations=ANNOTATIONS)

    print("\n--- 1. there is no サイズ固定 checkbox on either registration ---")
    img = PEImage(dll_path)
    for name in ("グロー", "ぼかし", "拡散光", "発光", "閃光"):
        for r in find(img, name):
            if not r.flag & 0x20:
                continue
            has = "サイズ固定" in r.check_names
            print(f"  {name:<8} object effect: サイズ固定={'yes' if has else 'NO':<3}"
                  f"  checkboxes = {r.check_names}")
    print("  every other object effect here that grows its canvas has one. グロー")
    print("  does not, so neither growth below can be turned off from the UI.")
    print("  (`通常` in that list is check[0], the 形状 combo - see verify_shapes.py.)")

    max_w, max_h = 4096, 4096      # stand-ins for 0x10196748 / 0x101920e0
    print(f"\n--- 2. growth 1 fires only when the object is smaller than the kernel ---")
    print(f"  {'w x h':>12}{'拡散':>6}{'2r+1':>7}{'(bx, by)':>12}{'final size':>14}")
    for w, h, spread in ((200, 200, 30), (200, 200, 99), (200, 200, 100),
                         (200, 200, 120), (8, 8, 30), (1, 1, 200)):
        bx, by = pre_growth(w, h, spread, spread, max_w, max_h)
        fw, fh = final_size(w, h, spread, max_w, max_h)
        print(f"  {f'{w} x {h}':>12}{spread:>6}{2 * spread + 1:>7}"
              f"{str((bx, by)):>12}{f'{fw} x {fh}':>14}")
    print("  the boundary is 2*拡散+1 > w, i.e. 拡散 >= w/2. Below it only growth 2")
    print("  applies and the object grows by exactly 拡散 on each side.")

    print("\n--- 3. growth 2 is unconditional, and both axes always grow ---")
    print("  ライン(横) only ever writes a horizontal streak, but the canvas still")
    print("  gains 拡散 rows above and below:")
    for spread in (5, 30, 100):
        fw, fh = final_size(200, 200, spread, max_w, max_h)
        print(f"    200 x 200, 拡散={spread:<4} -> {fw} x {fh}"
              f"   (added {fw - 200} x {fh - 200}, all four sides)")
    print("  the transparent margin is harmless on its own, but it moves every")
    print("  downstream effect's idea of where the object is.")

    print("\n--- 4. the maximum-canvas clamp bites before the kernel-fit growth ---")
    print(f"  {'w x h':>12}{'拡散':>6}{'rx after clamp':>16}{'final size':>14}")
    for w, h, spread, mw in ((4000, 200, 200, 4096), (4090, 200, 200, 4096),
                             (4096, 200, 200, 4096)):
        rx = spread if w + 2 * spread <= mw else c_div(mw - w, 2)
        fw, fh = final_size(w, h, spread, mw, max_h)
        print(f"  {f'{w} x {h}':>12}{spread:>6}{rx:>16}{f'{fw} x {fh}':>14}")
    print("  rx is cut down first (0x10054e43), so the glow silently gets narrower")
    print("  as the object approaches the maximum canvas size rather than being")
    print("  clipped at the edge.")

    print("\n--- 5. what are 0x10178ec0 / 0x101790c8? ---")
    print("  the frame path compares against two globals this project has not named")
    print("  before. They are the pair `table[0x44]` and `table[0x48]` pick when the")
    print("  pixel is 6 bytes, exactly where they pick 0x10196748 / 0x101920e0 for")
    print("  8-byte pixels ([`canvas_growth.md` §1](../common/canvas_growth.md)):")
    for va, label in ((0x10178EC0, "width"), (0x101790C8, "height")):
        hits = [(a, s) for a, s in _refs_in(img, va)
                if 0x10081B40 <= a < 0x10082300 or 0x10054DB0 <= a < 0x10058EA0]
        print(f"  0x{va:08x} ({label}):")
        for a, s in hits:
            owner = ("グロー func_proc" if a < 0x10058EA0 else
                     "table[0x44] rect blit" if a < 0x10081F90 else
                     "table[0x48] rect clear")
            print(f"    0x{a:08x}  {s:<44} {owner}")
    print("  so 'maximum frame size', paired with the maximum object canvas.")
    print("  Who writes them is outside func_proc and not traced here.")


def _refs_in(img: PEImage, va: int):
    """Absolute references to `va` inside .text, as (address, disassembly)."""
    out = []
    for base in (0x10054DB0, 0x10081B40):
        for insn, _ in disasm_range(img, base, 0x5000, resolve=False):
            if f"[0x{va:08x}]" in insn.op_str:
                out.append((insn.address, f"{insn.mnemonic} {insn.op_str}"))
    return out


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
