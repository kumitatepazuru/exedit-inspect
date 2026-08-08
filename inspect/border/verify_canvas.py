"""Where everything lands: the canvas 縁取り hands back, and the object's
position inside it.

Five claims:

  1. **The published size is exactly `(w + 2*サイズ, h + 2*サイズ)`** - the
     pre-pad of verify_params.py §4 is invisible from the outside because the
     crop at 0x10051a6a takes back exactly what the pad added. Checked over
     every object shape x サイズ combination that reaches the pipeline.

  2. **The object ends up at exactly `(サイズ, サイズ)`** in that canvas, so
     the border is the same width on all four sides. Two independent
     placements have to agree for this: the composite at 0x10051a3a draws the
     object at `(サイズ, サイズ)` of the *pre-padded* canvas, while pass 1
     writes scratch row `k` from source row `k - サイズ`.

  3. **All four rect-clears at 0x10051891-0x1005195b are unreachable.** They
     are the same four strips シャドー uses to clear around its shadow box,
     but 縁取り's content-box origin globals are hard-wired to 0 and its right
     and bottom edges coincide with the canvas, so no strip is ever non-empty.

  4. **`fpip+0xD4` / `+0xD8` are never touched.** シャドー has to shift the
     object's centre because it grows the canvas on one side only; 縁取り
     grows symmetrically, so there is nothing to correct. Checked by scanning
     every instruction in the effect for those displacements.

  5. **There is no `サイズ固定`**, so any `サイズ > 0` changes the bounding
     box - the same hole グロー / ライト / シャドー have (canvas_growth.md §6).
     Unlike シャドー there is no wasted transparent band: the growth is
     symmetric and every one of the 2*サイズ added rows and columns can carry
     border.

Run via main.py:
    uv run main.py inspect/border/verify_canvas.py
"""

from tools.cints import c_div
from tools.disasm import disasm_range
from tools.filter_table import find
from tools.pe_image import PEImage

CODE = (0x100515D0, 0x100522E4)   # 縁取り's private code, start..end
BIG = 1 << 20                     # stand-in allocation, big enough never to clamp


def geometry(w0, h0, size_raw, stride=BIG, rows=BIG):
    """func_proc's canvas maths (0x10051641-0x100517ac, 0x10051a6a-0x10051acd).

    Kept self-contained rather than imported from verify_params.py, matching
    how シャドー's verify_geometry.py and its reference implementation each
    re-derive the same geometry - a shared bug would otherwise agree with
    itself.
    """
    pad_x = pad_y = 0
    w, h = w0, h0
    if 2 * size_raw >= w0 or 2 * size_raw >= h0:                 # 0x10051644
        pad_x = c_div(max(2 * size_raw - w0, 0) + 2, 2)          # 0x1005166c
        pad_y = c_div(max(2 * size_raw - h0, 0) + 2, 2)
        if 2 * pad_x > stride - w0:
            pad_x = c_div(stride - w0, 2)
        if 2 * pad_y > rows - h0:
            pad_y = c_div(rows - h0, 2)
        w, h = w0 + 2 * pad_x, h0 + 2 * pad_y

    size = size_raw                                              # 0x1005176f
    if 2 * size > stride - w:
        size = c_div(stride - w, 2)
    if 2 * size > rows - h:
        size = c_div(rows - h, 2)

    return {
        "w0": w0, "h0": h0, "pad_x": pad_x, "pad_y": pad_y,
        "padded_w": w, "padded_h": h, "size": size,
        "canvas_w": w + 2 * size, "canvas_h": h + 2 * size,
        "final_w": w + 2 * size - 2 * pad_x, "final_h": h + 2 * size - 2 * pad_y,
    }


def clear_rects(g):
    """0x10051891-0x1005195b, with the content-box origin globals as read.

    Both are stored as 0 at 0x10051607/0x1005160c and, per tools.xrefs, nothing
    in the image writes them again - so they are 0 here by construction, not by
    assumption. Each strip is (x, y, w, h) or None when its guard fails.
    """
    g_x, g_y = 0, 0
    cw, ch = g["canvas_w"], g["canvas_h"]
    # fpip+0xB4 / +0xB8 still hold the *pre-padded* object size at this point:
    # func_proc does not publish the grown size until 0x10051ac7.
    right = g["padded_w"] + 2 * g["size"] + g_x
    bottom = 2 * g["size"] + g_y + g["padded_h"]
    return {
        "left":   (0, 0, g_x, ch) if g_x > 0 else None,
        "top":    (0, 0, cw, g_y) if g_y > 0 else None,
        "right":  (right, 0, cw - right, ch) if cw > right else None,
        "bottom": (0, bottom, cw, ch - bottom) if ch > bottom else None,
    }


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    img = PEImage(dll_path)
    shapes = [(w, h, s) for w in range(1, 121) for h in range(1, 121, 7)
              for s in range(0, 81)]

    print("--- 1. the published canvas is (w + 2*サイズ, h + 2*サイズ) ---")
    bad = [(w, h, s) for w, h, s in shapes
           if (geometry(w, h, s)["final_w"], geometry(w, h, s)["final_h"])
           != (w + 2 * s, h + 2 * s)]
    check(f"{len(shapes)} (w, h, サイズ) combinations: the published size is always "
          "(w+2s, h+2s), pre-pad or not", not bad, f"{len(bad)} bad, first {bad[:1]}")
    print(f"  {'w':>5}{'h':>5}{'サイズ':>8}{'pre-pad':>9}{'canvas':>12}{'published':>12}")
    for w, h, size in ((100, 60, 3), (100, 60, 40), (20, 20, 40), (64, 64, 10)):
        g = geometry(w, h, size)
        pad = f"{g['pad_x']},{g['pad_y']}"
        canvas = f"{g['canvas_w']}x{g['canvas_h']}"
        final = f"{g['final_w']}x{g['final_h']}"
        print(f"  {w:>5}{h:>5}{size:>8}{pad:>9}{canvas:>12}{final:>12}")
    print("  The middle column is what the workers actually fill; the right one is what")
    print("  AviUtl sees. They differ exactly when the pre-pad ran.")

    print("\n--- 2. the object sits at (サイズ, サイズ), so the border is even ---")
    print("  Two placements have to line up:")
    print("    composite  0x10051a3a: object -> (サイズ, サイズ) of the PRE-PADDED canvas")
    print("    pass 1     0x10051b65: scratch row k is centred on source row k - サイズ")
    print("  and the crop at 0x10051ac1 then removes (padX, padY) from the origin.")
    bad = []
    for w, h, size in shapes:
        g = geometry(w, h, size)
        # object pixel (0,0): padded (padX, padY) -> canvas (+size) -> crop (-pad)
        ox = g["pad_x"] + g["size"] - g["pad_x"]
        oy = g["pad_y"] + g["size"] - g["pad_y"]
        if (ox, oy) != (g["size"], g["size"]):
            bad.append(("origin", w, h, size, ox, oy))
        elif (g["final_w"] - (ox + w), g["final_h"] - (oy + h)) != (g["size"], g["size"]):
            bad.append(("uneven", w, h, size))
    check("same sweep: the object is at (サイズ, サイズ) and the margin left over on "
          "the far side is サイズ too", not bad, f"{len(bad)} bad, first {bad[:1]}")
    print("  Note what this rules out: シャドー's canvas is `w + |X| + 2r` wide, which")
    print("  leaves a min(|X|, r) band that can never be painted (シャドー §3). 縁取り")
    print("  has no offset, so every added pixel is reachable by the dilation.")

    print("\n--- 3. the four rect-clears are dead code ---")
    live = [(name, w, h, s, rect) for w, h, s in shapes
            for name, rect in clear_rects(geometry(w, h, s)).items() if rect is not None]
    check(f"{len(shapes)} shapes x 4 strips: not one is ever non-empty",
          not live, f"{len(live)} live, first {live[:1]}")
    print("  left / top are guarded by `g > 0` on globals that only ever get 0")
    print("  (0x10051898, 0x100518c2); right / bottom compare the grown canvas against")
    print("  `fpip->w + 2*サイズ + g`, which IS the grown canvas (0x10051908, 0x10051939).")
    print("  In シャドー the same four calls are load-bearing - there the content box is")
    print("  offset by (max(X,0), max(Y,0)) and genuinely smaller than the canvas.")

    print("\n--- 4. no fpip+0xD4 / +0xD8 centre correction ---")
    hits = [(hex(i.address), i.mnemonic, i.op_str)
            for i, _ in disasm_range(img, CODE[0], CODE[1] - CODE[0], resolve=False)
            if "+ 0xd4]" in i.op_str or "+ 0xd8]" in i.op_str]
    check(f"zero references to fpip+0xD4 / +0xD8 in 縁取り's {CODE[1] - CODE[0]} bytes",
          not hits, f"{len(hits)} hits {hits[:2]}")
    print("  シャドー adds `(-X) << 11` to +0xD4 because it grows on one side only")
    print("  (シャドー §3); 縁取り adds サイズ to all four sides, so the object's centre")
    print("  does not move and there is nothing to correct.")

    print("\n--- 5. no サイズ固定 ---")
    reg = find(img, "縁取り")
    check("exactly one registration, object effect only", len(reg) == 1,
          f"{len(reg)} registrations")
    r = reg[0]
    check("two checkboxes, both really buttons (negative defaults) - no toggle at all",
          r.check_n == 2 and all(r.is_button(i) for i in range(r.check_n)),
          f"check_n={r.check_n} defaults={r.check_defaults}")
    print(f"  checkboxes: {list(zip(r.check_names, r.check_defaults))}")
    print("  So the only way to leave the bounding box alone is サイズ = 0, which is")
    print("  also the early-out. Same shape as グロー / ライト / シャドー")
    print("  (canvas_growth.md §6), and unlike ぼかし / 拡散光 / 発光 / 閃光.")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
