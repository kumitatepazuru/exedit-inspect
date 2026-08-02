"""func_proc's parameter and geometry code, instruction by instruction, plus
the parts of the four workers that the decompiler cannot show.

Three things are worth having in mind while reading the dump:

  1. **Only `濃さ` goes through the usual /1000 conversion.** `X`, `Y` and
     `拡散` are used as raw pixel counts - there is exactly one `0x10624dd3`
     in the whole effect (param_scaling.md §2), and it produces
     `density = trunc(濃さ_raw * 4096 / 1000)`, the Q12 opacity that pass 4
     multiplies the blurred alpha by.

  2. **The canvas grows by `|X| + 2r` and `|Y| + 2r`, and the two placements
     are not symmetric.** The shadow's box goes at `(max(X,0), max(Y,0))` and
     the object at `(max(-X,0)+r, max(-Y,0)+r)`, so the shadow ends up offset
     from the object by exactly `(X, Y)` however the signs fall
     (verify_geometry.py §2). The `-r` that the negative-X branch subtracts
     before clamping at 0 can never survive that clamp - it is dead in every
     reachable state, and saying so requires reading the actual `jns`, not the
     decompiler's reconstruction of it.

  3. **The radius is split into halves and the blur runs four passes.**
     `r1 = trunc(拡散/2)`, `r2 = 拡散 - r1`, kernel widths `2*r1+1` (A, at
     0x10231f98) and `2*r2+1` (B, at 0x10231f94). Passes 1-2 use B, passes 3-4
     use A, one vertical and one horizontal each, so each axis is convolved
     with `box(2*r2+1) ⊛ box(2*r1+1)` = a triangle of half-width `拡散`
     exactly (verify_blur_chain.py). This is ぼかし's scheme (box_blur.md §2),
     applied to the alpha channel alone.

Caveat, as usual: angr does not lift x87. Every floating-point instruction in
this effect lives in the two pass-4 encoders, and those are the ranges at the
bottom of this dump.

Run via main.py:
    uv run main.py inspect/shadow/disasm_params.py
"""

from tools.disasm import dump_all
from tools.pe_image import PEImage

# ---- func_proc 0x10087fb0, in the order it executes
ENTRY = (0x10087FB0, 0x2C)        # prologue, 濃さ == 0 early-out
PARAMS = (0x10087FDC, 0x68)       # X/Y/濃さ/拡散 -> globals; check[0] zeroes the offset
GROW = (0x10088044, 0x75)         # canvas = (w+|X|, h+|Y|), clamped to the allocated buffer
RCLAMP = (0x100880B9, 0x34)       # 拡散 -> r, clamped against the REMAINING margin only
CENTRE = (0x100880ED, 0x42)       # +2r on both axes; fpip+0xD4/+0xD8 centre correction
PLACE = (0x1008812F, 0x7D)        # shadow origin (g_X,g_Y) and object origin (obj_x,obj_y)
PATTERN = (0x100881AC, 0xD4)      # load パターン画像ファイル and tile it over the shadow box
CLEAR = (0x10088280, 0xCD)        # clear the four strips outside the shadow box
KERNELS = (0x1008834D, 0x52)      # scratch planes, radius split, kernel widths, 影色 -> YCbCr
DISPATCH = (0x1008839F, 0x70)     # four blur passes, then one of the two encoders
SEPARATE = (0x1008840F, 0x105)    # check[0] on: hand the shadow to the drawing pipeline
COMPOSITE = (0x10088514, 0x6A)    # check[0] off: draw the object on top, swap, resize

# ---- the workers: only the parts that pin down direction, source and rounding
P1_HEAD = (0x1008858F, 0x49)      # pass 1: split by column, kernel B
P1_BODY = (0x100885DC, 0x40)      # pass 1: read alpha at +6, divide by kernel B, store 16-bit
P2_HEAD = (0x100886F0, 0x41)      # pass 2: split by row over h+kernelB-1
P2_BODY = (0x10088755, 0x30)      # pass 2: plane 1 -> plane 2, stepping by 2 bytes = horizontal
P3_HEAD = (0x10088840, 0x63)      # pass 3: split by column over w+kernelB-1, switch to kernel A
P4_HEAD = (0x100889A0, 0x7E)      # pass 4: the x87 scale = density / (kernelA * 4096)
P4_STORE = (0x10088A33, 0x74)     # pass 4: the flat-colour + alpha pixel write
P4PAT_HEAD = (0x10088C13, 0x31)   # pattern variant: the same scale, times 1/4096
P4PAT_STORE = (0x10088C88, 0x3D)  # pattern variant: multiply the pattern's own alpha

ANNOTATIONS = {
    # ---------------------------------------------------------------- entry
    0x10087FB4: "edi = fp",
    0x10087FBA: "fp->ex_data_ptr, parked in a caller-owned slot (re-read at 0x10088379)",
    0x10087FC1: "eax = fp->track  ([0]=X, [1]=Y, [2]=濃さ, [3]=拡散)",
    0x10087FC4: "track[2] == 0 ?  (濃さ, the only trackbar with an early-out)",
    0x10087FC7: "濃さ == 0 -> return 1. no canvas growth, no buffer touched at all",
    0x10087FD0: "esi = fpip (2nd argument), held for the rest of func_proc",
    0x10087FD4: "obj_x accumulator = 0  (becomes max(-X,0)+r at 0x1008818b)",
    0x10087FD8: "obj_y accumulator = 0",
    # --------------------------------------------------------------- params
    0x10087FDC: "ecx = track[0] = X raw  (pixels; no /1000 anywhere on X/Y/拡散)",
    0x10087FDE: "ebp = fpip+0xB4 = object width w",
    0x10087FE4: "ebx = fpip+0xB8 = object height h",
    0x10087FEA: "g_X (0x10231fa4) = X",
    0x10087FF3: "eax = track[1] = Y raw",
    0x10087FF6: "g_Y (0x10231fa8) = Y",
    0x10088003: "ecx = track[2] = 濃さ raw (0..1000, display scale 10 -> 0.0..100.0%)",
    0x10088006: "濃さ << 12 ...",
    0x10088009: "... magic 0x10624dd3 ...",
    0x10088015: "g_density (0x10231f9c) = trunc(濃さ*4096/1000). THE only /1000 in this effect",
    0x10088021: "edx = track[3] = 拡散 raw -> used directly as the radius r",
    0x1008802A: "edx = fp->check[0] = 影を別オブジェクトで描画",
    0x1008802E: "unchecked -> keep X/Y",
    0x10088030: "checked: g_X = 0 ...",
    0x10088036: "... g_Y = 0. the offset is applied to the whole drawn object later "
                "(0x1008842b) instead of to the shadow inside this canvas",
    0x1008803E: "ecx = g_X (whichever of the two branches wrote it)",
    # ------------------------------------------------------- canvas growth
    0x10088046: "cdq/xor/sub = |X| ...",
    0x1008804B: "... ebp = w + |X|",
    0x10088057: "ebx = h + |Y|  (same |.| idiom on g_Y)",
    0x10088059: "eax = fpip+0xEC = the ALLOCATED row stride, not just w",
    0x1008805F: "w + |X| vs stride ...",
    0x10088067: "... X > 0 and too wide: X += stride - (w+|X|)  ->  X = stride - w",
    0x1008806D: "... X <= 0 and too wide: X += (w+|X|) - stride  ->  X = -(stride - w)",
    0x10088071: "g_X = the clamped offset; |X| now fits the allocated buffer exactly",
    0x1008807D: "same clamp against fpip+0xF0 = the allocated row COUNT",
    # --------------------------------------------------------- radius clamp
    0x100880BF: "edx = r (拡散 raw)",
    0x100880C3: "eax = stride - (w+|X|) = the margin the offset has NOT already eaten",
    0x100880C7: "2r vs that margin ...",
    0x100880CB: "... too big: r = trunc(margin/2)  (cdq;sub;sar = c_div by 2)",
    0x100880DC: "same again for the vertical margin, rows - (h+|Y|)",
    0x100880E5: "NOTE: r is never compared against w or h themselves - see verify_params.py §5",
    # ------------------------------------------------------------ centring
    0x100880F7: "eax = 2r",
    0x100880F9: "ecx = -X",
    0x100880FF: "canvas width  = w + |X| + 2r",
    0x10088101: "canvas height = h + |Y| + 2r",
    0x10088109: "(-X) << 11 = -(X/2) in 1/4096-pixel units",
    0x10088112: "fpip+0xD4 -= X/2 px: the canvas grew by |X| on ONE side, so the object's "
                "centre moves half that far the other way. 2048 = 4096/2 confirms the "
                "1/4096-pixel unit independently of 閃光 (canvas_growth.md §7)",
    0x10088129: "fpip+0xD8 -= Y/2 px, same reasoning. the symmetric +2r needs no correction",
    # ----------------------------------------------------------- placement
    0x1008812F: "ecx = g_X",
    0x10088137: "X >= 0 -> skip; g_X stays X and the object gets no extra left margin",
    0x1008813D: "X < 0: object origin x = |X|",
    0x10088145: "ecx = X - r ...",
    0x10088147: "... g_X = X - r, provisionally",
    0x1008814D: "... and jns only keeps it when X-r >= 0, which cannot happen here "
                "(X<0, r>=0). DEAD: g_X is always 0 on this branch, i.e. g_X = max(X,0)",
    0x10088151: "g_X = 0",
    0x10088159: "X >= 0 path: eax = r (the shared value the two adds below need)",
    0x10088165: "Y >= 0 -> skip; same dead `- r` on the Y side",
    0x1008816D: "Y < 0: g_Y = Y - r, then clamped to 0 the same way",
    0x1008818B: "object origin x = max(-X,0) + r",
    0x10088195: "object origin y = max(-Y,0) + r",
    # ------------------------------------------------------------- pattern
    0x100881A1: "eax = ex_data+4 = the パターン画像ファイル path (256 bytes, verify_ex_data.py)",
    0x100881AC: "empty path -> skip the whole tiling block",
    0x100881C4: "the shared scratch buffer [0x101a5328] doubles as the decode target",
    0x100881CA: "table[0x38](scratch, path, &patW, &patH, 0, 0): exedit's image loader "
                "(0x1004c8d0, shared with the 画像ファイル object). 0 = failure",
    0x100881D2: "load failed -> fall through with patW = patH = 0, so the plain encoder runs",
    0x1008820A: "mode 0x13000003 = simple copy, 8-byte pixels both sides (blend_modes.md §3)",
    0x10088238: "table[0x44](fpip+0xB0, g_X+tileX, g_Y+tileY, scratch, 0,0, patW, patH, 0, mode) "
                "- tiled from the shadow box's own corner, not from the canvas corner",
    0x1008824B: "inner loop bound: canvasW - g_X",
    0x1008826C: "outer loop bound: canvasH - g_Y",
    # -------------------------------------------------------------- clears
    0x10088280: "g_X > 0 ?",
    0x1008829E: "table[0x48](fpip+0xB0, 0, 0, g_X, canvasH, 0,0,0,0, 2) = clear the LEFT strip "
                "to fully transparent (blend_modes.md §4)",
    0x100882CD: "... the TOP strip, height g_Y",
    0x100882E3: "eax = g_X + w + 2r = the shadow box's right edge",
    0x100882F5: "ecx = g_Y + h + 2r = its bottom edge",
    0x1008831C: "... the RIGHT strip",
    0x10088347: "... the BOTTOM strip. what survives is exactly the shadow box",
    # ------------------------------------------------------------- kernels
    0x10088356: "plane 1 (0x10231f90) = [0x101a5328], the buffer 発光/グロー/クロマキー/ライト "
                "also borrow - here as 16-bit alpha, canvas stride",
    0x10088361: "stride * canvasH ...",
    0x10088367: "... plane 2 (0x10231fa0) = plane 1 + stride*canvasH*2  (2 bytes/sample)",
    0x1008836F: "r1 = trunc(r/2)",
    0x10088373: "r2 = r - r1 = ceil(r/2)",
    0x10088381: "kernel A (0x10231f98) = 2*r1 + 1",
    0x10088387: "kernel B (0x10231f94) = 2*r2 + 1",
    0x1008838D: "ecx = ex_data dword[0] = 影色 (bytes 0..2 = R,G,B; byte 3 unused padding)",
    0x1008839F: "sub_1006fed0: Y -> 0x102320b8, Cb -> 0x102320b4, Cr -> 0x102320b6 "
                "(the shared BT.601 Q14 conversion, rgb_ycbcr.md)",
    # ------------------------------------------------------------ dispatch
    0x100883AE: "exec_multi_thread_func(sub_10088580): pass 1, vertical, kernel B",
    0x100883BE: "... sub_100886f0: pass 2, horizontal, kernel B",
    0x100883CE: "... sub_10088840: pass 3, vertical, kernel A",
    0x100883DD: "patW == 0 ...",
    0x100883E5: "... or patH == 0 -> the plain encoder",
    0x100883F1: "... sub_10088bc0: pass 4 with a pattern image (colour comes from the pattern)",
    0x10088403: "... sub_100889a0: pass 4 plain (colour comes from 影色の設定)",
    # ----------------------------------------------- 影を別オブジェクトで描画
    0x1008840F: "check[0] == 0 -> the ordinary composite path at 0x10088514",
    0x1008841B: "checked: 3rd argument to sub_1004b200, constant 0x10fffff",
    0x10088423: "g_X restored to the real X (only so the two shifts below can use it)",
    0x1008842B: "X << 12 = X in 1/4096-pixel units",
    0x10088451: "fpip+0xBC += X*4096  (the object POSITION field, distinct from the "
                "+0xD4 centre correction above)",
    0x1008846B: "fpip+0xC0 += Y*4096",
    0x1008847B: "fpip+0xB4 = w + 2r ...",
    0x10088481: "... fpip+0xB8 = h + 2r  (no |X|/|Y| here: they were zeroed at 0x10088030)",
    0x10088487: "swap fpip+0xAC <-> fpip+0xB0: the shadow canvas becomes 'the image'",
    0x1008849A: "sub_1004b200(fp+0xE4, fpip, 0x10fffff): hand it to exedit's drawing "
                "pipeline as its own object. internals not traced (README §11)",
    0x100884B1: "swap back ...",
    0x100884CD: "... restore w and h ...",
    0x100884EC: "... and undo the +0xBC / +0xC0 offsets. the original object then "
                "continues down the effect chain completely untouched",
    0x10088507: "return 1",
    # ----------------------------------------------------------- composite
    0x10088520: "mode 3 = normal composite (src over dst), 8-byte pixels (blend_modes.md)",
    0x10088545: "table[0x44](fpip+0xB0, obj_x, obj_y, fpip+0xAC, 0, 0, w, h, 0, 3): the "
                "object, unmodified, on top of the shadow",
    0x10088557: "swap fpip+0xAC <-> fpip+0xB0",
    0x10088563: "fpip+0xB4 = w + |X| + 2r ...",
    0x10088569: "... fpip+0xB8 = h + |Y| + 2r. there is no サイズ固定 on this effect",
    # ------------------------------------------------------------- pass 1
    0x1008858F: "eax = fpip+0xB8 = h (the row count this pass slides over)",
    0x10088595: "ecx = fpip+0xB4 = w",
    0x100885A2: "(tid+1) * w ...",
    0x100885AA: "... / thread_num: pass 1 splits by COLUMN",
    0x100885AC: "the row step comes from fpip+0xEC, the canvas stride - both planes use it",
    0x100885D0: "ecx = kernel B",
    0x100885DC: "edx = fpip+0xAC = the object's own pixels",
    0x100885EA: "ebx = fpip+0xAC + col*8: 8 bytes/pixel PIXEL_YCA",
    0x100885ED: "edx = plane 1",
    0x100885F5: "edi = plane 1 + col*2: 2 bytes/sample, alpha only",
    0x100885FA: "movsx from +6 = the ALPHA. y/cb/cr of the object are never read by any pass",
    0x10088603: "idiv kernel B: divided by the full kernel width even while the window is "
                "still filling, i.e. off-image counts as transparent (box_blur.md §3)",
    0x10088615: "store 16-bit",
    0x10088618: "head-phase counter ...",
    0x1008862B: "... which runs kernelB times, so this pass emits h + kernelB - 1 rows",
    # ------------------------------------------------------------- pass 2
    0x100886F3: "ecx = kernel B again",
    0x10088718: "ebx = h + kernelB - 1 = exactly what pass 1 wrote",
    0x10088726: "split by ROW this time",
    0x10088755: "eax = plane 2 (destination)",
    0x10088765: "eax = plane 1 (source)",
    0x10088776: "+= 2 bytes per step, not += stride*2: this pass is HORIZONTAL",
    0x1008877F: "idiv kernel B",
    # ------------------------------------------------------------- pass 3
    0x10088847: "eax = kernel B (only to recompute the intermediate's extents)",
    0x1008885A: "esi = w + kernelB - 1 = the intermediate width, split by COLUMN",
    0x1008886E: "eax = h + kernelB - 1 = the intermediate height",
    0x1008889D: "ecx = kernel A: passes 3 and 4 use the OTHER half of the radius",
    0x100888A3: "read plane 2 ...",
    0x100888B4: "... write plane 1. output height becomes h + kernelB + kernelA - 2 = h + 2r",
    # ------------------------------------------------------------- pass 4
    0x100889B3: "fild g_density: the Q12 opacity from 濃さ, pushed once per thread",
    0x100889C6: "edx = w + kernelB - 1 = the width pass 3 left behind",
    0x100889E0: "ebx = h + kernelA + kernelB - 2 = h + 2r rows to emit",
    0x100889F5: "eax = kernelA * 4096",
    0x10088A05: "fdivp: st0 = density / (kernelA * 4096). the horizontal box average and "
                "the Q12 opacity are folded into ONE multiply - there is no idiv here",
    0x10088A33: "eax = g_Y + row",
    0x10088A43: "... * stride + g_X: the shadow box's origin inside fpip+0xB0",
    0x10088A4B: "esi = destination pixel (8 bytes)",
    0x10088A53: "edi = plane 1 + row*stride*2 (source, 2 bytes)",
    0x10088A62: "sum += plane1[x]  (the sliding sum is NOT divided by kernelA here)",
    0x10088A6F: "sum == 0 -> only the alpha is written; y/cb/cr keep the buffer's old "
                "contents (harmless: alpha 0, box_blur.md §1)",
    0x10088A71: "dst.y  = 影色 Y   -- stored STRAIGHT, not amplify-multiplied like ライト/閃光",
    0x10088A7F: "dst.cb = 影色 Cb",
    0x10088A89: "dst.cr = 影色 Cr",
    0x10088A78: "fild sum ...",
    0x10088A90: "... fmul st(1) = sum * density / (kernelA*4096) ...",
    0x10088A96: "... _ftol = truncate toward zero (integer_semantics.md)",
    0x10088A9B: "dst.a = that. bounded by density <= 4096, so no clamp is needed",
    0x10088AA1: "sum == 0: dst.a = 0, colour untouched",
    # ------------------------------------------------- pass 4, pattern variant
    0x10088C13: "eax = kernelA * 4096, same as the plain encoder",
    0x10088C2C: "... then x 1/4096: st0 = density / (kernelA * 4096 * 4096)",
    0x10088C88: "movsx from dst+6 = the alpha of the TILED PATTERN already sitting there",
    0x10088C95: "fild patternAlpha ...",
    0x10088C9D: "... fimul sum ...",
    0x10088CA1: "... fmul st(1) = patternAlpha * sum * density / (kernelA*4096*4096)",
    0x10088CA8: "dst.a = that. y/cb/cr are NEVER written: the pattern's own colour stays, "
                "and 影色の設定 has no effect at all in this mode",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_all(img, {
        "func_proc: prologue, 濃さ == 0 early-out": ENTRY,
        "func_proc: trackbars -> globals, 影を別オブジェクトで描画 zeroes X/Y": PARAMS,
        "func_proc: canvas = (w+|X|, h+|Y|), clamped to the allocated buffer": GROW,
        "func_proc: 拡散 -> r, clamped against the remaining margin only": RCLAMP,
        "func_proc: +2r per axis, fpip+0xD4/+0xD8 centre correction": CENTRE,
        "func_proc: shadow origin (g_X, g_Y) and object origin (obj_x, obj_y)": PLACE,
        "func_proc: load パターン画像ファイル and tile it over the shadow box": PATTERN,
        "func_proc: clear the four strips outside the shadow box": CLEAR,
        "func_proc: scratch planes, radius split, kernel widths, 影色 -> YCbCr": KERNELS,
        "func_proc: four blur passes, then one of the two encoders": DISPATCH,
        "func_proc: 影を別オブジェクトで描画 on - hand the shadow to the pipeline": SEPARATE,
        "func_proc: 影を別オブジェクトで描画 off - composite, swap, resize": COMPOSITE,
        "pass 1 (sub_10088580) head: split by column, kernel B": P1_HEAD,
        "pass 1 body: alpha at +6 -> plane 1, divided by kernel B": P1_BODY,
        "pass 2 (sub_100886f0) head: split by row over h+kernelB-1": P2_HEAD,
        "pass 2 body: plane 1 -> plane 2, stepping 2 bytes = horizontal": P2_BODY,
        "pass 3 (sub_10088840) head: switch to kernel A": P3_HEAD,
        "pass 4 (sub_100889a0) head: the x87 scale density/(kernelA*4096)": P4_HEAD,
        "pass 4 store: flat 影色 + the computed alpha": P4_STORE,
        "pass 4 pattern variant (sub_10088bc0) head: the same scale x 1/4096": P4PAT_HEAD,
        "pass 4 pattern variant store: multiply the pattern's own alpha": P4PAT_STORE,
    }, annotations=ANNOTATIONS)

    print("""
Reading of the above
--------------------
  0x10231f90  scratch plane 1 = [0x101a5328]                 (16-bit alpha, canvas stride)
  0x10231f94  kernel B = 2*(拡散 - trunc(拡散/2)) + 1        (passes 1 and 2)
  0x10231f98  kernel A = 2*trunc(拡散/2) + 1                 (passes 3 and 4)
  0x10231f9c  density  = trunc(濃さ_raw * 4096 / 1000)       (Q12, 0..4096)
  0x10231fa0  scratch plane 2 = plane 1 + stride*canvasH*2
  0x10231fa4  g_X = max(X, 0)   -- the shadow box's x origin in the grown canvas
  0x10231fa8  g_Y = max(Y, 0)
  0x102320b4  影色 Cb   (int16, from sub_1006fed0)
  0x102320b6  影色 Cr
  0x102320b8  影色 Y

Every worker takes only (tid, thread_num, fp, fpip) and reads the rest from
these globals, per filter_registration.md §6. Note that the object's own
width/height (fpip+0xB4 / +0xB8) are still the ORIGINAL values while the four
passes run - they are only overwritten at the very end (0x10088563), which is
why each pass can recompute the intermediate extents from w, h and the two
kernel widths.

The one thing no worker ever reads is the object's colour: pass 1 loads
`word ptr [ebx+6]` and nothing else out of fpip+0xAC. A shadow is a function
of the silhouette alone.""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
