"""What func_proc does with the three trackbars and one checkbox, instruction
by instruction, plus the pixel-write instructions inside the four workers that
angr's decompiler renders ambiguously.

Two things are worth having in mind while reading the dump:

  1. **`比率` splits one Q12 strength into two independent coefficients.**
     `強さ` converts through the usual shared magic-number divide
     (`0x10624dd3` -> /1000, see param_scaling.md §2) into `S = trunc(raw*4096
     /1000)`. `比率` (raw -1000..1000) then produces:

         A = S * (1000 + min(比率, 0)) / 1000      (reduced only when 比率 < 0)
         B = S * (1000 - max(比率, 0)) / 1000      (reduced only when 比率 > 0)

     B gates the *gradient* pass (tints `fpip+0xAC` in place); A gates the
     *halo* pass (box-blurs alpha into a separate, larger canvas). At 比率=0
     both equal S. At the extremes one of them is exactly 0, which shuts that
     whole pass off - verify_params.py checks the arithmetic, verify_shading.py
     and verify_halo.py check what "off" actually looks like at each extreme.

  2. **The 逆光 dispatch is a checkbox read, not a trackbar.** `fp->check[0]`
     (逆光) selects between two structurally identical pairs of workers that
     differ in exactly two spots: which alpha they box-blur (plain vs
     `0x1000 - alpha`) and whether the horizontal pass adds a flat "+4096"
     before scaling by the coefficient. Both of those live in the raw bytes,
     not in the decompiled shape, which is why they are annotated here rather
     than left to decompile_light.py.

Caveats, as usual: angr does not lift x87, but there is no floating point
anywhere in this effect (the only division is x86 `idiv`/magic-multiply, all
integer) - the caveat here is instead that the decompiler's struct-offset
inference silently drops the difference between `add word ptr [ecx], dx`
(gradient pass: accumulate onto the existing pixel) and `mov word ptr [ecx],
0x1000` (halo pass: overwrite), and mis-shares field names between `fpip+0xAC`
and `fpip+0xB0` across the two pass families. Every ANNOTATIONS entry below
that says "add" or "mov" has been read off the actual opcode, not inferred.

Run via main.py:
    uv run main.py inspect/light/disasm_params.py
"""

from tools.disasm import dump_all
from tools.pe_image import PEImage

ENTRY = (0x1005BA30, 0x30)              # prologue, 強さ==0 early-out, S = raw*4096/1000
RATIO_SPLIT = (0x1005BA59, 0x60)        # 比率 -> A / B
SPREAD_CLAMP1 = (0x1005BAB9, 0x9C)      # 拡散 -> r, clamp #1 (fits w/h, then max canvas)
COLOUR = (0x1005BB4C, 0x40)             # scratch ptr, kernel width, ex_data -> YCbCr
GRADIENT_DISPATCH = (0x1005BB7C, 0x70)  # B > 0 ?  check[0] (逆光) picks the worker pair
SPREAD_CLAMP2 = (0x1005BBEF, 0x50)      # radius re-clamped against the *allocated* buffer
HALO_DISPATCH_AND_COMPOSITE = (0x1005BC3F, 0x8A)  # halo workers, table[0x44], swap, resize

# The pixel-store tail of each worker: same shape, two meaningful differences.
HALO_STORE = (0x1005BF02, 0x45)               # halo: clamp to 0x1000, then overwrite
GRADIENT_STORE_OFF = (0x1005C2F8, 0x8A)       # 逆光 off: "+0x1000" bias, then ADD
GRADIENT_STORE_ON = (0x1005C7AC, 0x80)        # 逆光 on: no bias, then ADD

WNDPROC = (0x1005C9C0, 0x68)

ANNOTATIONS = {
    0x1005BA35: "edi = fp",
    0x1005BA39: "eax = fp->ex_data_ptr (saved to [esp+0xc] for later)",
    0x1005BA3C: "esi = fp->track  (index[0]=強さ, [1]=拡散, [2]=比率)",
    0x1005BA43: "eax = track[0] = 強さ raw",
    0x1005BA47: "強さ == 0 -> return 1, nothing touched at all (no canvas growth either)",
    0x1005BA4D: "raw << 12  (raw * 4096)",
    0x1005BA52: "magic 0x10624dd3 ...",
    0x1005BA59: "eax = track[2] = 比率 raw  (fetched here, before the /1000 correction lands)",
    0x1005BA5D: "... sar 6 + sign-fix = S = trunc(raw*4096/1000)",
    0x1005BA68: "ebx = S  (survives the rest of func_proc: it is what 'if (A <= 0) return' tests)",
    0x1005BA6C: "[esp+0x1c] = S  (this slot becomes A)",
    0x1005BA70: "[esp+0x10] = S  (this slot becomes B)",
    0x1005BA74: "比率 >= 0 ?  jump ahead to the B-only branch",
    0x1005BA76: "比率 < 0: ecx = 比率 + 1000",
    0x1005BA81: "ecx = (比率+1000) * S",
    0x1005BA84: "magic 0x10624dd3 /1000 again ...",
    0x1005BA90: "[esp+0x1c] = trunc((比率+1000)*S/1000)  -> A is reduced, B (=[esp+0x10]) untouched",
    0x1005BA98: "比率 <= 0 ?  (we're already in the 比率>=0 half, so this means 比率==0) skip B's reduction",
    0x1005BA9A: "比率 > 0: ecx = 1000 - 比率",
    0x1005BAA6: "ecx = (1000-比率) * S",
    0x1005BAA9: "magic 0x10624dd3 /1000 ...",
    0x1005BAB5: "[esp+0x10] = trunc((1000-比率)*S/1000)  -> B is reduced, A (ebx) untouched",
    0x1005BAB9: "eax = track[1] = 拡散 raw  (used directly as radius r - no /1000 anywhere)",
    0x1005BABC: "esi = fpip  (2nd argument)",
    0x1005BAC0: "global r = 拡散",
    0x1005BACB: "2r+1 vs w (fpip+0xB4) ...",
    0x1005BAD3: "... too big: r = trunc(w/2) - 2   (cdq;sub;sar = c_div(w,2), a plain overwrite of r)",
    0x1005BAE2: "same check against h (fpip+0xB8): 2r+1 vs h -> r = trunc(h/2) - 2",
    0x1005BAFF: "r < 0 -> r = 0",
    0x1005BB0A: "w + 2r vs max canvas width 0x10196748 ...",
    0x1005BB1D: "... too big: r = trunc((max_w - w)/2)",
    0x1005BB2B: "h + 2r vs max canvas height 0x101920e0 -> same clamp",
    0x1005BB4C: "scratch buffer ptr = [0x101a5328] (borrowed - shared with 発光/グロー/クロマキー)",
    0x1005BB56: "kernel width = 2r+1",
    0x1005BB65: "eax = ex_data dword[0] (bytes 0..2 = R,G,B like Win32 COLORREF; byte 3 is unused padding, not a flag - see README §2)",
    0x1005BB77: "call sub_1006fed0: Y -> 0x101b20c0, Cb -> 0x101b20bc, Cr -> 0x101b20be. unconditional: there is no 光色=指定なし option",
    0x1005BB83: "B <= 0 ?  skip the whole gradient pass (both worker pairs)",
    0x1005BB87: "ecx = fp->check  (check[0] = 逆光)",
    0x1005BB8C: "check[0] == 0 ?  (逆光 unchecked / default)",
    0x1005BB91: "逆光 ON: g_101b20b0 = B directly, no extra scaling",
    0x1005BB99: "push worker = sub_1005c520 (vertical, inverted alpha)",
    0x1005BBA6: "push worker = sub_1005c700 (horizontal + tint, no +4096 bias)",
    0x1005BBAD: "逆光 OFF (default): ecx = B*2",
    0x1005BBB0: "magic 0x2e8ba2e9, shift 1 -> divide by 11 (verify_params.py)",
    0x1005BBC5: "g_101b20b0 = trunc(B*2/11)  <- default gradient path is scaled to ~18% of B",
    0x1005BBBB: "push worker = sub_1005c080 (vertical, plain alpha)",
    0x1005BBD6: "push worker = sub_1005c250 (horizontal + tint, WITH +4096 bias)",
    0x1005BBDE: "exec_multi_thread_func(worker, fp, fpip): vertical pass",
    0x1005BBE7: "A <= 0 ?  return 1 - the halo pass, radius re-clamp, final composite, buffer",
    0x1005BBEF: "eax = r (radius from clamp #1)",
    0x1005BBFA: "ecx = fpip+0xEC (allocated row stride, NOT just w)",
    0x1005BC06: "ecx = stride - w  (real spare margin in the already-allocated buffer)",
    0x1005BC0B: "2r vs that margin ...",
    0x1005BC0F: "... too big: r = trunc(margin/2)  (buffer-capacity clamp, distinct from clamp #1's canvas-max check)",
    0x1005BC1B: "same again against fpip+0xF0 (allocated row COUNT) - w) for the height margin",
    0x1005BC36: "ebp = w + 2r, ebx = h + 2r  (the object's size AFTER this frame, computed but not yet stored)",
    0x1005BC42: "g_101b20b0 = A  (halo coefficient; no /11 scaling here, ever)",
    0x1005BC4F: "exec_multi_thread_func(sub_1005bcd0, fp, fpip): halo vertical box-average of alpha",
    0x1005BC5F: "exec_multi_thread_func(sub_1005be50, fp, fpip): halo horizontal box-average + encode",
    0x1005BC93: "table[0x44]: copy fpip+0xAC (the gradient-tinted object) onto fpip+0xB0 at (r,r), mode=3 (normal composite, 8B/pixel)",
    0x1005BCA5: "swap fpip+0xAC <-> fpip+0xB0",
    0x1005BCB1: "fpip+0xB4 = w + 2r, fpip+0xB8 = h + 2r  (canvas grows in BOTH axes - there is no サイズ固定 on this effect at all)",
    # halo store (sub_1005be50): overwrite, hard-clamped alpha
    0x1005BF02: "eax = (avg2D * A) >> 12",
    0x1005BF05: "clamp to 0x1000 (100%) - the ONLY hard clamp on either pass",
    0x1005BF11: "mov word ptr [ecx], 0x1000        <- Y pinned to reference white (OVERWRITE, not add)",
    0x1005BF1D: "mov word ptr [ecx+2], Cb (raw light colour, unscaled)",
    0x1005BF28: "mov word ptr [ecx+4], Cr (raw light colour, unscaled)",
    0x1005BF43: "mov word ptr [ecx-2](=+6): alpha = (lightY * clamped_coef) >> 12  -- amplify-multiply encoding, same idiom as 閃光",
    # gradient store, 逆光 OFF (sub_1005c250): +4096 bias, then ADD
    0x1005C30F: "add eax, 0x1000   <- +4096 DC bias: multiplier ranges [B_scaled, 2*B_scaled], never zero while B_scaled>0",
    0x1005C314: "imul eax, g_101b20b0 (= B_scaled) ; sar 0xc",
    0x1005C31E: "je: multiplier == 0 -> skip (dead in practice, B_scaled>0 whenever this worker runs)",
    0x1005C325: "multiplier >= 0x1000 -> add the RAW light colour unscaled (no clamp beyond this branch: overdrive plateaus, never overshoots the light colour itself)",
    0x1005C334: "add word ptr [ecx], dx    <- ADD onto the existing Y (this is fpip+0xAC, the SOURCE image, not the halo buffer)",
    0x1005C344: "add word ptr [ecx+2], dx  <- ADD onto Cb",
    0x1005C355: "add word ptr [ecx+4], dx  <- ADD onto Cr. alpha (+6) is never touched by this pass",
    # gradient store, 逆光 ON (sub_1005c700): no bias
    0x1005C7BF: "imul eax, g_101b20b0 (= B, unscaled) ; sar 0xc   <- no '+0x1000' here, unlike the OFF path",
    0x1005C7DF: "add word ptr [ecx], dx    <- same ADD-onto-fpip+0xAC shape as the OFF path",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)
    dump_all(img, {
        "func_proc: prologue, 強さ==0 early-out, S = raw*4096/1000": ENTRY,
        "func_proc: 比率 splits S into A (halo) and B (gradient)": RATIO_SPLIT,
        "func_proc: 拡散 -> r, clamp #1 (fit w/h, then max canvas)": SPREAD_CLAMP1,
        "func_proc: scratch/kernel width, ex_data -> YCbCr": COLOUR,
        "func_proc: B>0 ? dispatch gradient pass, picked by check[0]=逆光": GRADIENT_DISPATCH,
        "func_proc: A>0 ? clamp #2 (buffer capacity), halo dispatch": SPREAD_CLAMP2,
        "func_proc: halo dispatch, table[0x44] composite, swap, resize": HALO_DISPATCH_AND_COMPOSITE,
        "halo store (sub_1005be50 tail): clamp then OVERWRITE fpip+0xB0": HALO_STORE,
        "gradient store, 逆光 OFF (sub_1005c250 tail): +4096 bias then ADD onto fpip+0xAC": GRADIENT_STORE_OFF,
        "gradient store, 逆光 ON (sub_1005c700 tail): no bias, ADD onto fpip+0xAC": GRADIENT_STORE_ON,
        "func_WndProc": WNDPROC,
    }, annotations=ANNOTATIONS)

    print("""
Reading of the above
--------------------
  0x101b20ac  scratch buffer pointer = [0x101a5328] (borrowed, shared with 発光/グロー/クロマキー)
  0x101b20b0  coefficient for whichever pass is currently running (A for the halo
              pass, B or trunc(B*2/11) for the gradient pass - never both at once)
  0x101b20b4  kernel width = 2r+1
  0x101b20b8  radius r (re-clamped between the gradient dispatch and the halo dispatch)
  0x101b20bc  light colour Cb   (int16, from sub_1006fed0)
  0x101b20be  light colour Cr
  0x101b20c0  light colour Y

Every worker reads its geometry from these globals; none of the four workers
takes a parameter beyond (thread_id, thread_num, fp, fpip), per
filter_registration.md §6.

The two passes never conflict even though the halo pass runs unconditionally
after the gradient pass: the gradient pass writes into fpip+0xAC (the object's
OWN buffer, in place) while the halo pass writes into fpip+0xB0 (a separate,
larger canvas). table[0x44] then draws the (possibly gradient-tinted) object
on top of the halo, and only then do the two buffers swap.""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
