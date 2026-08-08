"""Annotated raw disassembly of 縁取り: all of func_proc plus the arithmetic
core of each of the three workers.

func_proc keeps everything in `esp+0x..` slots and never sets up a frame
pointer, so the decompiled output (decompile_border.py) reads as an
undifferentiated wall of stack traffic. This file walks the same bytes with a
note beside every instruction that matters, and the notes are what the
verify_*.py scripts turn into checked claims.

The slot names below are frame-relative (offsets from esp on entry, where
`+0x04` is the `fp` argument and `+0x08` is `fpip`). MSVC reuses both argument
slots as scratch, which is why `size` lives at `+0x08`:

    -0x04   ex_data pointer (fp->ex_data_ptr)
    -0x08   pre-pad: canvas width after the pad, then TOTAL width added (2*padX)
    -0x0c   pre-pad: padX, then TOTAL height added (2*padY)
    -0x10   patH  (pattern image height, 0 when no pattern)
    -0x14   patW
    -0x18   canvas height (after the pad, then after the +2*size growth)
    +0x04   scratch: padY, then tileY, then the fild source for the gain
    +0x08   サイズ (clamped)

Run via main.py:
    uv run main.py inspect/border/disasm_params.py
    uv run main.py inspect/border/disasm_params.py --only GAIN
"""

import argparse

from tools.disasm import dump_all
from tools.pe_image import PEImage

# func_proc, split at the boundaries between the things it does.
REGIONS = {
    "ENTRY: early-out on サイズ == 0, and the ぼかし conversion that nothing reads":
        (0x100515D0, 0x71),
    "PREPAD: grow the object to at least one kernel per axis (only if it is smaller)":
        (0x10051641, 0x12E),
    "GROW: clamp サイズ to the allocated margin, then w,h += 2*サイズ":
        (0x1005176F, 0x41),
    "PATTERN: load パターン画像ファイル and tile it over the whole canvas":
        (0x100517B0, 0xE1),
    "CLEAR: four rect-clears around the content box - all four are unreachable":
        (0x10051891, 0xCD),
    "GAIN: kernel width, the x87 gain, and the border colour":
        (0x1005195E, 0x67),
    "DISPATCH: pass 1, then the colour or the pattern flavour of pass 2":
        (0x100519C5, 0x45),
    "COMPOSITE: object over border, undo the pre-pad, publish the new size":
        (0x10051A0A, 0xD6),
}

# The parts of the three workers that decide the arithmetic. The loop plumbing
# (pointer bumps, thread-range splitting) is left to decompile_border.py.
WORKERS = {
    "pass 1 (0x10051ae0): thread range = columns, and the saturating gain":
        (0x10051AE0, 0x8A),
    "pass 1: the middle phase, i.e. the sliding window proper":
        (0x10051BB5, 0x5A),
    "pass 2 colour (0x10051c80): thread range = rows of the GROWN canvas":
        (0x10051C80, 0x6E),
    "pass 2 colour: the flat-colour store and the sum == 0 special case":
        (0x10051D30, 0x4D),
    "pass 2 pattern (0x10051ea0): multiply the tiled pattern's own alpha":
        (0x10051F52, 0x3C),
}

A = {
    # -- ENTRY ------------------------------------------------------------
    0x100515D8: "eax = fp->ex_data_ptr (FILTER+0x4c) -> slot -0x04",
    0x100515DB: "ecx = fp->track",
    0x100515E4: "track[0] = サイズ",
    0x100515E6: "サイズ == 0 -> return 1. THE ONLY early-out; ぼかし = 0 still runs",
    0x100515FB: "edi = fpip->w  (+0xb4)",
    0x10051601: "ebp = fpip->h  (+0xb8)",
    0x10051607: "g_101b1e3c = 0 -- content-box origin x. NOTHING EVER WRITES IT AGAIN",
    0x1005160C: "g_101b1e40 = 0 -- content-box origin y. same",
    0x10051619: "ecx = track[1] = ぼかし",
    0x1005161C: "ecx <<= 12",
    0x1005161F: "the shared /1000 magic divide (param_scaling.md §2) -- the only one here",
    0x10051630: "ecx = 4096 - trunc(ぼかし*4096/1000)",
    0x10051632: "g_101b1e38 = that. tools.xrefs finds NO reader anywhere in the image",
    # -- PREPAD -----------------------------------------------------------
    0x10051641: "eax = 2*サイズ = kernel width - 1",
    0x10051644: "2*サイズ >= w ? -> pre-pad",
    0x10051648: "... else 2*サイズ >= h ? -> pre-pad. Otherwise skip to GROW",
    0x10051652: "eax = 2*サイズ - h",
    0x10051654: "ecx = 2*サイズ - w",
    0x1005165C: "ecx = max(2*サイズ - w, 0)",
    0x10051662: "eax = max(2*サイズ - h, 0)",
    0x1005166C: "padX = (max(2*サイズ-w,0) + 2) / 2  -- note the +2: never zero",
    0x1005167E: "padY = same for h",
    0x10051686: "eax = fpip->stride (+0xec) - w = margin the allocation still has",
    0x10051697: "2*padX fits -> keep it",
    0x1005169C: "... else padX = trunc((stride - w)/2). THIS CAN BREAK the guarantee below",
    0x100516A4: "same clamp on padY against fpip->rows (+0xf0)",
    0x100516CC: "eax = h + 2*padY = padded canvas height -> slot -0x18",
    0x100516D2: "ecx = w + 2*padX = padded canvas width -> slot -0x08",
    0x100516EC: "table[0x48](fpip+0xB0, 0, 0, canvasW, canvasH, 0,0,0,0, 2) -- clear it",
    0x10051717: "table[0x44](fpip+0xB0, padX, padY, fpip+0xAC, 0,0, w, h, 0, 0x13000003)",
    0x10051736: "swap fpip+0xAC <-> fpip+0xB0: the padded copy becomes the image",
    0x10051748: "ecx = canvasW - w = 2*padX -> slot -0x08 (used by COMPOSITE to undo this)",
    0x10051753: "ecx = canvasH - h = 2*padY -> slot -0x0c",
    0x10051761: "fpip->w = canvasW",
    0x10051767: "fpip->h = canvasH",
    # -- GROW -------------------------------------------------------------
    0x1005176F: "eax = fpip->stride - w",
    0x1005177C: "2*サイズ fits in the row margin -> keep",
    0x10051781: "... else サイズ = trunc((stride - w)/2)",
    0x10051789: "same against fpip->rows. サイズ is NEVER compared with w or h itself",
    0x100517A3: "eax = 2*サイズ (clamped)",
    0x100517AA: "w += 2*サイズ  <- the canvas grows by サイズ on every side",
    0x100517AC: "h += 2*サイズ",
    # -- PATTERN ----------------------------------------------------------
    0x100517B0: "eax = ex_data + 4 = the pattern path (ex_data+0..2 is the colour)",
    0x100517B3: "patH = 0",
    0x100517B7: "patW = 0",
    0x100517BD: "slot -0x18 = grown canvas height",
    0x100517C1: "empty path -> no pattern",
    0x100517DF: "table[0x38]([0x101a5328], path, &patW, &patH, 0, 0) -- decode into scratch",
    0x100517E7: "loader failed -> no pattern (patW/patH stay 0, so pass 2 = colour)",
    0x100517ED: "loop bound uses g_101b1e40, which is 0 -> tile over the WHOLE canvas",
    0x10051851: "table[0x44](fpip+0xB0, 0+tileX, 0+tileY, scratch, 0,0, patW, patH, 0, 0x13000003)",
    # -- CLEAR ------------------------------------------------------------
    0x10051891: "eax = g_101b1e3c = 0 ...",
    0x10051898: "... so the left strip is never cleared",
    0x100518C0: "same for the top strip",
    0x100518FA: "eax = fpip->w + 2*サイズ + 0, which is exactly the grown width in edi",
    0x10051908: "edi > eax is false by construction -> right strip never cleared",
    0x10051939: "same for the bottom strip. All four rect-clears are dead in 縁取り",
    # -- GAIN -------------------------------------------------------------
    0x10051962: "the shared scratch buffer 発光/グロー/クロマキー/ライト/シャドー also borrow",
    0x1005196A: "g_101b1e30 = scratch plane (16-bit, one per canvas pixel)",
    0x10051971: "g_101b1e34 = 2*サイズ + 1 = kernel width",
    0x10051979: "eax = 2*サイズ",
    0x1005197A: "edx = track[1] = ぼかし (raw 0..100, no scaling)",
    0x1005197D: "edx = 2*サイズ * ぼかし",
    0x10051984: "the whole gain is x87 from here; angr shows only 'unsupported instruction'",
    0x10051988: "* 0.01",
    0x1005198E: "+ 1.0",
    0x10051994: "1024.0 / that",
    0x1005199A: "+ 0.5, then _ftol truncates -> round-half-up",
    0x100519A5: "g_101b1f54 = round(1024 / (0.02*サイズ*ぼかし + 1)). 1024 when ぼかし = 0",
    0x100519C0: "sub_1006fed0(&Y, &Cb, &Cr, ex_data[0]) -- rgb_ycbcr.md §2",
    # -- DISPATCH ---------------------------------------------------------
    0x100519CA: "pass 1 (vertical), always",
    0x100519D5: "eax = patW",
    0x100519E0: "eax = patH",
    0x100519E6: "either is 0 -> the flat-colour pass 2",
    0x100519ED: "pass 2, pattern flavour",
    0x100519FF: "pass 2, flat-colour flavour",
    # -- COMPOSITE --------------------------------------------------------
    0x10051A1C: "mode 3 = NORMAL alpha compositing (blend_modes.md §3), 8-byte pixels",
    0x10051A3A: "table[0x44](fpip+0xB0, サイズ, サイズ, fpip+0xAC, 0,0, w, h, 0, 3)",
    0x10051A3D: "eax = 2*padX",
    0x10051A46: "pre-pad happened -> crop it back off",
    0x10051A4C: "ecx = 2*padY",
    0x10051A5C: "no pre-pad: just swap the buffers and publish",
    0x10051A7A: "h -= 2*padY",
    0x10051A7E: "w -= 2*padX  -> back to (w0 + 2*サイズ, h0 + 2*サイズ)",
    0x10051A8C: "table[0x48](fpip+0xAC, 0, 0, w, h, ...) -- redundant, the copy below is 0x13",
    0x10051A9F: "sy = padY",
    0x10051AB2: "sx = padX",
    0x10051AC1: "table[0x44](fpip+0xAC, 0, 0, fpip+0xB0, padX, padY, w, h, 0, 0x13000003)",
    0x10051AC7: "fpip->w = w0 + 2*サイズ",
    0x10051ACD: "fpip->h = h0 + 2*サイズ. fpip+0xD4/+0xD8 are NEVER touched: growth is symmetric",
    # -- pass 1 -----------------------------------------------------------
    0x10051AEA: "eax = fpip->h",
    0x10051AF4: "ecx = fpip->w",
    0x10051B0A: "col_end = w * (thread_id + 1) / thread_num -- pass 1 splits by COLUMN",
    0x10051B0C: "edx = gain",
    0x10051B1A: "eax = fpip->stride (+0xec): BOTH buffers are addressed by the allocation",
    0x10051B2A: "col_start = w * thread_id / thread_num",
    0x10051B3E: "ecx = kernel = 2*サイズ + 1",
    0x10051B57: "esi = scratch + col*2  -- 16 bits per pixel, alpha only",
    0x10051B5A: "edx = fpip+0xAC + col*8 -- 8 bytes per pixel",
    0x10051B5D: "eax = phase counter; edi (the running sum) was zeroed at 0x10051b55",
    0x10051B65: "movsx from +6: THE ALPHA, and nothing else. y/cb/cr are never read",
    0x10051B69: "sum += alpha (head phase: kernel outputs, window still growing)",
    0x10051B6D: "signed imul by the gain -- this is where the §5 overflow lives",
    0x10051B72: "sar 10, i.e. floor(sum*gain/1024). NOT a divide by the kernel width",
    0x10051B75: "saturate at 4096; negative results are stored as-is",
    0x10051B8C: "src advances by stride*8",
    0x10051B95: "dst advances by stride*2",
    0x10051BC0: "middle phase: sum += in[+kernel] - in[0]",
    0x10051C13: "tail phase: kernel-1 more outputs, window shrinking",
    # -- pass 2 (colour) --------------------------------------------------
    0x10051C8A: "esi = kernel",
    0x10051CA5: "ecx = h + kernel - 1 = rows pass 1 produced; pass 2 splits by ROW",
    0x10051CC4: "eax = fpip->stride",
    0x10051D14: "dst row = (0 + y) * stride ...",
    0x10051D1F: "... + 0 -> fpip+0xB0 + (y*stride)*8. The origin globals are both 0",
    0x10051D30: "read the 16-bit scratch",
    0x10051D33: "sum += it",
    0x10051D35: "sum == 0 -> alpha 0 and DO NOT touch y/cb/cr",
    0x10051D37: "dst.y  = border colour Y",
    0x10051D41: "dst.cb = border colour Cb",
    0x10051D4C: "dst.cr = border colour Cr -- flat, never scaled by coverage",
    0x10051D59: "the SAME gain again: the chain applies it twice",
    0x10051D69: "dst.a = min(4096, floor(sum*gain/1024))",
    0x10051D77: "dst.a = 0",
    # -- pass 2 (pattern) -------------------------------------------------
    0x10051F52: "read the 16-bit scratch",
    0x10051F59: "same gain, same shift",
    0x10051F61: "coverage saturated -> leave the pattern pixel completely alone",
    0x10051F69: "dst.a = pattern alpha ...",
    0x10051F70: "... * coverage >> 12. y/cb/cr are NEVER written: the pattern supplies colour",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="disasm_params")
    parser.add_argument("--only", help="substring of a region label")
    args = parser.parse_args(argv or [])

    img = PEImage(dll_path)
    targets = {**REGIONS, **WORKERS}
    if args.only:
        targets = {k: v for k, v in targets.items() if args.only.lower() in k.lower()}
        if not targets:
            print(f"no region label contains {args.only!r}; known:")
            for k in {**REGIONS, **WORKERS}:
                print(f"  {k}")
            return
    dump_all(img, targets, annotations=A)


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
