"""Which frame numbers フェード reads, and where exedit puts them.

フェード is the first effect in this project whose input is *time* rather than
pixels, so the three fields it reads have to be identified from the code that
fills them rather than from the code that uses them:

    t = *(fpip+0xA8) - fp[0x118] - *(fpip+0x118)      fade-in
    u = fp[0x11C]    - *(fpip+0xA8)                   fade-out

None of the three is in the AviUtl SDK. exedit fills `fp+0x118` / `fp+0x11C`
in two near-identical setup routines (`0x10047be0` and `0x10047e30`) that also
fill the *documented* `fpip->frame` and `fpip->frame_n`, and it is that overlap
that pins everything down.

(1) `fp+0x118` / `fp+0x11C` = first and last frame of the object's timeline.
    Both setup routines branch on `obj+0x50`:
      * `< 0` - a plain object - copy `fp+0xEC` / `fp+0xF0`, which two
        instructions earlier were loaded from `obj+8` / `obj+0xC`,
      * `>= 0` - an object cut into segments by 中間点 - walk the chain and
        take the **first segment's start** and the **last segment's end**.
    So フェード always fades over the whole object, not over the segment the
    playhead happens to be in.

(2) `fpip+0xA8` is in the same units: the same routines compute
    `fpip->frame = *(fpip+0xA8) - chain_start` and
    `fpip->frame_n = chain_end - chain_start + 1` from it, using exactly the
    values they just stored into `fp+0x118` / `fp+0x11C`. Therefore

        t (before the third term) == fpip->frame
        u                         == fpip->frame_n - 1 - fpip->frame

    i.e. フェード could have been written with the two documented SDK fields.
    The script prints both setup routines side by side to show the four
    instructions that make this an identity rather than a coincidence.

(3) `fpip+0x118` is a per-*sub*-object delay in frames, and only テキスト
    writes it (`0x1008b2f2`, the per-character draw callback pushed at
    `0x1008aa28`), from `表示速度`. Every other object leaves it at whatever
    the drawing pipeline last stored - the two other writes at `0x1008b388` /
    `0x1008b6fb` restore the value saved on entry at `0x1008b04a`.

(4) The proof that these are two different structs that merely happen to share
    an offset: `ワイプ` (`0x10090490`) reads `fp+0x118` and `fp+0x11C` with the
    same shape as フェード but does **not** subtract `fpip+0x118`, and the same
    `0x1008b010` reads `+0x118` off *both* of its arguments in one basic block.

Run via main.py:
    uv run main.py inspect/fade/verify_timeline.py
    uv run main.py inspect/fade/verify_timeline.py --wide
"""

import argparse

from tools.disasm import dump_range
from tools.pe_image import PEImage

SETUP_A = 0x10047BE0  # ... 0x10047e2f
SETUP_B = 0x10047E30  # ... 0x1004822a

SETUP_ANNOTATIONS = {
    # --- routine A, the fp+0x118 / fp+0x11C half ------------------------
    0x10047CA3: "fp+0xEC = obj[+8]  = this segment's first frame",
    0x10047CAF: "fp+0xF0 = obj[+0xC] = this segment's last frame",
    # --- routine A, the fpip half ---------------------------------------
    0x10047D00: "fpip+0x12C: the 時間制御 remap table. NULL -> keep *(fpip+0xA8)",
    0x10047D34: "  no remap needed: *(fpip+0xA8) = obj[+8]",
    0x10047D73: "  remapped: *(fpip+0xA8) = table_value / 100 ...",
    0x10047D88: "  ... and *(fpip+0x114) = the 1/100-frame remainder",
    0x10047DB9: "obj[+0x50] < 0 -> plain object",
    0x10047DD8: "eax = *(fpip+0xA8)",
    0x10047DDE: "ecx = obj[chain head][+8] = chain start   <- same value as fp+0x118",
    0x10047DE4: "fpip->frame (+0x1C) = *(fpip+0xA8) - chain start",
    0x10047DE7: "walk 0x101592d8 forward to the last segment ...",
    0x10047E03: "  ... eax = its obj[+0xC] = chain end     <- same value as fp+0x11C",
    0x10047E0A: "fpip->frame_n (+0x20) = chain end - chain start + 1",
    0x10047E12: "the plain-object arm: chain start/end are just obj[+8] / obj[+0xC]",
    0x10047E1D: "fpip->frame   = *(fpip+0xA8) - obj[+8]",
    0x10047E27: "fpip->frame_n = obj[+0xC] - obj[+8] + 1",

    # --- routine B, the same thing, this time storing into fp -----------
    0x10047F2E: "fp+0xEC = obj[+8]",
    0x10047F3A: "fp+0xF0 = obj[+0xC]",
    0x10047FA3: "obj[+0x50] < 0 -> plain object ...",
    0x10047FB6: "  fp+0x118 = fp+0xEC = this object's first frame",
    0x10047FBC: "  fp+0x11C = fp+0xF0 = its last frame",
    0x10047FC7: "the 中間点 arm: ecx = obj[+0x50] = index of the FIRST segment",
    0x10047FDC: "edx = obj[first][+8]",
    0x10047FE0: "fp+0x118 = the first segment's first frame",
    0x10047FE6: "follow 0x101592d8[i] while it is >= 0: the last segment",
    0x10048002: "eax = obj[last][+0xC]",
    0x1004800E: "fp+0x11C = the last segment's last frame",
    0x10048014: "if this segment is not the last one ...",
    0x1004801B: "  ... fp+0xF0 += 1, so the segments join without a gap",
    0x100481DD: "fpip->frame   = *(fpip+0xA8) - chain start   (same two values again)",
    0x10048203: "fpip->frame_n = chain end - chain start + 1",
    0x1004820C: "and the plain-object arm of the same computation",
}

FADE_ANNOTATIONS = {
    0x1004DD84: "フェード: edx = fp[0x118]",
    0x1004DD8A: "フェード: edi = *(fpip+0x118)   <- the extra term",
    0x1004DD92: "eax = *(fpip+0xA8)",
    0x1004DD98: "t = frame - fp[0x118]           == fpip->frame",
    0x1004DD9A: "t -= *(fpip+0x118)              <- ワイプ has no equivalent",
    0x100904E9: "ワイプ: edx = fp[0x118]",
    0x100904F1: "ワイプ: eax = *(fpip+0xA8)",
    0x100904F7: "ワイプ: t = frame - fp[0x118], and that is all",
    0x10090525: "ワイプ: u = fp[0x11C] - *(fpip+0xA8), identical to フェード",
}

TEXT_ANNOTATIONS = {
    0x1008B017: "ebx = arg1 = fpip",
    0x1008B026: "eax = *(fpip+0x118), the delay this object came in with",
    0x1008B04A: "saved at [esp+0x28] ...",
    0x1008B04E: "eax = arg0 = fp - a DIFFERENT struct that also has a +0x118",
    0x1008B0AD: "fp[0x11C] and fp[0x118]: the object timeline, as in フェード",
    0x1008B0B3: "  (so this one block reads +0x118 off both pointers)",
    0x1008B29A: "eax = *(fpip+0x100) = frame rate denominator ...",
    0x1008B2A6: "st0 = *(fpip+0xFC) = frame rate numerator",
    0x1008B2BF: "x [esp+0xc8], this character's own delay",
    0x1008B2CC: "... x1000 (5*5*5*8), so the delay is in ms if rate/scale is fps",
    0x1008B2D7: "st0 = delay * rate / (scale * 1000) = the delay in frames",
    0x1008B2DE: "ecx = the delay saved on entry",
    0x1008B2E9: "+= it, so nested sub-objects accumulate",
    0x1008B2F2: "*(fpip+0x118) = that. The only write in the image that changes it",
    0x1008B388: "restores [esp+0x28] unchanged - the early-out arm",
    0x1008B6FB: "restores [esp+0x28] unchanged - the normal exit",
}


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="verify_timeline")
    parser.add_argument("--wide", action="store_true",
                        help="dump both setup routines in full instead of the key ranges")
    args = parser.parse_args(argv or [])

    img = PEImage(dll_path)

    print("--- (1)(2) exedit's two object-setup routines ---")
    print("Both write fp+0x118 / fp+0x11C and fpip->frame / fpip->frame_n from the")
    print("same pair of frame numbers. They are byte-for-byte different functions")
    print("but structurally the same; only the second one is annotated in full.")
    if args.wide:
        dump_range(img, SETUP_A, 0x24F, label="setup A 0x10047be0",
                   resolve=False, annotations=SETUP_ANNOTATIONS)
        dump_range(img, SETUP_B, 0x3FA, label="setup B 0x10047e30",
                   resolve=False, annotations=SETUP_ANNOTATIONS)
    else:
        for label, va, size in (
            ("setup A: fp+0xEC / fp+0xF0 from the object", 0x10047CA3, 0x12),
            ("setup A: fpip+0xA8 and the 時間制御 remap", 0x10047D00, 0x92),
            ("setup A: fpip->frame / frame_n, 中間点 arm", 0x10047DB9, 0x59),
            ("setup A: ... and the plain-object arm", 0x10047E12, 0x1D),
            ("setup B: fp+0x118 / fp+0x11C, both arms", 0x10047F2E, 0xF6),
            ("setup B: fpip->frame / frame_n from the same values", 0x100481B3, 0x79),
        ):
            dump_range(img, va, size, label=label, resolve=False,
                       annotations=SETUP_ANNOTATIONS)

    print("""
  Reading the two together:

      chain_start = fp[0x118]         chain_end = fp[0x11C]
      fpip->frame   == *(fpip+0xA8) - chain_start
      fpip->frame_n == chain_end - chain_start + 1

  so フェード's two counters are the documented SDK fields in disguise:

      t = fpip->frame - *(fpip+0x118)
      u = fpip->frame_n - 1 - fpip->frame

  and `fp+0xEC`/`fp+0xF0` - the *segment* the playhead is in - are the fields
  フェード does NOT read. An object split by 中間点 fades once over its whole
  length, not once per segment.""")

    print("\n--- (3) フェード vs ワイプ: the third term ---")
    dump_range(img, 0x1004DD84, 0x1C, label="フェード 0x1004dd84",
               resolve=False, annotations=FADE_ANNOTATIONS)
    dump_range(img, 0x100904E9, 0x14, label="ワイプ 0x100904e9",
               resolve=False, annotations=FADE_ANNOTATIONS)
    dump_range(img, 0x10090525, 0x12, label="ワイプ 0x10090525",
               resolve=False, annotations=FADE_ANNOTATIONS)

    print("\n--- (4) who writes *(fpip+0x118) ---")
    for label, va, size in (
        ("0x1008b010 prologue: fp and fpip are separate arguments", 0x1008B010, 0x46),
        ("0x1008b0ad: the object timeline off fp", 0x1008B0AD, 0x0E),
        ("0x1008b29a: the per-character delay, in frames", 0x1008B29A, 0x62),
        ("0x1008b37c / 0x1008b6ef: the two writes that restore it", 0x1008B37C, 0x24),
        ("...", 0x1008B6EF, 0x1E),
    ):
        dump_range(img, va, size, label=label, resolve=True,
                   annotations=TEXT_ANNOTATIONS)
    print("""
  0x1008b010 is pushed as a callback at 0x1008aa28, inside テキスト's func_proc,
  and テキスト's track[1] is `表示速度`. So the delay is per character: with
  文字毎に個別オブジェクト on and 表示速度 non-zero, each character carries its
  own *(fpip+0x118) and therefore its own フェード-in start. A character whose
  delay has not elapsed gets t < 0, alpha <= 0, and func_proc's `return 0`.

  **Undetermined**: what *(fpip+0x118) holds for everything else. No other write
  to it exists in the image, and this project has not traced where the
  FILTER_PROC_INFO is first built - the same reservation the 0x10135c68 entry in
  common/README.md §5 makes. Everything downstream assumes it is 0.""")

    print("\n--- the fields, collected ---")
    print("""
    fp+0xEC  / fp+0xF0    this segment's first / last frame
    fp+0x118 / fp+0x11C   the whole object's first / last frame  <- フェード reads these
    fpip+0x1C             fpip->frame   = *(fpip+0xA8) - fp[0x118]      (SDK)
    fpip+0x20             fpip->frame_n = fp[0x11C] - fp[0x118] + 1     (SDK)
    fpip+0xA8             the current frame, absolute, after 時間制御
    fpip+0x114            its 1/100-frame remainder (フェード ignores it)
    fpip+0x118            this sub-object's own delay [frames]
    fpip+0x12C            the 時間制御 remap table, or NULL""")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
