"""音量フェード is the same function, and the differences are the interesting part.

`音量フェード` (`0x1004dea0`, registration `0x100a5810`, index 89) sits directly
after `フェード` in `.text` and has the same two trackbars with the same names,
ranges, defaults and display scale. Its `func_proc` is a near copy: the same
x87 seconds-to-frames conversion, the same two `((k+1) << 12) / (n+1)` ramps,
the same three exits.

Comparing the two is worth a script because it isolates exactly which parts of
フェード are about *images* and which are about *time*. Everything in the time
half is duplicated verbatim; everything in the pixel half is replaced.

(1) The registrations, side by side - identical except `flag` (`0x00200020` vs
    `0x00000020`; bit 9 = `FILTER_FLAG_AUDIO_FILTER`) and the address of an
    otherwise identical `{100, 100}` display-scale array.

(2) The parameter conversion, instruction for instruction. The script aligns
    the two instruction streams and prints every position where they differ, so
    "the same conversion" is a diff rather than an assertion.

(3) The three differences that matter:

      * フェード keeps the alpha in the global `0x101a5390` because the worker
        runs on other threads and `exec_multi_thread_func` only passes two
        parameters (filter_registration.md §6). 音量フェード keeps it in `ebp`
        - it has no worker, so it needs no global, and it is the second effect
        after `ルミナンスキー` with zero private globals.
      * 音量フェード does **not** subtract `*(fpip+0x118)`. That field is
        テキスト's per-character delay (verify_timeline.py §3), which has no
        audio counterpart.
      * the pixel loop becomes a flat loop over `*(fpip+0x104)`, exedit's
        16-bit PCM buffer, for `audio_ch * audio_n` samples. `モノラル化`
        (`0x1006ab3d`) reads the same field, which is what identifies it - the
        SDK's `audiop` at `+0x2C` is not used by either.

Run via main.py:
    uv run main.py inspect/fade/verify_audio_twin.py
"""

from tools.disasm import disasm_range, dump_range
from tools.filter_table import find
from tools.pe_image import PEImage

FADE = (0x1004DD40, 0xD3)
VOLUME = (0x1004DEA0, 0xC7)

# The parameter-conversion prologue of each: from the first fild to the
# instruction that discards the x87 stack.
FADE_CONV = (0x1004DD59, 0x1004DD84)
VOL_CONV = (0x1004DEB4, 0x1004DEDF)

VOL_ANNOTATIONS = {
    0x1004DEAF: "ebp = 4096. A register, not a global - there is no worker to tell",
    0x1004DEB4: "the identical seconds -> frames conversion",
    0x1004DEDF: "ecx = *(fpip+0xA8), the current frame",
    0x1004DEED: "t = frame - fp[0x118]. NO *(fpip+0x118) term",
    0x1004DEF5: "t < in_frames ?",
    0x1004DF01: "the identical ramp",
    0x1004DF13: "u = fp[0x11C] - frame",
    0x1004DF27: ">= 4096 -> return 1",
    0x1004DF31: "> 0 -> the sample loop; <= 0 -> return 0",
    0x1004DF3A: "ecx = fpip->audio_ch (+0x34) ...",
    0x1004DF3D: "eax = *(fpip+0x104) = exedit's PCM buffer, NOT audiop (+0x2C)",
    0x1004DF43: "  ... * fpip->audio_n (+0x30) = the number of 16-bit samples",
    0x1004DF4B: "movsx: signed 16-bit sample ...",
    0x1004DF51: "  ... * alpha >> 12, exactly フェード's pixel body",
    0x1004DF57: "+2 bytes: one sample, interleaved channels and all",
}


def stream(img, start, size):
    return [(i.address, i.mnemonic, i.op_str)
            for i, _ in disasm_range(img, start, size, resolve=False)]


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    img = PEImage(dll_path)

    print("--- (1) the two registrations ---")
    a = find(img, "フェード")[0]
    b = find(img, "音量フェード")[0]
    rows = [
        ("struct", f"0x{a.struct_va:08x}", f"0x{b.struct_va:08x}"),
        ("flag", f"0x{a.flag:08x}", f"0x{b.flag:08x}"),
        ("func_proc", f"0x{a.func_proc:08x}", f"0x{b.func_proc:08x}"),
        ("func_init/exit/update/WndProc",
         f"{a.func_init:x}/{a.func_exit:x}/{a.func_update:x}/{a.func_wndproc:x}",
         f"{b.func_init:x}/{b.func_exit:x}/{b.func_update:x}/{b.func_wndproc:x}"),
        ("ex_data_size", str(a.ex_data_size), str(b.ex_data_size)),
        ("track names", str(a.track_names), str(b.track_names)),
        ("track defaults", str(a.track_defaults), str(b.track_defaults)),
        ("track range", f"{a.track_s}..{a.track_e}", f"{b.track_s}..{b.track_e}"),
        ("check_n", str(a.check_n), str(b.check_n)),
        ("+0x74 block", f"0x{a.ext_va:08x}", f"0x{b.ext_va:08x}"),
        ("display scale", str(a.scale), str(b.scale)),
        ("drag range", f"{a.drag_min}/{a.drag_max}", f"{b.drag_min}/{b.drag_max}"),
    ]
    print(f"  {'':<30s}{'フェード':<24s}{'音量フェード'}")
    for label, x, y in rows:
        mark = "  " if x == y else "<-"
        print(f"  {label:<30s}{x:<24s}{y}  {mark}")
    print("  flag bit 9 (0x200) is FILTER_FLAG_AUDIO_FILTER; bit 5 (0x20) is exedit's")
    print("  'object effect' marker, which both carry (filter_registration.md §2).")

    print("\n--- (2) the parameter conversion, aligned ---")
    fa = stream(img, FADE_CONV[0], FADE_CONV[1] - FADE_CONV[0])
    fb = stream(img, VOL_CONV[0], VOL_CONV[1] - VOL_CONV[0])
    print(f"  {len(fa)} vs {len(fb)} instructions")
    diffs = 0
    for (va, ma, oa), (vb, mb, ob) in zip(fa, fb):
        same = (ma, oa) == (mb, ob)
        # the two functions hold fpip and fp in different registers, so
        # normalise the base register before calling a difference real
        norm = (ma == mb
                and oa.replace("esi", "*").replace("edi", "*")
                == ob.replace("esi", "*").replace("edi", "*"))
        flag = "" if same else ("   (same but for the base register)" if norm else "   <-- DIFFERS")
        if not same:
            diffs += 1
        print(f"  0x{va:08x}: {ma:<6s} {oa:<28s} | 0x{vb:08x}: {mb:<6s} {ob:<24s}{flag}")
    print(f"  {diffs} position(s) differ"
          + (" - the two blocks are identical, opcode for opcode." if not diffs else "."))

    print("\n--- (3) 音量フェード in full ---")
    dump_range(img, *VOLUME, label="音量フェード func_proc 0x1004dea0",
               resolve=True, annotations=VOL_ANNOTATIONS)

    print("\n--- the same PCM buffer, from モノラル化 ---")
    dump_range(img, 0x1006AB3D, 0x1A, label="モノラル化 0x1006ab3d", resolve=False,
               annotations={0x1006AB3D: "*(fpip+0x104): the same audio buffer",
                            0x1006AB43: "fpip->audio_n (+0x30)"})

    print("\n--- what is and is not shared ---")
    print("""
    shared verbatim     the +0x74 block shape, the trackbar definitions, the
                        seconds->frames conversion, both ramps, the min, the
                        three exits, `>> 12` as the scale
    フェード only       the global 0x101a5390, exec_multi_thread_func, the row
                        split, `*(fpip+0x118)`
    音量フェード only   the flat sample loop over *(fpip+0x104), and `ebp` in
                        place of the global - which leaves it with **no private
                        global at all**, the second such effect after
                        ルミナンスキー""")

    text = "\n".join(f"{m} {o}" for _a, m, o in stream(img, *VOLUME))
    print(f"\n  globals referenced by 音量フェード: "
          f"{[w for w in text.split() if w.startswith('[0x101') or w.startswith('[0x102')] or 'none'}")

    print("\n--- (4) the one place `sar` is not the same as a divide ---")
    print("  Both effects finish with `sar 12`. In フェード the left operand is a")
    print("  PIXEL_YCA alpha, which is never negative, so floor == truncate")
    print("  (verify_alpha_curve.py §5). In 音量フェード it is a signed PCM sample,")
    print("  and there the two really do differ:\n")
    print("     sample     s*g       sar 12 (floor)   trunc(s*g/4096)   delta")
    g = 2048
    for s in (-32768, -1001, -3, -1, 0, 1, 3, 1001, 32767):
        prod = s * g
        floor_ = prod >> 12
        trunc_ = int(prod / 4096) if prod >= 0 else -((-prod) // 4096)
        print(f"    {s:7d} {prod:11d} {floor_:15d} {trunc_:17d} {floor_ - trunc_:7d}")
    print("  So every negative sample is rounded *down* rather than toward zero: a")
    print("  bias of at most one LSB, applied only to the negative half of the wave.")
    print("  It is inaudible at 16 bits, but it is the reason a faded silence is not")
    print("  bit-exactly silent - the samples land on -1 instead of 0.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
