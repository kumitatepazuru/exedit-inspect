"""An integer-faithful reference implementation of ルミナンスキー, plus self-checks.

Everything the other scripts in this directory establish, assembled into one
executable statement of the effect. All four workers are here, each written to
follow its code path branch for branch - `c_div` where the code uses `idiv`,
the fold written as the two instructions that implement it rather than as
`abs()`, and the `keep` shortcut kept separate from the ramp even though the
two agree on their shared boundary.

There is no floating point to model and no shared state to thread through: the
effect contains neither (verify_dispatch.py). There is no frame-filter variant
either - one registration, the object effect, so pixels are always exedit's
8-byte PIXEL_YCA (`y, cb, cr, a` as four signed 16-bit fields, alpha 0..4096).
And there is no scratch buffer, no canvas growth and no second pass: one worker
runs once over `*(fpip+0xAC)` and that is the whole effect.

Nothing here reads the DLL: this is the *claim*. The scripts that read the DLL
are disasm_params.py (the branch tree), verify_dispatch.py (who runs, on what),
verify_ex_data.py (the combobox and the two shared UI entries) and
verify_alpha_curve.py (the four curves, checked exhaustively).

The self-checks at the bottom are the point. Each is a property that follows
from the reading above and would break if the reading were wrong - the mode
selecting the worker, alpha being the only field written, the boundaries being
closed on the keep side, ぼかし = 0 collapsing to a hard step, type 2 dimming
the band it keeps, and the effect never brightening anything.

Run via main.py:
    uv run main.py inspect/luma_key/simulate_luma_key_reference.py
"""

from tools.cints import c_div

DARK, BRIGHT, BAND, BAND_HARD = 0, 1, 2, 3

TYPE_NAMES = {
    DARK: "暗い部分を透過",
    BRIGHT: "明るい部分を透過",
    BAND: "明暗部分を透過",
    BAND_HARD: "明暗部分を透過(ぼかし無し)",
}


# --------------------------------------------------------------------------
# worker 0x10064f60 - type 0, 暗い部分を透過
# --------------------------------------------------------------------------

def _worker_dark(img, base: int, blur: int) -> None:
    lo = base - blur                                  # 0x10064f9e: sub
    for row in img:
        for px in row:
            t = px[0] - lo                            # 0x10064fe4
            if t < 0:                                 # 0x10064fe8: jns
                px[3] = 0
            elif t < blur:                            # 0x10064ff6: jge -> keep
                px[3] = c_div(px[3] * t, blur)        # 0x10064ffe..0x10065004


# --------------------------------------------------------------------------
# worker 0x10065020 - type 1, 明るい部分を透過
# --------------------------------------------------------------------------

def _worker_bright(img, base: int, blur: int) -> None:
    hi = base + blur                                  # 0x1006505e: add
    for row in img:
        for px in row:
            t = hi - px[0]                            # 0x100650a8 - the sense is
            if t < 0:                                 # mirrored, not the branches
                px[3] = 0
            elif t < blur:
                px[3] = c_div(px[3] * t, blur)


# --------------------------------------------------------------------------
# worker 0x100650e0 - type 2, 明暗部分を透過
# --------------------------------------------------------------------------

def _worker_band(img, base: int, blur: int) -> None:
    lo = base - blur
    for row in img:
        for px in row:
            t = px[0] - lo                            # 0x10065162
            if t > blur:                              # 0x10065166: jle
                t = 2 * blur - t                      # 0x1006516a..0x10065171
            if t < 0:                                 # 0x10065175: jge
                px[3] = 0
            elif t < blur:                            # 0x1006517f: jge -> keep.
                # After the fold t <= blur always, so `keep` fires only at
                # t == blur, i.e. only at y == base. The whole band is ramp.
                px[3] = c_div(px[3] * t, blur)


# --------------------------------------------------------------------------
# worker 0x100651b0 - type 3, 明暗部分を透過(ぼかし無し)
# --------------------------------------------------------------------------

def _worker_band_hard(img, base: int, blur: int) -> None:
    lo = base - blur
    for row in img:
        for px in row:
            t = px[0] - lo                            # 0x1006523a
            if t > blur:                              # 0x10065240: jle
                t = 2 * blur - t                      # 0x10065244..0x10065248
            if t < 0:                                 # 0x1006524c: jge
                px[3] = 0                             # 0x1006524e: mov [ecx+6], bx
            # no else: this worker has no multiply and no divide at all


WORKERS = {DARK: _worker_dark, BRIGHT: _worker_bright,
           BAND: _worker_band, BAND_HARD: _worker_band_hard}


# --------------------------------------------------------------------------
# func_proc 0x10064ee0
# --------------------------------------------------------------------------

def luma_key(img, ex_type: int, track):
    """`img` is a list of rows of [y, cb, cr, a] and is modified in place,
    exactly as the effect modifies *(fpip+0xAC).

    No early return: whatever `ex_type` and the trackbars are, one worker walks
    every pixel. Values of `ex_type` outside 0..2 all land on worker 3, which is
    the `else` arm rather than a `== 3` test.
    """
    base, blur = track                                # fp->track[0], fp->track[1]
    WORKERS.get(ex_type, _worker_band_hard)(img, base, blur)
    return img


# --------------------------------------------------------------------------
# self-checks
# --------------------------------------------------------------------------

def _gradient(w=17, h=1, a=4096):
    """A horizontal luminance ramp 0..4096 at constant chroma and alpha."""
    return [[[c_div(x * 4096, w - 1), 0, 0, a] for x in range(w)] for _ in range(h)]


def _alphas(img):
    return [px[3] for row in img for px in row]


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- the combobox picks the worker, and nothing else does ---")
    outs = []
    for t in (DARK, BRIGHT, BAND, BAND_HARD):
        img = _gradient()
        luma_key(img, t, (2048, 512))
        outs.append(tuple(_alphas(img)))
        print(f"  type {t} {TYPE_NAMES[t]:<28} {outs[-1]}")
    check("all four modes give different results", len(set(outs)) == 4)

    img = _gradient()
    luma_key(img, 9, (2048, 512))
    check("an out-of-range type falls through to worker 3 (the `else` arm)",
          tuple(_alphas(img)) == outs[BAND_HARD])

    print("\n--- only alpha is written ---")
    img = _gradient(33, 4)
    before = [[px[:] for px in row] for row in img]
    luma_key(img, BAND, (2048, 300))
    check("y, cb and cr survive untouched",
          all(px[:3] == q[:3] for row, brow in zip(img, before) for px, q in zip(row, brow)))
    check("alpha did change", _alphas(img) != _alphas(before))

    print("\n--- the boundaries are closed on the keep side ---")
    base, blur = 2048, 512
    for t, edges in ((DARK, (1535, 1536, 2047, 2048)),
                     (BRIGHT, (2048, 2049, 2560, 2561)),
                     (BAND_HARD, (1535, 1536, 2560, 2561))):
        img = [[[y, 0, 0, 4096] for y in edges]]
        luma_key(img, t, (base, blur))
        print(f"  type {t}: y = {edges} -> alpha = {tuple(_alphas(img))}")
    img = [[[y, 0, 0, 4096] for y in (1535, 1536, 2560, 2561)]]
    luma_key(img, BAND_HARD, (base, blur))
    check("type 3 keeps [base-ぼかし, base+ぼかし] inclusive and drops one unit outside",
          _alphas(img) == [0, 4096, 4096, 0])

    print("\n--- ぼかし = 0 is a hard step, not a crash ---")
    for t, expect in ((DARK, [0, 4096, 4096]), (BRIGHT, [4096, 4096, 0]),
                      (BAND, [0, 4096, 0]), (BAND_HARD, [0, 4096, 0])):
        img = [[[y, 0, 0, 4096] for y in (2047, 2048, 2049)]]
        luma_key(img, t, (2048, 0))
        check(f"type {t} at ぼかし = 0: y = 2047/2048/2049 -> {expect}",
              _alphas(img) == expect, f"got {_alphas(img)}")
    print("  The ramp needs 0 <= t < ぼかし, which is empty. Types 2 and 3 collapse to")
    print("  'keep exactly one luminance value', which is as close to useless as the")
    print("  effect gets - and nothing in exedit stops the slider from getting there.")

    print("\n--- type 2 dims the band it keeps; type 3 does not ---")
    band = list(range(1536, 2561, 128))
    for t in (BAND, BAND_HARD):
        img = [[[y, 0, 0, 4096] for y in band]]
        luma_key(img, t, (2048, 512))
        print(f"  type {t}  y = {band}")
        print(f"          a = {_alphas(img)}")
    img = [[[y, 0, 0, 4096] for y in band]]
    luma_key(img, BAND, (2048, 512))
    check("type 2 leaves exactly one sample at full alpha",
          _alphas(img).count(4096) == 1)
    img = [[[y, 0, 0, 4096] for y in band]]
    luma_key(img, BAND_HARD, (2048, 512))
    check("type 3 leaves all of them at full alpha", set(_alphas(img)) == {4096})

    print("\n--- the effect multiplies the alpha already there ---")
    for a in (4096, 2048, 1024):
        img = [[[1792, 0, 0, a]]]      # halfway up type 0's ramp
        luma_key(img, DARK, (2048, 512))
        print(f"  input alpha {a:>4} at y = 1792 (ramp factor 1/2)  ->  {img[0][0][3]}")
    img = [[[1792, 0, 0, 4096]]]
    luma_key(img, DARK, (2048, 512))
    once = img[0][0][3]
    luma_key(img, DARK, (2048, 512))
    check("running it twice squares the factor rather than repeating it",
          img[0][0][3] == c_div(once * once, 4096), f"{once} -> {img[0][0][3]}")
    check("alpha never goes up",
          all(luma_key([[[y, 0, 0, a]]], t, (2048, 512))[0][0][3] <= a
              for t in WORKERS for a in (0, 1, 1000, 4096) for y in range(0, 4097, 97)))

    print("\n--- a semi-transparent object is not destroyed ---")
    img = [[[3000, 0, 0, 2048] for _ in range(8)] for _ in range(8)]
    luma_key(img, DARK, (2048, 512))
    check("a uniformly 50%-opaque object above the band passes through unchanged",
          set(_alphas(img)) == {2048})
    print("  Worth contrasting with カラーキー, whose 境界補正 turns a uniform 50% alpha")
    print("  into 512 at r=1 and into 0 at r>=2 (border_correction.md). ルミナンスキー")
    print("  has no border correction and no box average at all: a pixel's new alpha")
    print("  depends only on its own y and its own a, so there is nothing for a")
    print("  neighbourhood to erode.")

    print("\n--- the shipped defaults ---")
    print(f"  基準輝度 = 2048, ぼかし = 512, type = 0 ({TYPE_NAMES[DARK]})")
    img = _gradient(17)
    luma_key(img, DARK, (2048, 512))
    print(f"  y    = {[px[0] for px in img[0]]}")
    print(f"  a    = {_alphas(img)}")
    print("  A newly added ルミナンスキー does something immediately: mid-grey sits")
    print("  exactly on the top of the ramp, so everything below 50% luminance is")
    print("  already gone. カラーキー ships with a configuration that does nothing at")
    print("  all until three sliders are moved (param_scaling.md §1); this one is the")
    print("  opposite extreme.")

    print(f"\n{sum(checks)}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
