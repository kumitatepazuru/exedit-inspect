"""An integer-faithful reference implementation of クロマキー, plus self-checks.

Everything the other scripts in this directory establish, assembled into one
executable statement of the effect. All four code paths are here, each written
to follow its worker instruction for instruction - `c_div` where the code uses
`idiv`, `sar` where it uses `sar`, `math.trunc` for `_ftol`, and the two box
passes replayed phase by phase rather than as a closed form.

Nothing here reads the DLL: this is the *claim*. The scripts that read the DLL
are disasm_params.py (the branch tree), verify_key_metric.py (the metric),
verify_spill.py (色彩補正 / 透過補正) and verify_border_chain.py (境界補正).

The pixel format is exedit's object buffer, PIXEL_YCA - `y, cb, cr, a` as four
signed 16-bit fields, alpha 0..4096. There is no frame-filter variant to
model: クロマキー has one registration and it is the object effect.

The self-checks at the bottom are the point. Each is a property that follows
from the reading above and would break if the reading were wrong - the key
colour erasing itself, 透過補正 doing nothing without 色彩補正, 境界補正 = 1
being a pure blur, the luminance of the key colour not mattering.

Run via main.py:
    uv run main.py inspect/chroma_key/simulate_chroma_key_reference.py
"""

import math

from tools.cints import c_div, sar

K = 65536 / (2 * math.pi)       # the double at 0x1009a430


# --------------------------------------------------------------------------
# integer primitives
# --------------------------------------------------------------------------

def ftol(x: float) -> int:
    """CRT _ftol at 0x10091ad8."""
    return math.trunc(x)


def i16(x: int) -> int:
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def clamp_chroma(x: int) -> int:
    """The +-2048 clamp the spill un-mix applies (0x10013293)."""
    return 2048 if x > 2048 else (-2048 if x < -2048 else x)


def hue_of(cb: int, cr: int) -> int:
    return ftol(math.atan2(cr, cb) * K)


def sat_of(cb: int, cr: int) -> int:
    return max(abs(cb), abs(cr))


# --------------------------------------------------------------------------
# the key metric
# --------------------------------------------------------------------------

class Key:
    """The per-frame constants every worker derives from ex_data + track[]."""

    def __init__(self, key_yc, track):
        self.y, self.cb, self.cr = key_yc
        self.hue = hue_of(self.cb, self.cr)
        self.sat = sat_of(self.cb, self.cr)
        # The divide in the spill un-mix needs a non-zero divisor; the band
        # does not, and is computed from the raw value first (0x10013142
        # before 0x10013157).
        self.sat_nz = max(self.sat, 1)
        self.hue_range = track[0] << 7
        self.sat_range = sar(track[1] * self.sat, 8)
        self.r = track[2]

    def distance(self, cb, cr, sat_ref):
        """(d, hue_excess, sat). `sat_ref` is the key saturation this worker
        happens to compare against - 0x100130b0 uses the clamped one, the
        other three use the raw one. They differ only for an achromatic key."""
        sat = sat_of(cb, cr)
        dh = abs(i16(hue_of(cb, cr) - self.hue))
        ds = abs(sat - sat_ref)
        hue_excess = max(0, dh - self.hue_range)
        return hue_excess + 8 * max(0, ds - self.sat_range), hue_excess, sat

    def unmix(self, px, f):
        """色彩補正: push the chroma away from the key by 4096/f."""
        if 1 < f < 4096:
            px[1] = clamp_chroma(self.cb + c_div((px[1] - self.cb) << 12, f))
            px[2] = clamp_chroma(self.cr + c_div((px[2] - self.cr) << 12, f))

    def coverage(self, floor_, sat):
        """f = max(<a hue-side estimate>, <the saturation-side estimate>)."""
        return max(floor_, c_div((self.sat_nz - sat) << 12, self.sat_nz))


# --------------------------------------------------------------------------
# the box passes (境界補正 only)
# --------------------------------------------------------------------------

def box_1d(src: list, r: int) -> list:
    """One row or column of 0x100136e0 / the horizontal half of pass 3.

    Three phases, divisor always the kernel width, samples outside the image
    read as zero. Written out rather than expressed as a slice sum so that the
    phase counts match the loop bounds in the binary; see
    verify_border_chain.py, which checks the two against each other.
    """
    n, kw = len(src), 2 * r + 1
    at = lambda i: src[i] if 0 <= i < n else 0
    out, s, lead, trail = [], 0, 0, 0
    for _ in range(r):
        s += at(lead)
        lead += 1
    for _ in range(kw - r):
        s += at(lead)
        lead += 1
        out.append(c_div(s, kw))
    for _ in range(max(0, n - kw)):
        s += at(lead) - at(trail)
        lead, trail = lead + 1, trail + 1
        out.append(c_div(s, kw))
    for _ in range(r):
        s -= at(trail)
        trail += 1
        out.append(c_div(s, kw))
    return out[:n]      # the real code writes past the end when n < kw


def stretch_constants(r: int) -> tuple:
    q = c_div(4096, r)
    return 4096 - q, 4096 - q * r


# --------------------------------------------------------------------------
# the four paths
# --------------------------------------------------------------------------

def _plain(img, key: Key):
    """worker 0x10012f10 - 境界補正 = 0, 色彩補正 off."""
    for row in img:
        for px in row:
            d, _, _ = key.distance(px[1], px[2], key.sat)
            if d < 4096:
                px[3] = sar(px[3] * d, 12)


def _plain_cc(img, key: Key, alpha_fix: bool):
    """worker 0x100130b0 - 境界補正 = 0, 色彩補正 on."""
    for row in img:
        for px in row:
            d, hue_excess, sat = key.distance(px[1], px[2], key.sat_nz)
            a = sar(px[3] * d, 12) if d < 4096 else px[3]
            f = key.coverage(hue_excess, sat)
            key.unmix(px, f)
            if alpha_fix and f < 4096:
                a = sar(f * a, 12)
            px[3] = a


def _border(img, key: Key, colour_correct: bool, alpha_fix: bool):
    """workers 0x10013340|0x10013500 -> 0x100136e0 -> 0x10013880|0x10013de0."""
    h, w, r = len(img), len(img[0]), key.r
    sat_ref = key.sat

    # pass 1: the matte, and (色彩補正 only) the hue-only map
    map_b = [[0] * w for _ in range(h)]
    map_c = [[0] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            px = img[y][x]
            d, hue_excess, _ = key.distance(px[1], px[2], sat_ref)
            map_b[y][x] = min(d, 4096)
            if colour_correct:
                # stored through a 16-bit slot, so a hue excess of 32768
                # (色相範囲 = 0, a pixel exactly opposite the key) wraps to
                # -32768 and the max() below simply ignores it.
                map_c[y][x] = i16(hue_excess)

    # pass 2: vertical box average, map B -> map A
    map_a = [[0] * w for _ in range(h)]
    for x in range(w):
        col = box_1d([map_b[y][x] for y in range(h)], r)
        for y in range(h):
            map_a[y][x] = col[y]

    # pass 3: horizontal box average, then apply
    a_const, b_const = stretch_constants(r)
    for y in range(h):
        blurred = box_1d(map_a[y], r)
        for x in range(w):
            px = img[y][x]
            v = sar(blurred[x] * map_b[y][x], 12)
            t = (v - a_const) * r + b_const if v else 0
            if v == 0 or t <= 0:
                px[3] = 0
                continue
            a = sar(px[3] * t, 12)
            f = key.coverage(map_c[y][x] if colour_correct else t, sat_of(px[1], px[2]))
            key.unmix(px, f)
            if colour_correct and alpha_fix and f < 4096:
                a = sar(f * a, 12)
            px[3] = a


def chroma_key(img, key_yc, status, track, check):
    """func_proc 0x10012de0. `img` is a list of rows of [y, cb, cr, a] and is
    modified in place, exactly as the effect modifies *(fpip+0xAC)."""
    if status != 1:
        return img                          # 0x10012de8
    key = Key(key_yc, track)
    colour_correct, alpha_fix = bool(check[0]), bool(check[1])
    if key.r == 0:
        (_plain_cc(img, key, alpha_fix) if colour_correct else _plain(img, key))
    else:
        _border(img, key, colour_correct, alpha_fix)
    return img


# --------------------------------------------------------------------------
# self-checks
# --------------------------------------------------------------------------

GREEN = (300, -600, -400)       # a plausible eyedropper result: y, cb, cr
DEFAULTS = [24, 96, 1]


def _image(w, h, px):
    return [[list(px) for _ in range(w)] for _ in range(h)]


def _scene(w, h, key_yc, fg):
    """A key-coloured field, an opaque foreground block, and a ring of
    half-and-half pixels between them - the contaminated edge that 色彩補正
    and 透過補正 exist for. Without it every pixel is either exactly the key
    or nowhere near it, and the interesting paths never run."""
    img = _image(w, h, (*key_yc, 4096))
    lo, hi = h // 4, 3 * h // 4
    mixed = [(a + b) // 2 for a, b in zip(key_yc, fg)]
    for y in range(lo - 1, hi + 1):
        for x in range(w // 4 - 1, 3 * w // 4 + 1):
            inner = lo <= y < hi and w // 4 <= x < 3 * w // 4
            img[y][x] = [*(fg if inner else mixed), 4096]
    return img


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    fg = (700, 100, 250)

    print("--- keying, 境界補正 = 0 ---")
    for cc in (0, 1):
        img = _scene(8, 8, GREEN, fg)
        chroma_key(img, GREEN, 1, [24, 96, 0], [cc, 0, 0])
        bg = {tuple(img[0][x]) for x in range(8)}
        check(f"色彩補正={cc}: an exact key-colour pixel goes fully transparent",
              all(p[3] == 0 for p in bg), f"corners: {sorted(bg)[0]}")
        check(f"色彩補正={cc}: the foreground block is untouched",
              img[4][4] == [*fg, 4096], f"centre: {img[4][4]}")

    img = _scene(8, 8, GREEN, fg)
    before = [row[:] for row in img]
    chroma_key(img, GREEN, 0, DEFAULTS, [0, 0, 0])
    check("status != 1 is a bit-exact no-op", img == before)

    print("\n--- the key colour's luminance is not used ---")
    a = _scene(8, 8, GREEN, fg)
    b = _scene(8, 8, GREEN, fg)
    chroma_key(a, GREEN, 1, DEFAULTS, [1, 1, 0])
    chroma_key(b, (-4096, GREEN[1], GREEN[2]), 1, DEFAULTS, [1, 1, 0])
    check("a key colour of the same chroma but opposite luminance is identical",
          a == b)

    print("\n--- 透過補正 needs 色彩補正 ---")
    for r in (0, 2):
        a = _scene(8, 8, GREEN, fg)
        b = _scene(8, 8, GREEN, fg)
        chroma_key(a, GREEN, 1, [24, 96, r], [0, 0, 0])
        chroma_key(b, GREEN, 1, [24, 96, r], [0, 1, 0])
        check(f"境界補正={r}, 色彩補正 off: 透過補正 changes nothing", a == b)
    a = _scene(8, 8, GREEN, fg)
    b = _scene(8, 8, GREEN, fg)
    chroma_key(a, GREEN, 1, [24, 96, 0], [1, 0, 0])
    chroma_key(b, GREEN, 1, [24, 96, 0], [1, 1, 0])
    check("色彩補正 on: 透過補正 does change the result", a != b)

    print("\n--- 色相範囲 = 256 disables the hue half of the metric ---")
    key = Key(GREEN, [256, 96, 0])
    worst = max(key.distance(cb, cr, key.sat)[1]
                for cb in range(-2048, 2049, 97) for cr in range(-2048, 2049, 97))
    check("hue_range = 32768 leaves no hue excess anywhere in the Cb/Cr plane",
          worst == 0, f"max hue_excess = {worst}")

    print("\n--- the spill un-mix inverts a grey-foreground mix ---")
    key = Key(GREEN, DEFAULTS)
    errs = []
    for pct in range(5, 100, 5):
        c = pct / 100
        px = [0, round((1 - c) * GREEN[1]), round((1 - c) * GREEN[2]), 4096]
        f = key.coverage(0, sat_of(px[1], px[2]))
        key.unmix(px, f)
        errs.append(max(abs(px[1]), abs(px[2])))
    check("a grey foreground comes back grey to within a few LSBs",
          max(errs) <= 8, f"worst residual chroma = {max(errs)}")

    print("\n--- 境界補正 ---")
    a_c, b_c = stretch_constants(1)
    check("境界補正 = 1: the stretch is the identity", (a_c, b_c) == (0, 0),
          f"A = {a_c}, B = {b_c}")
    check("t(4096) == 4096 for every 境界補正 in range",
          all((4096 - stretch_constants(r)[0]) * r + stretch_constants(r)[1] == 4096
              for r in range(1, 6)))

    img = _image(12, 12, (700, 100, 250, 4096))      # nothing matches the key
    chroma_key(img, GREEN, 1, [24, 96, 3], [0, 0, 0])
    interior = {img[y][x][3] for y in range(4, 8) for x in range(4, 8)}
    border = {img[0][x][3] for x in range(12)}
    check("an image with no key colour in it still loses its border rows",
          interior == {4096} and border == {0},
          f"interior alpha {interior}, row 0 alpha {border}")
    img = _image(12, 12, (700, 100, 250, 4096))
    chroma_key(img, GREEN, 1, [24, 96, 0], [0, 0, 0])
    check("... which does not happen at 境界補正 = 0",
          {img[y][x][3] for y in range(12) for x in range(12)} == {4096})

    print("\n--- an achromatic key colour keys greys, not a hue ---")
    # key_sat = 0 makes sat_range 0 whatever 彩度範囲 says, so the saturation
    # term is 8*sat for every pixel and only true greys can survive it.
    img = [[[2048, 0, 0, 4096], [2048, 700, -300, 4096], [2048, 40, 0, 4096]]]
    chroma_key(img, (2048, 0, 0), 1, [256, 256, 0], [0, 0, 0])
    check("cb = cr = 0: a grey pixel is erased outright",
          img[0][0][3] == 0, f"alpha {img[0][0][3]}")
    check("cb = cr = 0: a saturated pixel is kept (8*sat >= 4096)",
          img[0][1][3] == 4096, f"alpha {img[0][1][3]}")
    check("cb = cr = 0: a nearly-grey pixel is only attenuated",
          0 < img[0][2][3] < 4096, f"alpha {img[0][2][3]}")

    ok = sum(1 for _, good in checks if good)
    print(f"\n{ok}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
