"""An integer-faithful reference implementation of カラーキー, plus self-checks.

Everything the other scripts in this directory establish, assembled into one
executable statement of the effect. All three workers are here, each written to
follow its code path instruction for instruction - `c_div` where the code uses
`idiv`, `sar` where it uses `sar`, and the box passes replayed phase by phase
rather than as a closed form. The redundant second dispatch of the key worker is
kept rather than optimised away, so the reference has the same shape as
func_proc.

There is no floating point to model: カラーキー contains none
(verify_key_box.py). There is no frame-filter variant either - the effect has
one registration and it is the object effect, so the pixel format is always
exedit's 8-byte PIXEL_YCA (`y, cb, cr, a` as four signed 16-bit fields, alpha
0..4096).

Nothing here reads the DLL: this is the *claim*. The scripts that read the DLL
are disasm_params.py (the branch tree), verify_key_box.py (the key test),
verify_dispatch.py (who runs, on what) and verify_border_chain.py (境界補正).

The self-checks at the bottom are the point. Each is a property that follows
from the reading above and would break if the reading were wrong - the box
bounds being inclusive, alpha being binary without 境界補正, the second key
pass changing nothing, chroma never being written, and 境界補正 destroying
semi-transparency.

Run via main.py:
    uv run main.py inspect/color_key/simulate_color_key_reference.py
"""

from tools.cints import c_div, sar


# --------------------------------------------------------------------------
# worker 0x10016340 - the key test
# --------------------------------------------------------------------------

def _key_pass(img, key_yc, y_range, c_range) -> None:
    """`a = 0` inside an axis-aligned box around the key colour.

    Six inclusive interval tests (`jl` / `jg`, never `jle` / `jge`), one store
    of a literal 0, and nothing else - in particular no distance and no
    interpolation, so the result is binary.
    """
    ky, kcb, kcr = key_yc
    ymin, ymax = ky - y_range, ky + y_range
    cbmin, cbmax = kcb - c_range, kcb + c_range
    crmin, crmax = kcr - c_range, kcr + c_range
    for row in img:
        for px in row:
            if ymin <= px[0] <= ymax and cbmin <= px[1] <= cbmax \
                    and crmin <= px[2] <= crmax:
                px[3] = 0


# --------------------------------------------------------------------------
# workers 0x10016430 / 0x100165d0 - 境界補正
# --------------------------------------------------------------------------

def box_1d(src: list, r: int) -> list:
    """One line of either box pass, replayed phase by phase.

    Divisor is always the kernel width and samples outside the line read as
    zero, i.e. as "fully transparent". Written out rather than as a slice sum
    so the phase counts match the loop bounds in the binary; verify_border_chain.py
    checks the two against each other. The real code writes 2r+1 samples even
    when the line is shorter than that, which is the overrun documented there;
    here the tail is simply dropped.
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
    return out[:n]


def stretch_constants(r: int) -> tuple:
    """0x10016602..0x10016628, the same pair クロマキー computes."""
    q = c_div(4096, r)
    return 4096 - q, 4096 - q * r


def _border_pass(img, r: int) -> None:
    """pass 2 (0x10016430) then pass 3 (0x100165d0).

    Note what is being blurred: the pixel alpha, in place in the object buffer.
    クロマキー runs the identical code over a 16-bit matte it built in a
    scratch buffer, which is why the two effects diverge on semi-transparent
    input even though the arithmetic is the same.
    """
    h, w = len(img), len(img[0])

    # pass 2: vertical box average of the alpha, image -> pair buffer.
    # Only the alpha field of the pair buffer is written; its y/cb/cr keep
    # whatever they held, and nothing reads them.
    temp = [[0] * w for _ in range(h)]
    for x in range(w):
        col = box_1d([img[y][x][3] for y in range(h)], r)
        for y in range(h):
            temp[y][x] = col[y]

    # pass 3: horizontal box average of that, then the product and the stretch,
    # applied back into the image alpha in place.
    a_const, b_const = stretch_constants(r)
    for y in range(h):
        blurred = box_1d(temp[y], r)
        for x in range(w):
            a = img[y][x][3]
            v = sar(blurred[x] * a, 12)
            if v == 0:
                img[y][x][3] = 0
                continue
            t = (v - a_const) * r + b_const
            img[y][x][3] = 0 if t <= 0 else sar(a * t, 12)


# --------------------------------------------------------------------------
# func_proc 0x100162c0
# --------------------------------------------------------------------------

def color_key(img, key_yc, status, track):
    """`img` is a list of rows of [y, cb, cr, a] and is modified in place,
    exactly as the effect modifies *(fpip+0xAC)."""
    if status != 1:                                   # 0x100162c8
        return img
    y_range, c_range, r = track
    _key_pass(img, key_yc, y_range, c_range)          # dispatch 1
    if r != 0:                                        # 0x100162ee
        _key_pass(img, key_yc, y_range, c_range)      # dispatch 2 - the repeat
        _border_pass(img, r)                          # dispatches 3 and 4
    return img


# --------------------------------------------------------------------------
# self-checks
# --------------------------------------------------------------------------

GREEN = (1200, -600, -400)      # a plausible eyedropper result: y, cb, cr
FG = (2600, 100, 250)


def _image(w, h, px):
    return [[list(px) for _ in range(w)] for _ in range(h)]


def _scene(w, h, key_yc, fg, alpha=4096):
    """A key-coloured field with an opaque foreground block in the middle, and
    a ring of half-and-half pixels between them - the contaminated edge a key
    with a widened box is supposed to catch."""
    img = _image(w, h, (*key_yc, alpha))
    lo, hi = h // 4, 3 * h // 4
    mixed = [(a + b) // 2 for a, b in zip(key_yc, fg)]
    for y in range(lo - 1, hi + 1):
        for x in range(w // 4 - 1, 3 * w // 4 + 1):
            inner = lo <= y < hi and w // 4 <= x < 3 * w // 4
            img[y][x] = [*(fg if inner else mixed), alpha]
    return img


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, ok))
        print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"   {detail}" if detail else ""))

    print("--- the key test ---")
    img = _scene(8, 8, GREEN, FG)
    color_key(img, GREEN, 1, [0, 0, 0])
    check("an exact key-colour pixel goes fully transparent", img[0][0][3] == 0,
          f"corner: {img[0][0]}")
    check("the foreground block is untouched", img[4][4] == [*FG, 4096],
          f"centre: {img[4][4]}")

    img = _scene(8, 8, GREEN, FG)
    before = [[px[:] for px in row] for row in img]
    color_key(img, GREEN, 0, [256, 256, 3])
    check("status != 1 is a bit-exact no-op", img == before)

    print("\n--- the bounds are inclusive, on all three axes ---")
    for axis, name in enumerate(("y", "cb", "cr")):
        rng = 100
        track = [rng, rng, 0]
        on = list(GREEN)
        on[axis] += rng
        off = list(GREEN)
        off[axis] += rng + 1
        img = [[[*on, 4096], [*off, 4096]]]
        color_key(img, GREEN, 1, track)
        check(f"{name}: key+range is keyed, key+range+1 is kept",
              img[0][0][3] == 0 and img[0][1][3] == 4096,
              f"{img[0][0][3]} / {img[0][1][3]}")

    print("\n--- 色差範囲 is one range for two axes ---")
    a = [[[GREEN[0], GREEN[1] + 300, GREEN[2], 4096]]]
    b = [[[GREEN[0], GREEN[1], GREEN[2] + 300, 4096]]]
    color_key(a, GREEN, 1, [0, 300, 0])
    color_key(b, GREEN, 1, [0, 300, 0])
    check("a 300-unit offset in cb and in cr are treated identically",
          a[0][0][3] == b[0][0][3] == 0)
    a = [[[GREEN[0], GREEN[1] + 301, GREEN[2], 4096]]]
    color_key(a, GREEN, 1, [0, 300, 0])
    check("... and both fall out of the box at 301", a[0][0][3] == 4096)

    print("\n--- the key colour's luminance IS used (unlike クロマキー) ---")
    a = _scene(8, 8, GREEN, FG)
    b = _scene(8, 8, GREEN, FG)
    color_key(a, GREEN, 1, [200, 400, 0])
    color_key(b, (GREEN[0] + 2000, GREEN[1], GREEN[2]), 1, [200, 400, 0])
    check("moving the key colour along y alone changes the result", a != b)

    print("\n--- 境界補正 = 0 produces a binary alpha ---")
    img = _scene(16, 16, GREEN, FG)
    color_key(img, GREEN, 1, [400, 400, 0])
    alphas = {px[3] for row in img for px in row}
    check("every alpha is either 0 or the input 4096", alphas <= {0, 4096},
          f"distinct alphas: {sorted(alphas)}")

    print("\n--- the second dispatch of the key worker changes nothing ---")
    img = _scene(16, 16, GREEN, FG)
    once = [[px[:] for px in row] for row in img]
    _key_pass(once, GREEN, 400, 400)
    twice = [[px[:] for px in row] for row in img]
    _key_pass(twice, GREEN, 400, 400)
    _key_pass(twice, GREEN, 400, 400)
    check("running the key pass twice equals running it once", once == twice)

    print("\n--- chroma and luminance are never written ---")
    img = _scene(16, 16, GREEN, FG)
    before = [[px[:] for px in row] for row in img]
    color_key(img, GREEN, 1, [400, 400, 3])
    check("y, cb, cr survive the whole 境界補正 chain unchanged",
          all(px[:3] == q[:3] for row, brow in zip(img, before)
              for px, q in zip(row, brow)))

    print("\n--- 境界補正 on a fully opaque image with no key colour ---")
    for r in (1, 3):
        img = _image(16, 16, (*FG, 4096))
        color_key(img, GREEN, 1, [0, 0, r])
        interior = {img[y][x][3] for y in range(6, 10) for x in range(6, 10)}
        check(f"r={r}: the interior is left fully opaque", interior == {4096},
              f"interior alphas {sorted(interior)}")
        check(f"r={r}: the outermost row is still eroded", img[0][0][3] < 4096,
              f"corner alpha {img[0][0][3]}")
    img = _image(16, 16, (*FG, 4096))
    color_key(img, GREEN, 1, [0, 0, 0])
    check("... and none of that happens at 境界補正 = 0",
          {px[3] for row in img for px in row} == {4096})

    print("\n--- 境界補正 destroys semi-transparency ---")
    for r, expect in ((1, 512), (2, 0)):
        img = _image(16, 16, (*FG, 2048))       # uniformly 50% opaque, no key
        color_key(img, GREEN, 1, [0, 0, r])
        got = img[8][8][3]
        check(f"r={r}: a uniform 50%-opaque object comes out at {expect}/4096",
              got == expect, f"got {got}")
    print("  r=1 is alpha^3 / 4096^2; r>=2 clips it away entirely. The cause is that")
    print("  the value pass 3 multiplies by is the alpha itself, where クロマキー")
    print("  multiplies by a matte that is 4096 for any non-key pixel.")

    print("\n--- the stretch ---")
    a_c, b_c = stretch_constants(1)
    check("境界補正 = 1: the stretch is the identity", (a_c, b_c) == (0, 0),
          f"A = {a_c}, B = {b_c}")
    check("t(4096) == 4096 for every 境界補正 in range",
          all((4096 - stretch_constants(r)[0]) * r + stretch_constants(r)[1] == 4096
              for r in range(1, 6)))

    ok = sum(1 for _, good in checks if good)
    print(f"\n{ok}/{len(checks)} checks passed.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
