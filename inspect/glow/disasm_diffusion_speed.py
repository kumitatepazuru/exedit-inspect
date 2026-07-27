"""Decode the pair of full-buffer transforms 拡散速度 ("diffusion speed")
wraps around the 6 blur passes, by resolving every floating point constant
the four functions involved touch.

    base    = 1 + clamp(拡散速度, 1, 100) * 0.001
    forward = pow(base, y/16) - 1        once, before the 6 passes
    inverse = 16 * log_base(sum + 1)     once, after them

i.e. luma is blurred in an exponential domain rather than a linear one.
Because sum(base^x_i) is increasingly dominated by the largest x_i as base
grows past 1, averaging there and mapping back behaves less like a mean and
more like a soft maximum over the blur kernel - the brightest spot in a
neighbourhood pushes outward far more assertively than a linear average
would allow, which matches AviUtl's own description of the trackbar ("光の
拡散していく速さを指定します。※若干処理が重くなります。" - it sets how fast
the light spreads, and makes processing slightly heavier: this is a genuine
extra full-buffer round trip, not a cheaper substitute path).

Range handling around these two transforms is what actually bites a port -
see verify_curve_clamp.py for the input clamp and the deliberately
unclamped output, and verify_accumulate.py for what happens to the six
values in between.

Run via main.py:
    uv run main.py inspect/glow/disasm_diffusion_speed.py
"""

from tools.disasm import dump_all
from tools.pe_image import PEImage

# forward transform: runs once over the glow buffer BEFORE the 6-pass blur
FORWARD_ENTRY = (0x10070550, 0x60)   # clamps 拡散速度 to [1,100], computes base = 1 + speed*0.001
FORWARD_WORKER = (0x100705C0, 0x140)  # per-pixel: curved = pow(base, y/16) - 1; chroma -> signed byte /16

# inverse transform: runs once over the glow buffer AFTER the 6-pass blur
INVERSE_ENTRY = (0x10070700, 0x80)    # same clamp; computes 1/ln(base)
INVERSE_WORKER = (0x10070780, 0x160)  # per-pixel: y = round(16 * ln(curved+1) / ln(base)); chroma <<4


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    dump_all(PEImage(dll_path), {
        "forward transform entry (clamp + base = 1+speed*0.001)": FORWARD_ENTRY,
        "forward transform worker (curved = pow(base, y/16) - 1)": FORWARD_WORKER,
        "inverse transform entry (clamp + 1/ln(base))": INVERSE_ENTRY,
        "inverse transform worker (y = 16*log_base(curved+1))": INVERSE_WORKER,
    })

    print(
        "\n"
        "Resolved constants:\n"
        "  0x1009a3a8 = 0.001   (speed_clamped * 0.001)\n"
        "  0x1009a428 = 1.0     (+1.0 to build base; also used as fdivr numerator for 1/ln(base))\n"
        "  0x1009a788 = 0.0625  (= 1/16, luma 0..4096 -> 0..256 before the pow())\n"
        "  0x1009a424 = 1.0f    (float32; -1.0f after pow(), +1.0f before the matching log)\n"
        "\n"
        "Net effect: base = 1 + clamp(拡散速度,1,100)*0.001 (~1.001 .. 1.1 for the UI's 0..60 range).\n"
        "  forward: curved(y) = base^(y/16) - 1        (applied before the 6-pass blur)\n"
        "  inverse: y'         = 16 * log_base(curved+1) (applied after the 6-pass blur, exact inverse)\n"
        "This blurs luma in an exponential/log domain instead of linear space. Since\n"
        "sum(base^x_i) is dominated by the largest x_i as base grows past 1, averaging in this\n"
        "domain and mapping back behaves less like a plain mean and more like a soft maximum of\n"
        "the pixels inside the blur kernel - i.e. the brightest spot in a neighbourhood pushes its\n"
        "value outward through the blur far more assertively than a linear average would let it,\n"
        "which is a reasonable reading of the tooltip's \"光の拡散していく速さ\" (how fast/strongly\n"
        "the light spreads). It also explains the tooltip's \"processing becomes slightly heavier\":\n"
        "this is a genuine extra full-buffer forward+inverse pass, not a cheaper substitute path.\n"
    )


if __name__ == "__main__":
    run("exedit.auf", ["filter.h"])
