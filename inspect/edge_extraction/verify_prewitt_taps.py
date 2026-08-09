"""What the three workers actually convolve with, derived from the instructions.

The claim this script exists to prove is that all three workers compute the
**Prewitt operator** - not Sobel, not a Laplacian, not a 4-neighbour difference:

    Gx = [[-1, 0, +1],      Gy = [[-1, -1, -1],
          [-1, 0, +1],            [ 0,  0,  0],
          [-1, 0, +1]]            [+1, +1, +1]]

and combine the two with a Euclidean magnitude `sqrt(Gx^2 + Gy^2)`. The centre
pixel's colour is never read at all; only its alpha, and only after the
magnitude is finished (verify_output_encoding.py).

Reading that off by hand is exactly the kind of thing that goes wrong: the taps
are addressed as `word ptr [esi + edi - 0x1c]` with esi/edi holding a
row-relative base built by six `lea`s, the eight neighbours are visited in an
order that is not raster order, and each accumulator is updated through a
different register - one of them through a stack slot. So instead of asserting
it, this script *interprets* the code.

`Track` is a small abstract interpreter over linear forms. Every register and
stack slot holds an integer combination of the symbols

    C   the source buffer *(fpip+0xAC)      S   row stride, in pixels
    D   the pair buffer *(fpip+0xB0)        W   w      H   h
    Y0  the first row of this thread        Y1  one past its last row
    s(dy,dx).f   one 16-bit sample read from a neighbour

which is enough for everything on the path: `lea`, `add`, `sub`, `neg`, `shl`,
`dec` and moves through `[esp+..]` slots are all linear. `imul` of two unknowns
(the row offset `stride * y0`) becomes an opaque symbol, which is all it needs
to be. When a `movsx` reads memory its address is resolved in that algebra,
expressed relative to the centre pixel `P`, and turned into a `(dy, dx, field)`
triple - so a mistake about a base register cannot pass unnoticed: it would land
the tap on a non-existent field offset or outside the 3x3 neighbourhood, and
section 2 checks for exactly that.

Two things are given to the interpreter rather than derived, and both are named
in the output: the register state right after the `idiv` pair that splits the
rows between threads, and which register holds the centre pixel `P` once the row
pointers are built. Everything downstream of those - esi, edi and the four stack
slots the tap addressing uses - comes out of the interpretation.

The run takes the *interior* path: an opaque neighbourhood (every alpha >= 4096,
so no premultiply - see verify_alpha_weight.py) on a row that is neither the
first nor the last (the border rows are constant fills - see verify_border.py).

Run via main.py:
    uv run main.py inspect/edge_extraction/verify_prewitt_taps.py
    uv run main.py inspect/edge_extraction/verify_prewitt_taps.py --trace 輝度
"""

import argparse
import re

from tools.disasm import disasm_range
from tools.pe_image import PEImage

# ---------------------------------------------------------------- linear forms

Form = dict  # {symbol: coefficient}; "" is the constant term


def form(**kw) -> Form:
    return {k: v for k, v in kw.items() if v}


def const(n: int) -> Form:
    return {"": n} if n else {}


def add(a: Form, b: Form, k: int = 1) -> Form:
    out = dict(a)
    for s, c in b.items():
        out[s] = out.get(s, 0) + k * c
        if not out[s]:
            del out[s]
    return out


def scale(a: Form, k: int) -> Form:
    return {s: c * k for s, c in a.items()} if k else {}


def show(f: Form) -> str:
    if not f:
        return "0"
    parts = []
    for s in sorted(f, key=lambda s: (s == "", s)):
        c, mag = f[s], abs(f[s])
        sign = "-" if c < 0 else "+"
        parts.append(f"{sign} {mag}" if s == "" else
                     f"{sign} {s}" if mag == 1 else f"{sign} {mag}*{s}")
    text = " ".join(parts)
    return text[2:] if text.startswith("+ ") else text

# ------------------------------------------------------------------ x86 subset

REG16 = {"ax": "eax", "bx": "ebx", "cx": "ecx", "dx": "edx",
         "si": "esi", "di": "edi", "bp": "ebp", "sp": "esp"}
REG8 = {"al": "eax", "bl": "ebx", "cl": "ecx", "dl": "edx",
        "ah": "eax", "bh": "ebx", "ch": "ecx", "dh": "edx"}
REGS = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}

# the only fpip fields any of the three workers reads
FPIP = {0xAC: "C", 0xB0: "D", 0xB4: "W", 0xB8: "H", 0xEC: "S"}

# the five globals func_proc fills in; reading one is never an image access
GLOBALS = {0x10134E6C: "T", 0x10134E70: "colorCb", 0x10134E72: "colorCr",
           0x10134E74: "strength", 0x10134E78: "colorY"}

FIELDS = {0: "y", 2: "cb", 4: "cr", 6: "a"}
BRANCHES = ("jmp", "jl", "jle", "jge", "jne", "je", "jns", "js", "jg", "ja", "jb")


def reg(name: str) -> str:
    return REG16.get(name, REG8.get(name, name))


class Track:
    """Abstract interpreter over the linear forms above."""

    def __init__(self, img: PEImage, regs: dict, slots: dict, p_hook: tuple):
        self.img = img
        self.regs = {r: {} for r in REGS} | {"esp": form(esp=1)} | regs
        self.slots = dict(slots)
        self.p_hook = p_hook        # (address, register) -> P after that insn
        self.P = None
        self.taps = []              # (addr, dy, dx, field) in execution order
        self.trace = []
        self.notes = []

    # -- operands ---------------------------------------------------------

    def mem_form(self, text: str) -> Form:
        inner = text[text.index("[") + 1:text.rindex("]")]
        out, sign = {}, 1
        for tok in re.findall(r"[+-]|[^\s+\-]+", inner):
            if tok in "+-":
                sign = 1 if tok == "+" else -1
                continue
            if "*" in tok:
                r, s = tok.split("*")
                out = add(out, self.regs[reg(r)], sign * int(s))
            elif reg(tok) in REGS:
                out = add(out, self.regs[reg(tok)], sign)
            else:
                out = add(out, const(int(tok, 0)), sign)
            sign = 1
        return out

    def slot_key(self, text: str):
        """`[esp + 0x14]` -> the slot key, or None if it is not a stack slot."""
        f = self.mem_form(text)
        return f.get("", 0) if f.get("esp") else None

    def value(self, text: str) -> Form:
        if reg(text) in REGS:
            return self.regs[reg(text)]
        return self.load(text) if "[" in text else const(int(text, 0))

    def store(self, text: str, val: Form) -> None:
        if reg(text) in REGS:
            self.regs[reg(text)] = val
            return
        key = self.slot_key(text)
        if key is not None:
            self.slots[key] = val
        # writes to the output image are not modelled: nothing here reads them

    # -- memory -----------------------------------------------------------

    def load(self, text: str) -> Form:
        key = self.slot_key(text)
        if key is not None:
            return self.slots.get(key, {})
        f = self.mem_form(text)
        if set(f) <= {""}:                                  # absolute address
            va = f.get("", 0)
            if va in GLOBALS:
                return form(**{GLOBALS[va]: 1})
            self.notes.append(f"unknown absolute read 0x{va:08x}")
            return {}
        if f.get("F") == 1 and set(f) <= {"F", ""}:          # fpip field
            off = f.get("", 0)
            if off in FPIP:
                return form(**{FPIP[off]: 1})
            self.notes.append(f"unknown fpip field +0x{off:x}")
            return {}
        return self.sample(f)

    def sample(self, f: Form) -> Form:
        """Classify an image read and hand back a fresh symbol for it."""
        if self.P is None:
            self.notes.append(f"image read before P is known: {show(f)}")
            return {}
        rel = add(f, self.P, -1)
        if rel.get("D"):
            self.notes.append(f"read from the *output* buffer: {show(f)}")
            return {}
        if set(rel) - {"S", ""}:
            self.notes.append(f"unresolved image address: {show(f)}")
            return {}
        srow, byte = rel.get("S", 0), rel.get("", 0)
        if srow % 8:
            self.notes.append(f"address is not a whole number of rows away: {show(f)}")
            return {}
        dy = srow // 8
        dx, field = divmod(byte, 8)
        if field not in FIELDS or not -1 <= dy <= 1 or not -1 <= dx <= 1:
            self.notes.append(f"tap outside the 3x3 neighbourhood: dy={dy} dx={dx} +{field}")
            return {}
        return form(**{f"s({dy:+d},{dx:+d}).{FIELDS[field]}": 1})

    # -- execution --------------------------------------------------------

    def run(self, start: int, end: int, taken: dict, limit: int = 4000) -> None:
        """Interpret from `start` to `end`, resolving branches through `taken`.

        A conditional not listed in `taken` is not taken. That default is what
        picks the opaque path: every tap opens with `cmp <neighbour alpha>,
        0x1000 / jl <premultiply>`.
        """
        pc, steps = start, 0
        while pc != end:
            if (steps := steps + 1) > limit:
                raise RuntimeError(f"runaway at 0x{pc:08x}")
            insn = next(iter(disasm_range(self.img, pc, 16, resolve=False)))[0]
            pc = insn.address + insn.size
            m, ops = insn.mnemonic, [o.strip() for o in insn.op_str.split(",")]
            if m in BRANCHES:
                if m == "jmp" or taken.get(insn.address, False):
                    pc = int(ops[0], 16)
                continue
            if m in ("cmp", "test", "fild", "fsqrt", "call", "nop"):
                continue
            if m == "mov":
                self.store(ops[0], self.value(ops[1]))
            elif m in ("movsx", "movzx"):
                val = self.load(ops[1])
                for s in val:
                    dy, dx, fld = re.match(r"s\(([-+]\d),([-+]\d)\)\.(\w+)", s).groups()
                    self.taps.append((insn.address, int(dy), int(dx), fld))
                self.store(ops[0], val)
            elif m == "lea":
                self.store(ops[0], self.mem_form(ops[1]))
            elif m == "add":
                self.store(ops[0], add(self.value(ops[0]), self.value(ops[1])))
            elif m == "sub":
                self.store(ops[0], add(self.value(ops[0]), self.value(ops[1]), -1))
            elif m == "neg":
                self.store(ops[0], scale(self.value(ops[0]), -1))
            elif m == "xor" and ops[0] == ops[1]:
                self.store(ops[0], {})
            elif m == "dec":
                self.store(ops[0], add(self.value(ops[0]), const(-1)))
            elif m == "inc":
                self.store(ops[0], add(self.value(ops[0]), const(1)))
            elif m == "shl":
                self.store(ops[0], scale(self.value(ops[0]), 1 << int(ops[1], 0)))
            elif m == "imul" and len(ops) == 2:
                a, b = self.value(ops[0]), self.value(ops[1])
                if not set(b) - {""}:
                    self.store(ops[0], scale(a, b.get("", 0)))
                elif not set(a) - {""}:
                    self.store(ops[0], scale(b, a.get("", 0)))
                else:
                    # stride * y0: the row offset. Its value does not matter,
                    # only that every tap in the row shares it.
                    self.store(ops[0], form(**{f"row@{insn.address:08x}": 1}))
            else:
                raise RuntimeError(f"unhandled `{m} {insn.op_str}` at 0x{insn.address:08x}")
            self.trace.append((insn.address, f"{insn.mnemonic:<6} {insn.op_str}"))
            if insn.address == self.p_hook[0]:
                self.P = self.regs[self.p_hook[1]]

    def read(self, where: str) -> Form:
        return self.regs[reg(where)] if reg(where) in REGS else self.slots.get(int(where, 0), {})


# ----------------------------------------------------------------- the workers

WORKERS = {
    "色エッジ (両チェック OFF)": {
        "addr": 0x10022E30,
        # from just after the two idivs, to the start of the magnitude
        "span": (0x10022E68, 0x1002336C),
        "regs": {"edi": form(F=1), "esi": form(H=1), "ebx": form(W=1),
                 "eax": form(Y1=1), "ecx": form(Y0=1)},
        "slots": {0x3C: form(Y0=1)},
        "taken": {0x10022E74: True, 0x10022EC2: True},
        "p_hook": (0x10022F69, "ecx"),
        "channels": ("y", "cb", "cr"),
        "acc": {("Gy", "y"): "ebx", ("Gy", "cb"): "ebp", ("Gy", "cr"): "eax",
                ("Gx", "y"): "0x10", ("Gx", "cb"): "0x40", ("Gx", "cr"): "0x3c"},
    },
    "輝度エッジ": {
        "addr": 0x100234C0,
        "span": (0x100234F2, 0x10023789),
        "regs": {"esi": form(F=1), "ebx": form(H=1), "ebp": form(W=1),
                 "eax": form(Y1=1), "edi": form(Y0=1)},
        "slots": {},
        "taken": {0x100234FE: True, 0x10023549: True},
        "p_hook": (0x100235EB, "eax"),
        "channels": ("y",),
        "acc": {("Gy", "y"): "ecx", ("Gx", "y"): "eax"},
    },
    "透明度エッジ": {
        "addr": 0x10023880,
        "span": (0x100238B6, 0x10023A09),
        "regs": {"esi": form(F=1), "ebx": form(H=1),
                 "eax": form(Y1=1), "edi": form(Y0=1)},
        "slots": {0x10: form(W=1)},
        "taken": {0x100238BE: True, 0x10023901: True},
        "p_hook": (0x100239AC, "eax"),
        "channels": ("a",),
        "acc": {("Gy", "a"): "eax", ("Gx", "a"): "ecx"},
    },
}

PREWITT = {
    "Gx": {(-1, -1): -1, (-1, +1): +1,
           (0, -1): -1, (0, +1): +1,
           (+1, -1): -1, (+1, +1): +1},
    "Gy": {(-1, -1): -1, (-1, 0): -1, (-1, +1): -1,
           (+1, -1): +1, (+1, 0): +1, (+1, +1): +1},
}

NEIGHBOURS = [(dy, dx) for dy in (-1, 0, 1) for dx in (-1, 0, 1) if (dy, dx) != (0, 0)]


def kernel_of(f: Form, channel: str):
    k = {}
    for s, c in f.items():
        m = re.match(r"s\(([-+]\d),([-+]\d)\)\.(\w+)$", s)
        if not m or m.group(3) != channel:
            return None
        k[(int(m.group(1)), int(m.group(2)))] = c
    return k


def grid(k: dict) -> str:
    return "  |  ".join(" ".join(f"{k.get((dy, dx), 0):+d}" for dx in (-1, 0, 1))
                        for dy in (-1, 0, 1))


def run(dll_path: str, headers: list[str], argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="verify_prewitt_taps")
    parser.add_argument("--trace", help="also print the interpreted instruction stream")
    args = parser.parse_args(argv or [])

    img = PEImage(dll_path)
    failures = 0

    for name, w in WORKERS.items():
        start, end = w["span"]
        t = Track(img, w["regs"], w["slots"], w["p_hook"])
        t.run(start, end, w["taken"])

        print(f"=== {name}  worker 0x{w['addr']:08x} "
              f"(interpreted 0x{start:08x}..0x{end:08x}) ===")

        print("  1. what the tap addressing ended up being (derived, not assumed):")
        print(f"     P (centre pixel)  = {show(t.P)}")
        for r in ("esi", "edi", "ebx"):
            v = t.read(r)
            if any(s in v for s in ("C", "S")):
                print(f"     {r:<17} = {show(v)}")
        for key in sorted(t.slots):
            v = t.slots[key]
            if any(s in v for s in ("C", "D", "S")):
                print(f"     {f'[esp+0x{key:02x}]':<17} = {show(v)}")

        print("  2. every 16-bit image read in the loop body, in execution order:")
        seen = {}
        for a, dy, dx, fld in t.taps:
            seen.setdefault((dy, dx), set()).add(fld)
            print(f"     0x{a:08x}  s({dy:+d},{dx:+d}).{fld}")
        missing = [n for n in NEIGHBOURS if n not in seen]
        centre = (0, 0) in seen
        failures += bool(missing or centre or t.notes)
        print(f"     -> {len(seen)} distinct positions; "
              f"{'all 8 neighbours' if not missing else 'MISSING ' + str(missing)}; "
              f"centre pixel read here: {centre}")
        fields = sorted({f for fs in seen.values() for f in fs})
        print(f"     -> fields touched: {fields}  (the effect's channels are "
              f"{list(w['channels'])}; `a` is each neighbour's own alpha)")
        for n in t.notes:
            print(f"     !! {n}")

        print("  3. the accumulators, as linear combinations of those samples:")
        for (gname, ch), where in w["acc"].items():
            k = kernel_of(t.read(where), ch)
            home = where if where.startswith("e") else f"[esp+{where}]"
            if k is None:
                print(f"     {gname}.{ch:<3} ({home:<11}) = {show(t.read(where))}"
                      "   !! not a pure kernel")
                failures += 1
                continue
            good = k == PREWITT[gname]
            failures += not good
            print(f"     {gname}.{ch:<3} ({home:<11}) = {grid(k)}   "
                  f"{'OK' if good else 'MISMATCH'}")
        print()

        if args.trace and args.trace in name:
            print("  --- interpreted instruction stream ---")
            for a, text in t.trace:
                print(f"     0x{a:08x}: {text}")
            print()

    print(f"reference Prewitt   Gx = {grid(PREWITT['Gx'])}")
    print(f"                    Gy = {grid(PREWITT['Gy'])}")
    print(f"\n-> {'ALL OK' if not failures else f'{failures} MISMATCH(ES)'}")
    print("Sobel would weight the middle tap of each edge by 2; nothing in any of the")
    print("three workers is ever multiplied by 2, and the centre pixel is not part of")
    print("either sum - so this is Prewitt, and the response is 3x that of a plain")
    print("1-pixel difference.")


if __name__ == "__main__":
    run("data/exedit.auf", ["data/filter.h"])
