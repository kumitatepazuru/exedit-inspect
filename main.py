"""Bridge for running exedit-inspect reverse-engineering scripts.

Every script written for this project is executed through this file so the
target DLL path and the header files describing its structs stay consistent
across the whole project. Defaults point at the AviUtl exedit plugin and its
filter header:

    uv run main.py tools.get_func_address
    uv run main.py inspect/luminous/find_addr.py
    uv run main.py tools.get_func_address --dll-path data/other.auf --header data/other.h

A target may be given either as a dotted module path (resolved via regular
Python import, e.g. "tools.get_func_address") or as a file path (resolved by
loading that file directly, e.g. "inspect/luminous/find_addr.py"). File-path
loading is what scripts under inspect/ should use, since naming a package
"inspect" would shadow the standard library module of the same name.

Target scripts must expose:

    def run(dll_path: str, headers: list[str], argv: list[str]) -> None
"""

import argparse
import importlib
import importlib.util
import sys
from pathlib import Path

DEFAULT_DLL_PATH = "data/exedit.auf"
DEFAULT_HEADERS = ["data/filter.h"]


def _looks_like_path(target: str) -> bool:
    return target.endswith(".py") or "/" in target or "\\" in target


def _load_by_path(target: str):
    path = Path(target)
    if not path.exists() and path.suffix != ".py":
        path = path.with_suffix(".py")
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_target(target: str):
    if _looks_like_path(target):
        return _load_by_path(target)
    return importlib.import_module(target)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help='dotted module path ("tools.get_func_address") or script file path ("inspect/luminous/find_addr.py")')
    parser.add_argument("--dll-path", default=DEFAULT_DLL_PATH, help="path to the target DLL/AUF (default: %(default)s)")
    parser.add_argument("--header", dest="headers", action="append", help="header file to use; repeatable (default: data/filter.h)")
    args, extra = parser.parse_known_args()

    headers = args.headers or list(DEFAULT_HEADERS)
    module = _load_target(args.target)

    if not hasattr(module, "run"):
        print(f"error: {args.target} does not define a run(dll_path, headers, argv) function", file=sys.stderr)
        sys.exit(1)

    module.run(dll_path=args.dll_path, headers=headers, argv=extra)


if __name__ == "__main__":
    main()
