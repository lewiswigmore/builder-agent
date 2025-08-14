import argparse
from typing import Optional, Sequence


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="yourcli")
    parser.add_argument("--greet", metavar="NAME", help="Greet the specified NAME")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    name = args.greet if getattr(args, "greet", None) else "world"
    print(f"Hello, {name}!")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
