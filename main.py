"""
CLI entry point: review a local folder OR a GitHub URL.

Usage:
    python main.py <path>                 # review a local folder (defaults to ".")
    python main.py <github-url>           # clone, review, clean up
"""

import sys
from pipeline import review_repo, review_github


def _is_url(arg: str) -> bool:
    return arg.startswith(("http://", "https://", "git@")) or arg.endswith(".git")


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"\n⏳ Reviewing: {target}\n")
    report = review_github(target) if _is_url(target) else review_repo(target)
    print(report)


if __name__ == "__main__":
    main()
