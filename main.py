"""
CLI entry point: review a real folder of Python files.

Usage:
    python main.py <path-to-repo>     # defaults to "." (this project) if omitted
"""

import sys
from pipeline import review_repo


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"\n⏳ Reviewing repo at: {path}\n")
    print(review_repo(path))


if __name__ == "__main__":
    main()
