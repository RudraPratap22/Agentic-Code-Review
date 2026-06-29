"""
CLI entry point: review a local folder OR a GitHub URL.

Usage:
    python main.py <path>                 # review a local folder (defaults to ".")
    python main.py <github-repo-url>      # clone, review, clean up
    python main.py <github-pr-url>        # review only the lines changed in a PR
"""

import sys
from pipeline import review_repo, review_github
from github_pr import review_pr


def _is_url(arg: str) -> bool:
    return arg.startswith(("http://", "https://", "git@")) or arg.endswith(".git")


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"\n⏳ Reviewing: {target}\n")
    if _is_url(target) and "/pull/" in target:
        report = review_pr(target)          # a pull request → review only changed lines
    elif _is_url(target):
        report = review_github(target)      # a repo URL → clone + review
    else:
        report = review_repo(target)        # a local folder
    print(report)


if __name__ == "__main__":
    main()
