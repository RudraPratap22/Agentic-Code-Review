"""
CLI entry point: review a local folder OR a GitHub URL.

Usage:
    python main.py <path>                 # review a local folder (defaults to ".")
    python main.py <github-repo-url>      # clone, review, clean up
    python main.py <github-pr-url>        # review only the lines changed in a PR
    python main.py <github-pr-url> --post # ...and post the findings as inline PR comments
"""

import sys
from pipeline import review_repo, review_github
from github_pr import review_pr, post_pr_review


def _is_url(arg: str) -> bool:
    return arg.startswith(("http://", "https://", "git@")) or arg.endswith(".git")


def main():
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    target = args[0] if args else "."
    print(f"\n⏳ Reviewing: {target}\n")

    if _is_url(target) and "/pull/" in target:
        if "--post" in flags:
            print(post_pr_review(target))   # write inline comments to the PR
        else:
            print(review_pr(target))        # just print the report (read-only)
    elif _is_url(target):
        print(review_github(target))        # a repo URL → clone + review
    else:
        print(review_repo(target))          # a local folder


if __name__ == "__main__":
    main()
