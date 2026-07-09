"""Temporary fixture to verify the PR-review GitHub Action posts inline comments.

Not imported anywhere — delete once the Action is verified.
"""

import os


def run_command(cmd):
    os.system(cmd)
