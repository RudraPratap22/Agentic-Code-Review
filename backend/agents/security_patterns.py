"""Deterministic security patterns shared by the Python AST visitor and the JS/TS
tree-sitter visitor, so both languages detect the same underlying bugs the same way.

Lives in its own module to keep security_agent.py and treesitter_js.py free of a
circular import (security_agent imports the JS visitor).
"""

import re

# Variable names that almost certainly hold a secret.
SECRET_NAME_RE = re.compile(
    r"(api[_-]?key|secret|password|token|auth|access[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)

# A real SQL-injection string has actual query STRUCTURE (SELECT…FROM, INSERT INTO,
# UPDATE…SET, DELETE FROM) with an interpolated value ({}) inside it — not merely a SQL
# keyword appearing in prose. Callers first rebuild the string as a template where every
# interpolation (Python f-string `{x}`, JS `${x}`) is replaced by a literal `{}`.
SQL_INJECTION_RE = re.compile(
    r"(SELECT\b.+?\bFROM\b|INSERT\s+INTO\b|UPDATE\b.+?\bSET\b|DELETE\s+FROM\b|"
    r"DROP\s+(TABLE|DATABASE)\b).*?\{\}",
    re.IGNORECASE | re.DOTALL,
)
