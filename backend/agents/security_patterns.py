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


def looks_like_secret_value(value: str) -> bool:
    """True if a string literal plausibly IS a secret, rather than prose about secrets.

    A name match alone is not enough: `_SECRET_FIX = "Load secrets from a vault, never a
    source literal."` matches SECRET_NAME_RE but is obviously advice text. A real credential
    is a compact opaque token (`sk-live-abc123`) — whitespace is the giveaway, and empty or
    very short values carry no secret.

    Whitespace is the discriminator — deliberately not a minimum length, which would create
    false negatives on short-but-real credentials.

    Trade-off: a hardcoded passphrase containing spaces would be missed. That is far rarer
    than message/prompt constants whose names happen to contain 'secret' or 'token'.
    """
    stripped = value.strip()
    if not stripped:
        return False                    # `API_KEY = ""` holds no secret
    return not any(char.isspace() for char in stripped)

# A real SQL-injection string has actual query STRUCTURE (SELECT…FROM, INSERT INTO,
# UPDATE…SET, DELETE FROM) with an interpolated value ({}) inside it — not merely a SQL
# keyword appearing in prose. Callers first rebuild the string as a template where every
# interpolation (Python f-string `{x}`, JS `${x}`) is replaced by a literal `{}`.
SQL_INJECTION_RE = re.compile(
    r"(SELECT\b.+?\bFROM\b|INSERT\s+INTO\b|UPDATE\b.+?\bSET\b|DELETE\s+FROM\b|"
    r"DROP\s+(TABLE|DATABASE)\b).*?\{\}",
    re.IGNORECASE | re.DOTALL,
)
