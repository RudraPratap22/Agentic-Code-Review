"""Quality thresholds shared by the Python AST visitor and the JS/TS tree-sitter visitor,
so the same limits apply to every language we review.

Lives in its own module so treesitter_js.py can use them without importing quality_agent
(which imports treesitter_js).
"""

MAX_FUNCTION_LINES = 50
MAX_FUNCTION_ARGS = 5
