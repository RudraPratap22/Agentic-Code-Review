"""
Shared state definition for the Agentic Code Review system.
This is the single object that flows through all agents in the LangGraph.
"""

from typing import Optional
from pydantic import BaseModel, Field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Issue(BaseModel):
    """A single issue found by any agent."""
    agent: str = Field(description="Which agent found this issue")
    severity: Severity
    category: str = Field(description="e.g. 'hardcoded-secret', 'missing-docstring'")
    description: str
    line_number: Optional[int] = None
    suggestion: str = Field(description="How to fix this issue")

    # ── Trust + evidence (the anti-circularity backbone) ──
    tier: str = Field(
        default="verified",
        description="'verified' = found by a deterministic tool/AST (cannot hallucinate); "
                    "'suggested' = found by the LLM (lower trust, must cite evidence)",
    )
    source: str = Field(
        default="custom-ast",
        description="Which tool produced this finding, e.g. 'custom-ast', 'bandit', 'llm'",
    )
    rule_id: Optional[str] = Field(
        default=None,
        description="Stable rule code from the tool, e.g. 'B301' — citable, verifiable evidence",
    )
    evidence: Optional[str] = Field(
        default=None,
        description="The exact line/snippet this finding points to. Required for LLM ('suggested') findings.",
    )
    corroborated_by: list[str] = Field(
        default_factory=list,
        description="Other sources that independently flagged the same issue, e.g. ['bandit']",
    )
    filename: Optional[str] = Field(
        default=None,
        description="Which file this issue is in (set during repo review).",
    )


class AgentOutput(BaseModel):
    """Output from a single agent's review."""
    agent_name: str
    issues: list[Issue] = Field(default_factory=list)
    summary: str = Field(default="", description="Brief summary of findings")


class ReviewState(BaseModel):
    """
    The shared state that flows through the entire LangGraph.
    Each agent reads `code` and writes to its own output field.
    The supervisor reads all outputs and writes the final report.
    """
    # Input
    code: str = Field(description="The source code to review")
    filename: str = Field(default="untitled.py", description="Name of the file being reviewed")
    repo_path: Optional[str] = Field(
        default=None,
        description="Path to the repo root, for whole-project (architecture) review. "
                    "If None, the architecture agent skips.",
    )

    # Agent outputs — each agent writes to its own field
    security_output: Optional[AgentOutput] = None
    quality_output: Optional[AgentOutput] = None
    performance_output: Optional[AgentOutput] = None
    documentation_output: Optional[AgentOutput] = None
    architecture_output: Optional[AgentOutput] = None

    # Supervisor output
    final_report: Optional[str] = None
