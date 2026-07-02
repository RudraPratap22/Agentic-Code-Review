"""
Per-file review graph.
Architecture: START → [security, quality, performance, documentation] (parallel) → END

This graph reviews ONE file. All four nodes share identical wiring (START → self → END),
so we add them in a loop. The repo-level pieces — the architecture agent (whole repo)
and the supervisor (aggregates across files) — live in pipeline.py, which maps this
graph over every file and reduces the results into one report.
"""

from langgraph.graph import StateGraph, START, END
from models.state import ReviewState
from agents.security_agent import run_security_agent
from agents.quality_agent import run_quality_agent
from agents.performance_agent import run_performance_agent
from agents.documentation_agent import run_documentation_agent


def build_file_graph():
    graph = StateGraph(ReviewState)
    for name, fn in [
        ("security_agent", run_security_agent),
        ("quality_agent", run_quality_agent),
        ("performance_agent", run_performance_agent),
        ("documentation_agent", run_documentation_agent),
    ]:
        graph.add_node(name, fn)
        graph.add_edge(START, name)   # fan-out: all 4 start together
        graph.add_edge(name, END)     # fan-in: graph ends when all 4 finish
    return graph.compile()


file_review_graph = build_file_graph()
