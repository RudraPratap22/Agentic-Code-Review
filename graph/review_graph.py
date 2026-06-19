"""
LangGraph graph definition.
Architecture: START → [security, quality, performance, documentation] (parallel) → supervisor → END
"""

from langgraph.graph import StateGraph, START, END
from models.state import ReviewState
from agents.security_agent import run_security_agent
from agents.quality_agent import run_quality_agent
from agents.performance_agent import run_performance_agent
from agents.documentation_agent import run_documentation_agent
from agents.supervisor_agent import run_supervisor_agent


def build_graph():
    graph = StateGraph(ReviewState)

    # Add all 5 agent nodes
    graph.add_node("security_agent", run_security_agent)
    graph.add_node("quality_agent", run_quality_agent)
    graph.add_node("performance_agent", run_performance_agent)
    graph.add_node("documentation_agent", run_documentation_agent)
    graph.add_node("supervisor_agent", run_supervisor_agent)

    # Fan-out: START → all 4 agents in parallel
    graph.add_edge(START, "security_agent")
    graph.add_edge(START, "quality_agent")
    graph.add_edge(START, "performance_agent")
    graph.add_edge(START, "documentation_agent")

    # Fan-in: all 4 agents → supervisor
    graph.add_edge("security_agent", "supervisor_agent")
    graph.add_edge("quality_agent", "supervisor_agent")
    graph.add_edge("performance_agent", "supervisor_agent")
    graph.add_edge("documentation_agent", "supervisor_agent")

    # Supervisor → END
    graph.add_edge("supervisor_agent", END)

    return graph.compile()


review_graph = build_graph()
