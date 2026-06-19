"""
V1 end-to-end runner — feeds sample code through the full review pipeline:
security + quality + performance + documentation → supervisor → report
"""

from graph.review_graph import review_graph
from models.state import ReviewState

# Sample code designed to trigger issues in ALL 4 agents
SAMPLE_CODE = '''
import pickle
import os
import time
import requests

API_KEY = "sk-abc123supersecret"
DB_PASSWORD = "hunter2"

class UserManager:
    def __init__(self, db):
        self.db = db

    def get_user(self, user_id):
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return self.db.execute(query)

    def get_all_users_with_orders(self):
        users = self.db.execute("SELECT * FROM users")
        result = []
        for u in users:
            orders = self.db.execute(f"SELECT * FROM orders WHERE user_id = {u.id}")
            result += [orders]
        return result

    async def fetch_profiles(self, user_ids):
        profiles = []
        for uid in user_ids:
            # Get profile from API
            resp = requests.get(f"https://api.example.com/users/{uid}")
            profiles.append(resp.json())
            time.sleep(1)
        return profiles

    def process_data(self, raw_bytes, expression, cmd):
        data = pickle.loads(raw_bytes)
        result = eval(expression)
        os.system(cmd)
        return data, result

def x(a, b, c, d, e, f, g):
    return a + b + c
'''


def main():
    print("\n⏳ Running full code review pipeline...\n")

    initial_state = ReviewState(code=SAMPLE_CODE, filename="user_manager.py")
    result = review_graph.invoke(initial_state)

    # Print individual agent summaries
    print("=" * 60)
    print("AGENT SUMMARIES")
    print("=" * 60)

    for name, key in [
        ("🔒 Security", "security_output"),
        ("📐 Quality", "quality_output"),
        ("⚡ Performance", "performance_output"),
        ("📝 Documentation", "documentation_output"),
    ]:
        output = result[key]
        print(f"\n{name}: {output.summary}")
        for issue in output.issues:
            # Evidence trail: tool source, stable rule id, and cross-tool corroboration.
            rule = f" {issue.rule_id}" if issue.rule_id else ""
            tag = f"[{issue.tier}:{issue.source}{rule}]"
            corro = f"  ✓ also found by {', '.join(issue.corroborated_by)}" if issue.corroborated_by else ""
            print(f"  [{issue.severity.value.upper():8}] Line {str(issue.line_number or '?'):>3} {tag} — {issue.category}: {issue.description}{corro}")
            # For LLM ('suggested') findings, show the exact line it cited so a human can verify.
            if issue.evidence:
                print(f"             ↳ cites: {issue.evidence.strip()}")

    # Print final supervisor report
    print("\n" + "=" * 60)
    print("SUPERVISOR FINAL REPORT")
    print("=" * 60)
    print(result["final_report"])


if __name__ == "__main__":
    main()
