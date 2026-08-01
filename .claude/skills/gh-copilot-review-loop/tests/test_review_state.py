from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "review_state.py"
SPEC = importlib.util.spec_from_file_location("review_state", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
review_state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review_state)


def graphql_response(reviews: list[dict[str, object]]) -> dict[str, object]:
    return {
        "data": {
            "repository": {
                "pullRequest": {
                    "number": 42,
                    "url": "https://github.com/base-owner/base-repo/pull/42",
                    "headRefOid": "a" * 40,
                    "isDraft": False,
                    "reviewDecision": None,
                    "reviews": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": reviews,
                    },
                    "reviewThreads": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": [],
                    },
                }
            }
        }
    }


class CurrentPullRequestTests(unittest.TestCase):
    def test_fork_pull_request_uses_repository_from_base_url(self) -> None:
        response = {
            "number": 42,
            "url": "https://github.com/base-owner/base-repo/pull/42",
            "headRepositoryOwner": {"login": "fork-owner"},
            "headRepository": {"name": "fork-repo"},
        }

        with patch.object(review_state, "run_json", return_value=response):
            current = review_state.current_pr()

        self.assertEqual(current, ("base-owner", "base-repo", 42))


class CopilotReviewSummaryTests(unittest.TestCase):
    def test_pending_copilot_review_does_not_count_as_submitted(self) -> None:
        pending = {
            "id": "pending",
            "state": "PENDING",
            "body": "",
            "submittedAt": None,
            "author": {"login": "copilot-pull-request-reviewer"},
            "commit": None,
        }

        with patch.object(
            review_state,
            "run_json",
            return_value=graphql_response([pending]),
        ):
            summary = review_state.fetch("base-owner", "base-repo", 42)["summary"]

        self.assertEqual(summary["copilot_review_count"], 0)
        self.assertIsNone(summary["latest_copilot_review"])

    def test_latest_copilot_review_ignores_pending_review(self) -> None:
        submitted = {
            "id": "submitted",
            "state": "COMMENTED",
            "body": "Review complete",
            "submittedAt": "2026-08-01T12:00:00Z",
            "author": {"login": "copilot-pull-request-reviewer"},
            "commit": {"oid": "b" * 40},
        }
        pending = {
            "id": "pending",
            "state": "PENDING",
            "body": "",
            "submittedAt": None,
            "author": {"login": "copilot-pull-request-reviewer"},
            "commit": None,
        }

        with patch.object(
            review_state,
            "run_json",
            return_value=graphql_response([submitted, pending]),
        ):
            result = review_state.fetch("base-owner", "base-repo", 42)

        self.assertEqual(result["summary"]["review_count"], 2)
        self.assertEqual(result["summary"]["copilot_review_count"], 1)
        self.assertEqual(
            result["summary"]["latest_copilot_review"],
            submitted,
        )


if __name__ == "__main__":
    unittest.main()
