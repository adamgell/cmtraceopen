from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = SKILL_ROOT / "scripts" / "review_state.py"
SKILL_PATH = SKILL_ROOT / "SKILL.md"
LICENSE_PATH = SKILL_ROOT / "LICENSE.txt"
UPSTREAM_COMMIT = "72ef3d3322ee0ac8db02cf324c2030f13d3bb68d"
UPSTREAM_SCRIPT_SHA256 = (
    "71703606bcf171b9e7f8035466d41806622be7a6f04b8157ef86f16fb3ecdfad"
)
DOWNSTREAM_SCRIPT_COMMITS = (
    "925131c0da511e89eddbdb1e6f14f65ed4861a3f",
    "a76c272d62a1d527f59c542608d10c405a210e2f",
)
UPSTREAM_SOURCE = (
    "https://github.com/jorgeasaurus/agent-skills/tree/"
    f"{UPSTREAM_COMMIT}/gh-copilot-review-loop"
)
UPSTREAM_AUTHOR = "Jorge Suarez (jorgeasaurus)"
LICENSE_IDENTIFIER = "MIT, as declared by the upstream repository README. The"
LICENSE_IDENTIFIER_PARAGRAPH = (
    "License identifier: MIT, as declared by the upstream repository README. The\n"
    "upstream repository did not publish a root license file at this commit, so the\n"
    "standard MIT license text and source attribution are recorded locally."
)
UPSTREAM_LICENSE_DECLARATION = (
    "The upstream repository declares the work under the MIT License in its README."
)
REPOSITORY_LEVEL_CHANGES = (
    "SKILL.md uses a repository-relative invocation and an explicit --repo/--pr "
    "example; the reviewer-request command is formatted on one line; downstream "
    "regression tests cover the maintained script."
)
SCRIPT_CHANGES = (
    "base-repository URL parsing and pending-review filtering, including prefixed "
    "enterprise pull-request URLs."
)
MIT_LICENSE_SECTIONS = (
    "MIT License\n",
    "Permission is hereby granted, free of charge, to any person obtaining a copy",
    'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND',
)
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

    def test_enterprise_url_prefix_preserves_base_repository(self) -> None:
        response = {
            "number": 42,
            "url": (
                "https://enterprise.example/github/"
                "base-owner/base-repo/pull/42"
            ),
        }

        with patch.object(review_state, "run_json", return_value=response):
            try:
                current = review_state.current_pr()
            except SystemExit as error:
                self.fail(f"valid enterprise pull request URL rejected: {error}")

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


class ProvenanceTests(unittest.TestCase):
    def test_modified_script_provenance_is_explicit(self) -> None:
        script_digest = hashlib.sha256(SCRIPT_PATH.read_bytes()).hexdigest()
        skill_text = SKILL_PATH.read_text(encoding="utf-8")
        license_text = LICENSE_PATH.read_text(encoding="utf-8")

        license_marker = "Third-party attribution for gh-copilot-review-loop\n"
        skill_marker = "## Provenance\n"
        self.assertIn(license_marker, license_text)
        self.assertIn(skill_marker, skill_text)
        _, _, provenance = license_text.partition(license_marker)
        labeled_fields = dict(
            line.split(": ", 1)
            for line in provenance.splitlines()
            if ": " in line
        )
        _, _, skill_provenance = skill_text.partition(skill_marker)

        self.assertNotEqual(script_digest, UPSTREAM_SCRIPT_SHA256)
        self.assertEqual(labeled_fields["Source"], UPSTREAM_SOURCE)
        self.assertEqual(labeled_fields["Upstream author"], UPSTREAM_AUTHOR)
        self.assertEqual(labeled_fields["Upstream commit"], UPSTREAM_COMMIT)
        self.assertEqual(
            labeled_fields["Upstream script path"], "scripts/review_state.py"
        )
        self.assertEqual(
            labeled_fields["Upstream script SHA-256 at pinned commit"],
            UPSTREAM_SCRIPT_SHA256,
        )
        self.assertEqual(
            labeled_fields["Downstream script commits"],
            ", ".join(DOWNSTREAM_SCRIPT_COMMITS),
        )
        self.assertEqual(
            labeled_fields["Repository-level changes"],
            REPOSITORY_LEVEL_CHANGES,
        )
        self.assertEqual(labeled_fields["Script changes"], SCRIPT_CHANGES)
        self.assertEqual(labeled_fields["License identifier"], LICENSE_IDENTIFIER)
        self.assertIn(UPSTREAM_LICENSE_DECLARATION, skill_provenance)
        self.assertIn(LICENSE_IDENTIFIER_PARAGRAPH, license_text)
        for section in MIT_LICENSE_SECTIONS:
            self.assertIn(section, license_text)
        self.assertEqual(
            labeled_fields["Derivative status"],
            "the maintained scripts/review_state.py is not byte-identical to the pinned upstream script",
        )
        self.assertIn(UPSTREAM_COMMIT, skill_provenance)
        for commit in DOWNSTREAM_SCRIPT_COMMITS:
            self.assertIn(commit, skill_provenance)
        self.assertIn("modified downstream derivative", skill_provenance)
        self.assertIn("not byte-identical", skill_provenance)


if __name__ == "__main__":
    unittest.main()
