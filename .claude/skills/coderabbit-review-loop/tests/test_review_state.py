from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SKILL_ROOT.parents[2]
SCRIPT_PATH = SKILL_ROOT / "scripts" / "review_state.py"
SKILL_PATH = SKILL_ROOT / "SKILL.md"
LICENSE_PATH = SKILL_ROOT / "LICENSE.txt"
UPSTREAM_COMMIT = "72ef3d3322ee0ac8db02cf324c2030f13d3bb68d"
ORIGINAL_IMPORT_COMMIT = "6fb2a06e7cec174fe1b46f1930175ddd1f1cf5b6"
UPSTREAM_SCRIPT_SHA256 = (
    "71703606bcf171b9e7f8035466d41806622be7a6f04b8157ef86f16fb3ecdfad"
)
DOWNSTREAM_SCRIPT_COMMITS = (
    "925131c0da511e89eddbdb1e6f14f65ed4861a3f",
    "a76c272d62a1d527f59c542608d10c405a210e2f",
    "608e6659194ef5f6badeb0bb4aafb8ffad40f92b",
    "4c14b704f22266456380e07784fbd3a58b87c609",
    "eae1fa8ae87c0f65fbbba8f319451823408bcebb",
    "3afa2cf66950827fcbfe161334482698b6db0929",
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
    "example; on 2026-08-08 the skill was retargeted from GitHub Copilot to "
    "CodeRabbit with an approval-at-head clean-cycle gate and an explicit "
    "no-merge terminus; downstream regression tests cover the maintained script."
)
SCRIPT_CHANGES = (
    "base-repository URL parsing and pending-review filtering, including prefixed "
    "enterprise pull-request URLs; reviewer targeting retargeted to coderabbitai "
    "with approval-at-head summary fields; bounded GitHub CLI subprocesses, "
    "fail-closed pagination cursor progress, raw string GraphQL variables, and "
    "null-safe exact CodeRabbit bot-login aliases."
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


def graphql_response(
    reviews: list[dict[str, object]],
    *,
    head: str = "a" * 40,
    base: str = "b" * 40,
    threads: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "data": {
            "repository": {
                "pullRequest": {
                    "number": 42,
                    "url": "https://github.com/base-owner/base-repo/pull/42",
                    "headRefOid": head,
                    "baseRefOid": base,
                    "isDraft": False,
                    "reviewDecision": None,
                    "reviews": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": reviews,
                    },
                    "reviewThreads": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": threads if threads is not None else [],
                    },
                }
            }
        }
    }


def pull_request_page(**connections: object) -> dict[str, object]:
    return {
        "data": {
            "repository": {
                "pullRequest": {
                    "number": 42,
                    "url": "https://github.com/base-owner/base-repo/pull/42",
                    "headRefOid": "a" * 40,
                    "baseRefOid": "b" * 40,
                    "isDraft": False,
                    "reviewDecision": None,
                    **connections,
                },
            },
        },
    }


def comment_page(*comments: dict[str, object]) -> dict[str, object]:
    return {
        "data": {
            "node": {
                "comments": {
                    "pageInfo": {
                        "hasNextPage": False,
                        "endCursor": comments[-1]["id"] if comments else None,
                    },
                    "nodes": list(comments),
                },
            },
        },
    }


def review_thread(
    *comments: dict[str, object],
    thread_id: str = "thread-1",
) -> dict[str, object]:
    return {
        "id": thread_id,
        "isResolved": False,
        "isOutdated": False,
        "path": "src/one.ts",
        "line": 1,
        "resolvedBy": None,
        "comments": {
            "pageInfo": {"hasNextPage": False, "endCursor": None},
            "nodes": list(comments),
        },
    }


class ReviewTransportTests(unittest.TestCase):
    def test_run_json_times_out_with_a_clear_failure(self) -> None:
        command = ["gh", "api", "graphql"]
        with patch.object(
            review_state.subprocess,
            "run",
            side_effect=review_state.subprocess.TimeoutExpired(
                command,
                review_state.SUBPROCESS_TIMEOUT_SECONDS,
            ),
        ) as run, self.assertRaisesRegex(
            SystemExit,
            "timed out",
        ):
            review_state.run_json(command)

        self.assertEqual(
            review_state.SUBPROCESS_TIMEOUT_SECONDS,
            run.call_args.kwargs["timeout"],
        )

    def test_run_json_rejects_empty_or_malformed_output(self) -> None:
        command = ["gh", "api", "graphql"]
        for stdout in ("", "{"):
            with self.subTest(stdout=stdout), patch.object(
                review_state.subprocess,
                "run",
                return_value=review_state.subprocess.CompletedProcess(
                    command,
                    0,
                    stdout,
                    "",
                ),
            ), self.assertRaisesRegex(SystemExit, "invalid JSON"):
                review_state.run_json(command)

        with patch.object(
            review_state.subprocess,
            "run",
            return_value=review_state.subprocess.CompletedProcess(
                command,
                0,
                "[]",
                "",
            ),
        ), self.assertRaisesRegex(SystemExit, "JSON object"):
            review_state.run_json(command)

    def test_run_json_reports_command_failure(self) -> None:
        command = ["gh", "api", "graphql"]
        for stderr, message in (
            ("gh: authentication required", "authentication required"),
            ("", "command failed"),
        ):
            with self.subTest(stderr=stderr), patch.object(
                review_state.subprocess,
                "run",
                return_value=review_state.subprocess.CompletedProcess(
                    command,
                    1,
                    "",
                    stderr,
                ),
            ), self.assertRaisesRegex(SystemExit, message):
                review_state.run_json(command)


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


class CodeRabbitReviewSummaryTests(unittest.TestCase):
    def test_pending_coderabbit_review_does_not_count_as_submitted(self) -> None:
        pending = {
            "id": "pending",
            "state": "PENDING",
            "body": "",
            "submittedAt": None,
            "author": {"login": "coderabbitai[bot]"},
            "commit": None,
        }

        with patch.object(
            review_state,
            "run_json",
            return_value=graphql_response([pending]),
        ):
            summary = review_state.fetch("base-owner", "base-repo", 42)["summary"]

        self.assertEqual(summary["coderabbit_review_count"], 0)
        self.assertIsNone(summary["latest_coderabbit_review"])
        self.assertIsNone(summary["latest_coderabbit_review_state"])
        self.assertFalse(summary["approved_at_head"])

    def test_latest_coderabbit_review_ignores_pending_review(self) -> None:
        submitted = {
            "id": "submitted",
            "state": "CHANGES_REQUESTED",
            "body": "Review complete",
            "submittedAt": "2026-08-08T12:00:00Z",
            "author": {"login": "coderabbitai[bot]"},
            "commit": {"oid": "b" * 40},
        }
        pending = {
            "id": "pending",
            "state": "PENDING",
            "body": "",
            "submittedAt": None,
            "author": {"login": "coderabbitai[bot]"},
            "commit": None,
        }

        with patch.object(
            review_state,
            "run_json",
            return_value=graphql_response([submitted, pending]),
        ):
            result = review_state.fetch("base-owner", "base-repo", 42)

        self.assertEqual(result["summary"]["review_count"], 2)
        self.assertEqual(result["summary"]["coderabbit_review_count"], 1)
        self.assertEqual(
            result["summary"]["latest_coderabbit_review"],
            submitted,
        )
        self.assertEqual(
            result["summary"]["latest_coderabbit_review_state"],
            "CHANGES_REQUESTED",
        )
        self.assertFalse(result["summary"]["approved_at_head"])

    def test_approved_at_head_requires_head_anchor(self) -> None:
        stale_approval = {
            "id": "stale",
            "state": "APPROVED",
            "body": "lgtm",
            "submittedAt": "2026-08-08T12:00:00Z",
            "author": {"login": "coderabbitai[bot]"},
            "commit": {"oid": "b" * 40},
        }

        with patch.object(
            review_state,
            "run_json",
            return_value=graphql_response([stale_approval]),
        ):
            summary = review_state.fetch("base-owner", "base-repo", 42)["summary"]

        self.assertEqual(summary["latest_coderabbit_review_state"], "APPROVED")
        self.assertFalse(summary["approved_at_head"])

    def test_approved_at_head_true_when_anchored_to_head(self) -> None:
        head_approval = {
            "id": "head",
            "state": "APPROVED",
            "body": "lgtm",
            "submittedAt": "2026-08-08T13:00:00Z",
            "author": {"login": "coderabbitai[bot]"},
            "commit": {"oid": "a" * 40},
        }

        with patch.object(
            review_state,
            "run_json",
            return_value=graphql_response([head_approval]),
        ):
            summary = review_state.fetch("base-owner", "base-repo", 42)["summary"]

        self.assertTrue(summary["approved_at_head"])

    def test_spoofed_coderabbit_login_cannot_override_real_bot_review(self) -> None:
        real_review = {
            "id": "real",
            "state": "CHANGES_REQUESTED",
            "body": "changes required",
            "submittedAt": "2026-08-08T12:00:00Z",
            "author": {"login": "coderabbitai[bot]"},
            "commit": {"oid": "a" * 40},
        }
        spoofed_approval = {
            "id": "spoofed",
            "state": "APPROVED",
            "body": "lgtm",
            "submittedAt": "2026-08-08T13:00:00Z",
            "author": {"login": "coderabbit-helper"},
            "commit": {"oid": "a" * 40},
        }

        with patch.object(
            review_state,
            "run_json",
            return_value=graphql_response([real_review, spoofed_approval]),
        ):
            summary = review_state.fetch("base-owner", "base-repo", 42)["summary"]

        self.assertEqual(1, summary["coderabbit_review_count"])
        self.assertEqual(real_review, summary["latest_coderabbit_review"])
        self.assertEqual("CHANGES_REQUESTED", summary["latest_coderabbit_review_state"])
        self.assertFalse(summary["approved_at_head"])

    def test_coderabbit_identity_accepts_exact_github_bot_logins(self) -> None:
        for login in (
            "coderabbitai",
            "coderabbitai[bot]",
            "CodeRabbitAI[Bot]",
        ):
            with self.subTest(login=login):
                self.assertTrue(review_state.is_coderabbit({"login": login}))
        for author in (
            None,
            {},
            {"login": None},
            {"login": "coderabbit-helper"},
            {"login": "coderabbit[bot]"},
            {"login": "adamgell"},
        ):
            with self.subTest(author=author):
                self.assertFalse(review_state.is_coderabbit(author))

    def test_bare_graphql_login_counts_review_and_thread(self) -> None:
        review = {
            "id": "review",
            "state": "CHANGES_REQUESTED",
            "body": "changes required",
            "submittedAt": "2026-08-15T01:37:48Z",
            "author": {"login": "coderabbitai"},
            "commit": {"oid": "a" * 40},
        }
        thread = {
            "id": "thread",
            "isResolved": False,
            "isOutdated": False,
            "path": "src/example.py",
            "line": 1,
            "resolvedBy": None,
            "comments": {
                "pageInfo": {
                    "hasNextPage": False,
                    "endCursor": None,
                },
                "nodes": [
                    {
                        "id": "comment",
                        "body": "finding",
                        "createdAt": "2026-08-15T01:37:45Z",
                        "author": {"login": "coderabbitai"},
                    }
                ]
            },
        }

        with patch.object(
            review_state,
            "run_json",
            return_value=graphql_response([review], threads=[thread]),
        ):
            summary = review_state.fetch("base-owner", "base-repo", 42)["summary"]

        self.assertEqual(1, summary["coderabbit_review_count"])
        self.assertEqual(1, summary["unresolved_coderabbit_thread_count"])

    def test_asymmetric_connections_and_nested_comments_converge(self) -> None:
        review = {
            "id": "review-1",
            "state": "CHANGES_REQUESTED",
            "body": "changes",
            "submittedAt": "2026-08-08T12:00:00Z",
            "author": {"login": "coderabbitai[bot]"},
            "commit": {"oid": "a" * 40},
        }
        first_comment = {
            "id": "comment-1",
            "body": "first",
            "createdAt": "2026-08-08T12:00:00Z",
            "author": {"login": "human"},
        }
        coderabbit_comment = {
            "id": "comment-2",
            "body": "actionable",
            "createdAt": "2026-08-08T12:01:00Z",
            "author": {"login": "coderabbitai[bot]"},
        }
        first_thread = review_thread(first_comment)
        first_thread["comments"] = {
            "pageInfo": {"hasNextPage": True, "endCursor": "comment-1"},
            "nodes": [first_comment],
        }
        second_thread = {
            **review_thread(thread_id="thread-2"),
            "isResolved": True,
            "path": "src/two.ts",
            "line": 2,
            "resolvedBy": {"login": "human"},
        }
        snapshot_pages = [
            pull_request_page(
                reviews={
                    "pageInfo": {"hasNextPage": False, "endCursor": "review-1"},
                    "nodes": [review],
                },
                reviewThreads={
                    "pageInfo": {"hasNextPage": True, "endCursor": "thread-1"},
                    "nodes": [first_thread],
                },
            ),
            pull_request_page(
                reviewThreads={
                    "pageInfo": {"hasNextPage": False, "endCursor": "thread-2"},
                    "nodes": [first_thread, second_thread],
                },
            ),
            comment_page(coderabbit_comment),
        ]

        with patch.object(
            review_state,
            "run_json",
            side_effect=[*snapshot_pages, *snapshot_pages],
        ) as run_json:
            result = review_state.fetch("base-owner", "base-repo", 42)

        self.assertEqual(1, result["summary"]["review_count"])
        self.assertEqual(1, result["summary"]["unresolved_thread_count"])
        self.assertEqual(1, result["summary"]["unresolved_coderabbit_thread_count"])
        for offset in (0, 3):
            second_command = run_json.call_args_list[offset + 1].args[0]
            self.assertIn("skipReviews=true", second_command)
            self.assertEqual(
                "-f",
                second_command[
                    second_command.index("threads=thread-1") - 1
                ],
            )
            self.assertIn("threads=thread-1", second_command)
            self.assertIn("skipThreads=false", second_command)
            comment_command = run_json.call_args_list[offset + 2].args[0]
            self.assertIn("id=thread-1", comment_command)
            self.assertEqual(
                "-f",
                comment_command[
                    comment_command.index("id=thread-1") - 1
                ],
            )
            self.assertEqual(
                "-f",
                comment_command[
                    comment_command.index("comments=comment-1") - 1
                ],
            )
            self.assertIn("comments=comment-1", comment_command)
        self.assertEqual(6, run_json.call_count)

    def test_review_pagination_rejects_missing_cursor(self) -> None:
        response = pull_request_page(
            reviews={
                "pageInfo": {"hasNextPage": True, "endCursor": None},
                "nodes": [],
            },
            reviewThreads={
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "nodes": [],
            },
        )

        with patch.object(
            review_state,
            "run_json",
            return_value=response,
        ), self.assertRaisesRegex(SystemExit, "reviews.*cursor"):
            review_state._fetch_complete_snapshot(
                "base-owner",
                "base-repo",
                42,
            )

    def test_review_pagination_rejects_cursor_cycle(self) -> None:
        first = pull_request_page(
            reviews={
                "pageInfo": {"hasNextPage": True, "endCursor": "review-a"},
                "nodes": [],
            },
            reviewThreads={
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "nodes": [],
            },
        )
        second = pull_request_page(
            reviews={
                "pageInfo": {"hasNextPage": True, "endCursor": "review-b"},
                "nodes": [],
            },
        )
        cycle = pull_request_page(
            reviews={
                "pageInfo": {"hasNextPage": True, "endCursor": "review-a"},
                "nodes": [],
            },
        )

        with patch.object(
            review_state,
            "run_json",
            side_effect=[first, second, cycle],
        ), self.assertRaisesRegex(SystemExit, "reviews.*cursor"):
            review_state._fetch_complete_snapshot(
                "base-owner",
                "base-repo",
                42,
            )


    def test_thread_pagination_rejects_cursor_cycle(self) -> None:
        first = pull_request_page(
            reviews={
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "nodes": [],
            },
            reviewThreads={
                "pageInfo": {"hasNextPage": True, "endCursor": "thread-1"},
                "nodes": [],
            },
        )
        second = pull_request_page(
            reviewThreads={
                "pageInfo": {"hasNextPage": True, "endCursor": "thread-2"},
                "nodes": [],
            },
        )
        cycle = pull_request_page(
            reviewThreads={
                "pageInfo": {"hasNextPage": True, "endCursor": "thread-1"},
                "nodes": [],
            },
        )

        with patch.object(
            review_state,
            "run_json",
            side_effect=[first, second, cycle],
        ), self.assertRaisesRegex(SystemExit, "review threads.*cursor"):
            review_state._fetch_complete_snapshot(
                "base-owner",
                "base-repo",
                42,
            )

    def test_comment_pagination_rejects_cursor_cycle(self) -> None:
        first_comment = {
            "id": "comment-1",
            "body": "first",
            "createdAt": "2026-08-08T12:00:00Z",
            "author": {"login": "human"},
        }
        thread = review_thread(first_comment)
        thread["comments"] = {
            "pageInfo": {
                "hasNextPage": True,
                "endCursor": "comment-1",
            },
            "nodes": [first_comment],
        }
        second = comment_page(first_comment)
        second["data"]["node"]["comments"]["pageInfo"] = {
            "hasNextPage": True,
            "endCursor": "comment-2",
        }
        cycle = comment_page(first_comment)
        cycle["data"]["node"]["comments"]["pageInfo"] = {
            "hasNextPage": True,
            "endCursor": "comment-1",
        }

        with patch.object(
            review_state,
            "run_json",
            side_effect=[second, cycle],
        ), self.assertRaisesRegex(SystemExit, "thread comments.*cursor"):
            review_state._complete_thread_comments(thread)

    def test_comment_page_response_failures_fail_closed(self) -> None:
        first_comment = {
            "id": "comment-1",
            "body": "first",
            "createdAt": "2026-08-08T12:00:00Z",
            "author": {"login": "human"},
        }
        responses = (
            (
                {"errors": [{"message": "rate limited"}]},
                "rate limited",
            ),
            (
                {"data": {"node": None}},
                "review thread disappeared",
            ),
        )

        for response, message in responses:
            with self.subTest(message=message):
                thread = review_thread(first_comment)
                thread["comments"] = {
                    "pageInfo": {
                        "hasNextPage": True,
                        "endCursor": "comment-1",
                    },
                    "nodes": [first_comment],
                }
                with patch.object(
                    review_state,
                    "run_json",
                    return_value=response,
                ), self.assertRaisesRegex(SystemExit, message):
                    review_state._complete_thread_comments(thread)


    def test_invalid_repository_or_pull_request_fails_closed(self) -> None:
        empty_connection = {
            "pageInfo": {"hasNextPage": False, "endCursor": None},
            "nodes": [],
        }
        responses = (
            {"data": {"repository": None}},
            {"data": {"repository": {"pullRequest": None}}},
            {"data": {"repository": {"pullRequest": {}}}},
            pull_request_page(
                reviews=None,
                reviewThreads=empty_connection,
            ),
            pull_request_page(
                reviews=empty_connection,
                reviewThreads=None,
            ),
        )
        for response in responses:
            with (
                self.subTest(response=response),
                patch.object(review_state, "run_json", return_value=response),
                self.assertRaisesRegex(
                    SystemExit,
                    "repository or pull request not found",
                ),
            ):
                review_state._fetch_complete_snapshot(
                    "base-owner",
                    "base-repo",
                    42,
                )


    def test_invalid_review_connection_shapes_fail_closed(self) -> None:
        valid_connection = {
            "pageInfo": {"hasNextPage": False, "endCursor": None},
            "nodes": [],
        }
        invalid_connections = (
            ({"nodes": []}, "pageInfo"),
            (
                {
                    "pageInfo": {
                        "hasNextPage": False,
                        "endCursor": None,
                    },
                    "nodes": None,
                },
                "nodes",
            ),
            (
                {
                    "pageInfo": {
                        "hasNextPage": False,
                        "endCursor": None,
                    },
                    "nodes": [None],
                },
                "nodes",
            ),
            (
                {
                    "pageInfo": {
                        "hasNextPage": False,
                        "endCursor": 7,
                    },
                    "nodes": [],
                },
                "endCursor",
            ),
        )
        labels = {
            "reviews": "reviews",
            "reviewThreads": "review threads",
        }
        for connection_name, label in labels.items():
            for invalid_connection, field in invalid_connections:
                connections = {
                    "reviews": valid_connection,
                    "reviewThreads": valid_connection,
                    connection_name: invalid_connection,
                }
                message = f"{label} {field}"
                response = pull_request_page(**connections)
                with (
                    self.subTest(
                        connection=connection_name,
                        field=field,
                    ),
                    patch.object(
                        review_state,
                        "run_json",
                        return_value=response,
                    ),
                    self.assertRaisesRegex(SystemExit, message),
                ):
                    review_state._fetch_complete_snapshot(
                        "base-owner",
                        "base-repo",
                        42,
                    )


    def test_missing_required_review_node_fields_fail_closed(self) -> None:
        page_info = {"hasNextPage": False, "endCursor": None}
        cases = (
            (
                pull_request_page(
                    reviews={"pageInfo": page_info, "nodes": [{}]},
                    reviewThreads={"pageInfo": page_info, "nodes": []},
                ),
                "reviews nodes",
            ),
            (
                pull_request_page(
                    reviews={"pageInfo": page_info, "nodes": []},
                    reviewThreads={
                        "pageInfo": page_info,
                        "nodes": [{"id": "thread-1"}],
                    },
                ),
                "review threads nodes",
            ),
        )
        for response, message in cases:
            with (
                self.subTest(message=message),
                patch.object(review_state, "run_json", return_value=response),
                self.assertRaisesRegex(SystemExit, message),
            ):
                review_state._fetch_complete_snapshot(
                    "base-owner",
                    "base-repo",
                    42,
                )


    def test_stable_metadata_includes_base_ref_oid(self) -> None:
        response = graphql_response([])

        with patch.object(
            review_state,
            "run_json",
            side_effect=[response, response],
        ):
            pull_request = review_state.fetch(
                "base-owner",
                "base-repo",
                42,
            )["pull_request"]

        self.assertEqual("a" * 40, pull_request["head_sha"])
        self.assertEqual("b" * 40, pull_request["base_sha"])
        self.assertIn("baseRefOid", review_state.QUERY)

    def test_base_drift_between_complete_snapshots_fails_closed(self) -> None:
        with patch.object(
            review_state,
            "run_json",
            side_effect=[
                graphql_response([]),
                graphql_response([], base="c" * 40),
            ],
        ), self.assertRaisesRegex(
            SystemExit, "pull request changed during pagination"
        ):
            review_state.fetch("base-owner", "base-repo", 42)

    def test_head_drift_between_complete_snapshots_fails_closed(self) -> None:
        with patch.object(
            review_state,
            "run_json",
            side_effect=[
                graphql_response([]),
                graphql_response([], head="b" * 40),
            ],
        ), self.assertRaisesRegex(
            SystemExit, "pull request changed during pagination"
        ):
            review_state.fetch("base-owner", "base-repo", 42)

    def test_new_commented_coderabbit_review_at_stable_head_fails_closed(
        self,
    ) -> None:
        approval = {
            "id": "approval",
            "state": "APPROVED",
            "body": "lgtm",
            "submittedAt": "2026-08-08T12:00:00Z",
            "author": {"login": "coderabbitai[bot]"},
            "commit": {"oid": "a" * 40},
        }
        commented = {
            "id": "commented",
            "state": "COMMENTED",
            "body": "new findings",
            "submittedAt": "2026-08-08T12:01:00Z",
            "author": {"login": "coderabbitai[bot]"},
            "commit": {"oid": "a" * 40},
        }

        with patch.object(
            review_state,
            "run_json",
            side_effect=[
                graphql_response([approval]),
                graphql_response([approval, commented]),
            ],
        ), self.assertRaisesRegex(
            SystemExit, "review state changed during pagination"
        ):
            review_state.fetch("base-owner", "base-repo", 42)

    def test_new_actionable_coderabbit_thread_at_stable_head_fails_closed(
        self,
    ) -> None:
        coderabbit_comment = {
            "id": "comment-1",
            "body": "actionable",
            "createdAt": "2026-08-08T12:01:00Z",
            "author": {"login": "coderabbitai[bot]"},
        }

        with patch.object(
            review_state,
            "run_json",
            side_effect=[
                graphql_response([]),
                graphql_response(
                    [],
                    threads=[review_thread(coderabbit_comment)],
                ),
            ],
        ), self.assertRaisesRegex(
            SystemExit, "review state changed during pagination"
        ):
            review_state.fetch("base-owner", "base-repo", 42)

    def test_new_actionable_comment_at_stable_head_fails_closed(self) -> None:
        human_comment = {
            "id": "comment-1",
            "body": "question",
            "createdAt": "2026-08-08T12:00:00Z",
            "author": {"login": "human"},
        }
        coderabbit_comment = {
            "id": "comment-2",
            "body": "actionable",
            "createdAt": "2026-08-08T12:01:00Z",
            "author": {"login": "coderabbitai[bot]"},
        }

        with patch.object(
            review_state,
            "run_json",
            side_effect=[
                graphql_response(
                    [],
                    threads=[review_thread(human_comment)],
                ),
                graphql_response(
                    [],
                    threads=[review_thread(human_comment, coderabbit_comment)],
                ),
            ],
        ), self.assertRaisesRegex(
            SystemExit, "review state changed during pagination"
        ):
            review_state.fetch("base-owner", "base-repo", 42)

    def test_unresolved_outdated_coderabbit_thread_is_not_actionable(
        self,
    ) -> None:
        coderabbit_comment = {
            "id": "comment-1",
            "body": "superseded finding",
            "createdAt": "2026-08-08T12:01:00Z",
            "author": {"login": "coderabbitai[bot]"},
        }
        outdated_thread = review_thread(coderabbit_comment)
        outdated_thread["isOutdated"] = True
        response = graphql_response([], threads=[outdated_thread])

        with patch.object(
            review_state,
            "run_json",
            side_effect=[response, response],
        ):
            result = review_state.fetch("base-owner", "base-repo", 42)

        self.assertEqual(1, result["summary"]["unresolved_thread_count"])
        self.assertEqual(
            0,
            result["summary"]["unresolved_coderabbit_thread_count"],
        )


class ProvenanceTests(unittest.TestCase):
    def test_modified_script_provenance_is_explicit(self) -> None:
        script_history = subprocess.run(
            [
                "git",
                "log",
                "--reverse",
                "--format=%H",
                "--",
                ".claude/skills/gh-copilot-review-loop/scripts/review_state.py",
                ".claude/skills/coderabbit-review-loop/scripts/review_state.py",
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.splitlines()
        self.assertEqual(
            [ORIGINAL_IMPORT_COMMIT, *DOWNSTREAM_SCRIPT_COMMITS],
            script_history,
        )
        script_digest = hashlib.sha256(SCRIPT_PATH.read_bytes()).hexdigest()
        skill_text = SKILL_PATH.read_text(encoding="utf-8")
        license_text = LICENSE_PATH.read_text(encoding="utf-8")

        license_marker = "Third-party attribution for coderabbit-review-loop\n"
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
