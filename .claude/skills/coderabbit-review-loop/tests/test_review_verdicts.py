"""Approval semantics through the complete, stable-snapshot fetch boundary."""

from __future__ import annotations

from copy import deepcopy
import importlib.util
from itertools import permutations
import unittest
from unittest.mock import patch

from test_review_state import REPO_ROOT, graphql_response, review_state, review_thread


HEAD = "a" * 40
OLD_HEAD = "b" * 40


def review(
    state: str,
    minute: int,
    *,
    head: str = HEAD,
    login: str = "coderabbitai",
    updated_minute: int | None = None,
) -> dict:
    submitted = f"2026-10-03T01:{minute:02d}:00Z"
    return {
        "id": f"{state}-{minute}-{login}",
        "state": state,
        "submittedAt": submitted,
        "updatedAt": (
            f"2026-10-03T01:{updated_minute:02d}:00Z"
            if updated_minute is not None else submitted
        ),
        "author": {"login": login},
        "commit": {"oid": head},
        "body": "Review or discussion",
    }


class ReviewVerdictTests(unittest.TestCase):
    def fetch(self, reviews: list[dict], **kwargs: object) -> dict:
        with patch.object(
            review_state, "run_json", return_value=graphql_response(reviews, **kwargs)
        ):
            return review_state.fetch("base-owner", "base-repo", 42)

    def test_approval_survives_discussion_and_preserves_raw_latest(self) -> None:
        approval = review("APPROVED", 12)
        comment = review("COMMENTED", 15)
        for events in permutations([approval, comment]):
            with self.subTest(events=events):
                summary = self.fetch(list(events))["summary"]
                self.assertTrue(summary["approved_at_head"])
                self.assertEqual(2, summary["coderabbit_review_count"])
                self.assertEqual(comment, summary["latest_coderabbit_review"])
                self.assertEqual("COMMENTED", summary["latest_coderabbit_review_state"])
                self.assertEqual([approval], summary["effective_coderabbit_reviews"])

    def test_changes_or_dismissal_cannot_be_erased_by_discussion(self) -> None:
        for state in ("CHANGES_REQUESTED", "DISMISSED"):
            events = [review("APPROVED", 12), review(state, 14), review("COMMENTED", 15)]
            for ordered in permutations(events):
                with self.subTest(state=state, ordered=ordered):
                    self.assertFalse(self.fetch(list(ordered))["summary"]["approved_at_head"])

    def test_dismissed_approval_cannot_qualify(self) -> None:
        self.assertFalse(self.fetch([
            review("DISMISSED", 12, updated_minute=14), review("COMMENTED", 15),
        ])["summary"]["approved_at_head"])

    def test_late_dismissal_of_old_review_blocks_newer_submission(self) -> None:
        summary = self.fetch([
            review("DISMISSED", 10, head=OLD_HEAD, updated_minute=14),
            review("APPROVED", 12), review("COMMENTED", 15),
        ])["summary"]
        self.assertFalse(summary["approved_at_head"])

    def test_strictly_later_head_approval_replaces_blocking_verdict(self) -> None:
        for state in ("CHANGES_REQUESTED", "DISMISSED"):
            with self.subTest(state=state):
                summary = self.fetch([
                    review(state, 10, updated_minute=14),
                    review("APPROVED", 16), review("COMMENTED", 17),
                ])["summary"]
                self.assertTrue(summary["approved_at_head"])

    def test_editing_old_verdict_does_not_reorder_submission(self) -> None:
        for state, expected in (("APPROVED", False), ("CHANGES_REQUESTED", True)):
            later = "CHANGES_REQUESTED" if state == "APPROVED" else "APPROVED"
            with self.subTest(state=state):
                summary = self.fetch([
                    review(state, 10, updated_minute=18), review(later, 12),
                    review("COMMENTED", 15),
                ])["summary"]
                self.assertEqual(expected, summary["approved_at_head"])

    def test_comment_alone_or_old_head_approval_does_not_qualify(self) -> None:
        for events in (
            [review("COMMENTED", 15)],
            [review("APPROVED", 12, head=OLD_HEAD), review("COMMENTED", 15)],
            [review("APPROVED", 10), review("APPROVED", 12, head=OLD_HEAD),
             review("COMMENTED", 15)],
        ):
            with self.subTest(events=events):
                self.assertFalse(self.fetch(events)["summary"]["approved_at_head"])

    def test_bot_aliases_share_verdict_history_and_other_reviewers_do_not(self) -> None:
        for earlier, later in (("coderabbitai", "CodeRabbitAI[Bot]"),
                               ("CodeRabbitAI[Bot]", "coderabbitai")):
            with self.subTest(earlier=earlier, later=later):
                summary = self.fetch([
                    review("APPROVED", 10, login=earlier),
                    review("CHANGES_REQUESTED", 12, login=later),
                    review("APPROVED", 14, login="other-review-bot[bot]"),
                    review("COMMENTED", 15, login=earlier),
                ])["summary"]
                self.assertFalse(summary["approved_at_head"])

    def test_tied_substantive_blocker_wins_in_every_input_order(self) -> None:
        for blocker in (
            review("CHANGES_REQUESTED", 12),
            review("DISMISSED", 10, updated_minute=12),
            review("APPROVED", 12, head=OLD_HEAD, login="coderabbitai[bot]"),
        ):
            for events in permutations([review("APPROVED", 12), blocker, review("COMMENTED", 15)]):
                with self.subTest(events=events):
                    self.assertFalse(self.fetch(list(events))["summary"]["approved_at_head"])

    def test_tied_discussion_does_not_erase_approval(self) -> None:
        for events in permutations([review("APPROVED", 12), review("COMMENTED", 12)]):
            with self.subTest(events=events):
                self.assertTrue(self.fetch(list(events))["summary"]["approved_at_head"])

    def test_unknown_or_inconsistent_bot_state_fails_closed(self) -> None:
        for state in ("FUTURE_STATE", None, "", "PENDING"):
            event = {**review("COMMENTED", 11), "state": state}
            with self.subTest(state=state), self.assertRaisesRegex(SystemExit, "review.*state"):
                self.fetch([event, review("APPROVED", 12), review("COMMENTED", 15)])

    def test_missing_or_invalid_submitted_time_fails_closed(self) -> None:
        for timestamp in (None, "", "invalid", 7, "2026-10-03T01:11:00"):
            event = {**review("CHANGES_REQUESTED", 11), "submittedAt": timestamp}
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(SystemExit, "submittedAt"):
                self.fetch([event, review("APPROVED", 12), review("COMMENTED", 15)])

    def test_dismissal_requires_valid_update_time_not_before_submission(self) -> None:
        for timestamp in (None, "", "invalid", "2026-10-03T01:09:00Z"):
            event = {**review("DISMISSED", 10), "updatedAt": timestamp}
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(SystemExit, "updatedAt"):
                self.fetch([event, review("APPROVED", 12)])

    def test_timestamp_order_uses_instants_not_string_order(self) -> None:
        blocker = {**review("CHANGES_REQUESTED", 10), "submittedAt": "2026-10-03T00:14:00-01:00"}
        summary = self.fetch([blocker, review("APPROVED", 12)])["summary"]
        self.assertFalse(summary["approved_at_head"])

    def test_approval_does_not_hide_unresolved_substantive_threads(self) -> None:
        thread = review_thread({
            "id": "finding", "body": "Fix the regression", "createdAt": "2026-10-03T01:15:00Z",
            "author": {"login": "coderabbitai"},
        })
        result = self.fetch([review("APPROVED", 12), review("COMMENTED", 15)], threads=[thread])
        self.assertTrue(result["summary"]["approved_at_head"])
        self.assertEqual(1, result["summary"]["unresolved_coderabbit_thread_count"])
        self.assertEqual([thread["id"]], [item["id"] for item in result["unresolved_threads"]])
        self.assertEqual(thread["comments"]["nodes"], result["unresolved_threads"][0]["comments"]["nodes"])

    def test_later_review_page_can_revoke_approval(self) -> None:
        first = graphql_response([review("APPROVED", 12)])
        first["data"]["repository"]["pullRequest"]["reviews"]["pageInfo"] = {
            "hasNextPage": True, "endCursor": "next",
        }
        second = graphql_response([review("CHANGES_REQUESTED", 14), review("COMMENTED", 15)])
        with patch.object(review_state, "run_json", side_effect=[first, second, first, second]):
            result = review_state.fetch("base-owner", "base-repo", 42)
        self.assertFalse(result["summary"]["approved_at_head"])

    def test_conflicting_duplicate_review_across_pages_fails_closed(self) -> None:
        blocker = review("CHANGES_REQUESTED", 12)
        first = graphql_response([blocker])
        first["data"]["repository"]["pullRequest"]["reviews"]["pageInfo"] = {
            "hasNextPage": True, "endCursor": "next",
        }
        second = graphql_response([{**blocker, "state": "APPROVED"}])
        with patch.object(review_state, "run_json", side_effect=[first, second, first, second]), \
                self.assertRaisesRegex(SystemExit, "review.*changed during pagination"):
            review_state.fetch("base-owner", "base-repo", 42)

    def test_dismissal_between_snapshots_fails_closed(self) -> None:
        first = graphql_response([review("APPROVED", 12), review("COMMENTED", 15)])
        second = graphql_response([
            {**review("APPROVED", 12, updated_minute=17), "state": "DISMISSED"},
            review("COMMENTED", 15),
        ])
        with patch.object(review_state, "run_json", side_effect=[first, second]), \
                self.assertRaisesRegex(SystemExit, "review state changed during pagination"):
            review_state.fetch("base-owner", "base-repo", 42)


class LaneReviewContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        path = REPO_ROOT / ".omp/skills/cmtraceopen-dev/scripts/lane_state.py"
        spec = importlib.util.spec_from_file_location("approval_lane_state", path)
        assert spec is not None and spec.loader is not None
        cls.lane_state = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.lane_state)

    def snapshot(self, reviews: list[dict]) -> dict:
        response = graphql_response(reviews)
        response["data"]["repository"]["pullRequest"]["isDraft"] = True
        with patch.object(review_state, "run_json", return_value=response):
            return review_state.fetch("base-owner", "base-repo", 42)

    def validate(self, raw: dict) -> None:
        self.lane_state._validate_coderabbit_raw_verdict(raw, {
            "prNumber": 42,
            "prUrl": "https://github.com/base-owner/base-repo/pull/42",
            "headSha": HEAD,
            "currentBaseSha": OLD_HEAD,
        }, "integration")

    def test_lane_accepts_real_helper_approval_and_later_discussion(self) -> None:
        for events in ([review("APPROVED", 12)],
                       [review("APPROVED", 12), review("COMMENTED", 15)]):
            with self.subTest(events=events):
                self.validate(self.snapshot(events))

    def test_lane_recomputes_verdict_instead_of_trusting_approval_summary(self) -> None:
        for blocker in (
            review("CHANGES_REQUESTED", 14),
            review("DISMISSED", 10, updated_minute=14),
            review("CHANGES_REQUESTED", 12),
            review("APPROVED", 14, head=OLD_HEAD),
            {**review("CHANGES_REQUESTED", 14), "state": "FUTURE_STATE"},
            {**review("CHANGES_REQUESTED", 14), "submittedAt": None},
        ):
            raw = self.snapshot([review("APPROVED", 12), review("COMMENTED", 15)])
            raw["reviews"].insert(1, blocker)
            raw["summary"]["review_count"] += 1
            raw["summary"]["coderabbit_review_count"] += 1
            with self.subTest(blocker=blocker), self.assertRaises(ValueError):
                self.validate(raw)

    def test_lane_preserves_schema_counts_and_latest_event_integrity(self) -> None:
        original = self.snapshot([review("APPROVED", 12), review("COMMENTED", 15)])
        for variant in ("extra-field", "missing-updated", "empty-verdict", "wrong-count",
                        "wrong-latest", "wrong-state", "duplicate-review"):
            raw = deepcopy(original)
            if variant == "extra-field":
                raw["summary"]["unexpected"] = True
            elif variant == "missing-updated":
                del raw["reviews"][0]["updatedAt"]
            elif variant == "empty-verdict":
                raw["summary"]["effective_coderabbit_reviews"] = []
            elif variant == "wrong-count":
                raw["summary"]["coderabbit_review_count"] = 1
            elif variant == "wrong-latest":
                raw["summary"]["latest_coderabbit_review"] = raw["reviews"][0]
                raw["summary"]["latest_coderabbit_review_state"] = "APPROVED"
            elif variant == "wrong-state":
                raw["summary"]["latest_coderabbit_review_state"] = "APPROVED"
            else:
                raw["reviews"].append(deepcopy(raw["reviews"][0]))
                raw["summary"]["review_count"] += 1
                raw["summary"]["coderabbit_review_count"] += 1
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                self.validate(raw)

    def test_lane_preserves_draft_base_head_and_latest_cycle_head_gates(self) -> None:
        original = self.snapshot([review("APPROVED", 12), review("COMMENTED", 15)])
        for field, value in (("is_draft", False), ("head_sha", "c" * 40),
                             ("base_sha", "c" * 40)):
            raw = deepcopy(original)
            raw["pull_request"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(raw)
        raw = self.snapshot([review("APPROVED", 12), review("COMMENTED", 15, head=OLD_HEAD)])
        with self.assertRaises(ValueError):
            self.validate(raw)

    def test_lane_does_not_trust_forged_zero_actionable_thread_count(self) -> None:
        raw = self.snapshot([review("APPROVED", 12), review("COMMENTED", 15)])
        raw["unresolved_threads"] = [review_thread({
            "id": "finding", "author": {"login": "coderabbitai"},
            "body": "Regression", "createdAt": "2026-10-03T01:16:00Z",
        })]
        raw["summary"]["unresolved_thread_count"] = 1
        with self.assertRaises(ValueError):
            self.validate(raw)


if __name__ == "__main__":
    unittest.main()
