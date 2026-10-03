from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "validate_agent_output.py"
SPEC = importlib.util.spec_from_file_location("validate_agent_output", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

CASES_PATH = Path(__file__).with_name("repository_check_cases.py")
CASES_SPEC = importlib.util.spec_from_file_location(
    "repository_check_cases",
    CASES_PATH,
)
if CASES_SPEC is None or CASES_SPEC.loader is None:
    raise RuntimeError(f"cannot load repository check cases from {CASES_PATH}")
repository_check_cases = importlib.util.module_from_spec(CASES_SPEC)
CASES_SPEC.loader.exec_module(repository_check_cases)


def proposal(
    path: str = "tests/change.test.ts",
    proposal_kind: str = "test",
) -> dict[str, str]:
    return {
        "proposal_kind": proposal_kind,
        "path": path,
        "operation": "replace",
        "exact_content": "replacement",
        "patch_intent": "exercise the requested contract",
    }


def edit_proposal(path: str = "src/change.ts") -> dict[str, str]:
    return {
        "path": path,
        "operation": "replace",
        "exact_content": "replacement",
        "patch_intent": "exercise the requested contract",
    }


def command(*arguments: str) -> dict[str, object]:
    return {
        "argv": list(arguments),
        "timeout_seconds": 120,
    }


def clean_review_gate_states() -> dict[str, str]:
    return {
        "ci": "passed",
        "coderabbit": "passed",
        "contract_conformance": "passed",
    }


def clean_integration_gate_states(
    *,
    native_lab: str = "passed",
) -> dict[str, str]:
    return {
        "implementation": "green",
        "conformance": "passed",
        "review": "passed",
        "native_lab": native_lab,
        "mergeability": "mergeable",
    }


def blocked_payloads() -> dict[str, dict[str, object]]:
    """One valid blocked payload per role, each with exactly its contract keys."""
    blockers = ["approved contract absent"]
    return {
        "coder": {
            "role": "coder",
            "phase": "blocked",
            "summary": "Missing contract",
            "implementation_proposals": [],
            "proposed_red_checks": [],
            "proposed_green_checks": [],
            "proposed_verification_checks": [],
            "blockers": blockers,
        },
        "ui-design": {
            "role": "ui-design",
            "phase": "blocked",
            "summary": "Missing contract",
            "edit_proposals": [],
            "proposed_browser_checks": [],
            "blockers": blockers,
        },
        "tech-writer": {
            "role": "tech-writer",
            "phase": "blocked",
            "summary": "Missing contract",
            "edit_proposals": [],
            "evidence_sources": [],
            "proposed_documentation_checks": [],
            "blockers": blockers,
        },
        "reducer-adversary": {
            "role": "reducer-adversary",
            "phase": "blocked",
            "adversarial_contracts": [],
            "fixture_proposals": [],
            "failure_scenarios": [],
            "blockers": blockers,
        },
        "code-review": {
            "role": "code-review",
            "phase": "blocked",
            "head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "findings": [],
            "gate_states": {},
            "coverage": [],
            "blockers": blockers,
        },
        "reducer-contract": {
            "role": "reducer-contract",
            "phase": "blocked",
            "decisions": [],
            "evidence": [],
            "tests": [],
            "blockers": blockers,
        },
        "reducer-integration": {
            "role": "reducer-integration",
            "phase": "blocked",
            "heads": {},
            "gate_states": {},
            "blockers": blockers,
        },
    }


class AgentOutputValidationTests(unittest.TestCase):
    def test_rejects_empty_productive_payload_for_every_role(self) -> None:
        payloads = {
            "coder": {
                "role": "coder",
                "phase": "red_proposal",
                "summary": "nothing",
                "implementation_proposals": [],
                "proposed_red_checks": [],
                "proposed_green_checks": [],
                "proposed_verification_checks": [],
                "blockers": [],
            },
            "ui-design": {
                "role": "ui-design",
                "phase": "edit_proposal",
                "summary": "nothing",
                "edit_proposals": [],
                "proposed_browser_checks": [],
                "blockers": [],
            },
            "tech-writer": {
                "role": "tech-writer",
                "phase": "edit_proposal",
                "summary": "nothing",
                "edit_proposals": [],
                "evidence_sources": [],
                "proposed_documentation_checks": [],
                "blockers": [],
            },
            "reducer-adversary": {
                "role": "reducer-adversary",
                "phase": "adversarial_red",
                "adversarial_contracts": [],
                "fixture_proposals": [],
                "failure_scenarios": [],
                "blockers": [],
            },
            "code-review": {
                "role": "code-review",
                "phase": "review_report",
                "head_sha": "a" * 40,
                "base_sha": "b" * 40,
                "findings": [],
                "gate_states": {},
                "coverage": [],
                "blockers": [],
            },
            "reducer-contract": {
                "role": "reducer-contract",
                "phase": "contract_report",
                "decisions": [],
                "evidence": [],
                "tests": [],
                "blockers": [],
            },
            "reducer-integration": {
                "role": "reducer-integration",
                "phase": "integration_report",
                "heads": {},
                "gate_states": {},
                "blockers": [],
            },
        }
        for role, payload in payloads.items():
            with self.subTest(role=role), self.assertRaises(ValueError):
                validator.validate_output(role, payload)

    def test_accepts_role_specific_productive_payloads(self) -> None:
        payloads = {
            "coder": {
                "role": "coder",
                "phase": "red_proposal",
                "summary": "RED",
                "implementation_proposals": [proposal()],
                "proposed_red_checks": [command("python3", "-m", "unittest", "focused")],
                "proposed_green_checks": [],
                "proposed_verification_checks": [],
                "blockers": [],
            },
            "ui-design": {
                "role": "ui-design",
                "phase": "edit_proposal",
                "summary": "UI",
                "edit_proposals": [edit_proposal()],
                "proposed_browser_checks": [
                    "At a 1280x720 viewport, click Settings and confirm "
                    "the panel is visually aligned."
                ],
                "blockers": [],
            },
            "tech-writer": {
                "role": "tech-writer",
                "phase": "edit_proposal",
                "summary": "Docs",
                "edit_proposals": [edit_proposal("docs/book/src/change.md")],
                "evidence_sources": ["src/change.ts:1"],
                "proposed_documentation_checks": [
                    command("git", "diff", "--check", "--", "docs/change.md")
                ],
                "blockers": [],
            },
            "reducer-adversary": {
                "role": "reducer-adversary",
                "phase": "adversarial_red",
                "adversarial_contracts": [{
                    "invariant": "identity is stable",
                    "fixture_proposal": {"path": "crates/cmtraceopen-parser/tests/fixtures/adversarial.log", "content": "fixture"},
                    "proposed_red_command": command("cargo", "test", "focused"),
                    "expected_failure": "identity collision",
                }],
                "fixture_proposals": [{"path": "crates/cmtraceopen-parser/tests/fixtures/adversarial.log", "content": "fixture"}],
                "failure_scenarios": ["identity collision"],
                "blockers": [],
            },
            "code-review": {
                "role": "code-review",
                "phase": "review_report",
                "head_sha": "a" * 40,
                "base_sha": "b" * 40,
                "findings": [],
                "gate_states": clean_review_gate_states(),
                "coverage": ["src/change.ts"],
                "blockers": [],
            },
            "reducer-contract": {
                "role": "reducer-contract",
                "phase": "contract_report",
                "decisions": [{"contract": "identity", "evidence": "fixture", "consequence": "stable key", "test": command("cargo", "test", "--package", "cmtraceopen-parser")}],
                "evidence": ["contract"],
                "tests": [command("python3", "-m", "unittest", "tests.focused")],
                "blockers": [],
            },
            "reducer-integration": {
                "role": "reducer-integration",
                "phase": "integration_report",
                "heads": {"head": "a" * 40},
                "gate_states": clean_integration_gate_states(),
                "blockers": [],
            },
        }
        for role, payload in payloads.items():
            with self.subTest(role=role):
                validator.validate_output(role, payload)
        review_report = payloads["code-review"]
        review_report["head_sha"] = "stale"
        with self.assertRaises(ValueError):
            validator.validate_output("code-review", review_report)
        review_report["head_sha"] = "a" * 40
        mixed_report = dict(payloads["reducer-integration"])
        mixed_report["blockers"] = ["cannot also be productive"]
        with self.assertRaises(ValueError):
            validator.validate_output("reducer-integration", mixed_report)

    def test_integration_report_requires_exact_heads_and_gate_states(self) -> None:
        report = {
            "role": "reducer-integration",
            "phase": "integration_report",
            "heads": {"head": "a" * 40},
            "gate_states": clean_integration_gate_states(),
            "blockers": [],
        }
        validator.validate_output("reducer-integration", report)
        validator.validate_output(
            "reducer-integration",
            {
                **report,
                "gate_states": clean_integration_gate_states(
                    native_lab="not_required",
                ),
            },
        )

        missing = clean_integration_gate_states()
        missing.pop("mergeability")
        invalid_values = (
            ("heads", ["not-an-object"]),
            ("gate_states", ["not-an-object"]),
            ("heads", {"head": "stale"}),
            ("heads", {"": "a" * 40}),
            ("gate_states", missing),
            (
                "gate_states",
                {
                    **clean_integration_gate_states(),
                    "focused": "passed",
                },
            ),
            (
                "gate_states",
                {
                    **clean_integration_gate_states(),
                    "implementation": "passed",
                },
            ),
            (
                "gate_states",
                {
                    **clean_integration_gate_states(),
                    "native_lab": "unavailable",
                },
            ),
        )
        for field, value in invalid_values:
            with self.subTest(field=field, value=value):
                invalid = {**report, field: value}
                with self.assertRaises(ValueError):
                    validator.validate_output(
                        "reducer-integration",
                        invalid,
                    )

    def test_code_review_requires_closed_mandatory_gate_set(self) -> None:
        report = {
            "role": "code-review",
            "phase": "review_report",
            "head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "findings": [],
            "gate_states": clean_review_gate_states(),
            "coverage": ["src/change.ts"],
            "blockers": [],
        }
        validator.validate_output("code-review", report)

        missing = clean_review_gate_states()
        missing.pop("contract_conformance")
        invalid_gate_states = (
            {"CI": "failed"},
            missing,
            {**clean_review_gate_states(), "focused": "passed"},
            {**clean_review_gate_states(), "charter_review": "passed"},
            {**clean_review_gate_states(), "ci": "failed"},
        )
        for gate_states in invalid_gate_states:
            with self.subTest(gate_states=gate_states), self.assertRaises(ValueError):
                report["gate_states"] = gate_states
                validator.validate_output("code-review", report)

    def test_code_review_findings_require_portable_file_line_citations(
        self,
    ) -> None:
        report = {
            "role": "code-review",
            "phase": "blocked",
            "head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "findings": [{
                "file_line": "src/change.ts:42",
                "mechanism": "validated location",
                "failure_scenario": "the cited branch fails",
                "severity": "major",
            }],
            "gate_states": {},
            "coverage": ["reviewed source and contracts"],
            "blockers": ["verified blocking finding remains"],
        }
        validator.validate_output("code-review", report)

        for file_line in (
            "not-a-location",
            "src/change.ts:0",
            "src/change.ts:abc",
            "../change.ts:1",
            "/tmp/change.ts:1",
            "src\\change.ts:1",
            ":1",
            "src/change.ts:\N{ARABIC-INDIC DIGIT ONE}",
        ):
            with self.subTest(file_line=file_line), self.assertRaises(ValueError):
                report["findings"][0]["file_line"] = file_line
                validator.validate_output("code-review", report)

        clean_report = {
            **report,
            "phase": "review_report",
            "findings": [{
                "file_line": "src/change.ts:42",
                "mechanism": "validated location",
                "failure_scenario": "the cited branch fails",
                "severity": "major",
            }],
            "gate_states": clean_review_gate_states(),
            "blockers": [],
        }
        with self.assertRaisesRegex(
            ValueError,
            "productive review_report must contain no findings",
        ):
            validator.validate_output("code-review", clean_report)

    def test_reducer_contract_tests_require_policy_checked_commands(
        self,
    ) -> None:
        payload = {
            "role": "reducer-contract",
            "phase": "contract_report",
            "decisions": [{
                "contract": "identity",
                "evidence": "fixture",
                "consequence": "stable key",
                "test": command("cargo", "test", "--package", "cmtraceopen-parser"),
            }],
            "evidence": ["contract"],
            "tests": [command("python3", "-m", "unittest", "tests.focused")],
            "blockers": [],
        }
        validator.validate_output("reducer-contract", payload)

        invalid_commands = (
            "cargo test",
            {"argv": ["sh", "-c", "cargo test"], "timeout_seconds": 120},
            {"argv": [], "timeout_seconds": 120},
            {"argv": ["cargo", "test"], "timeout_seconds": 0},
            {"argv": ["cargo", ""], "timeout_seconds": 120},
            {"argv": ["cargo"] * 129, "timeout_seconds": 120},
            {"argv": ["cargo", "test"], "timeout_seconds": True},
            {"argv": ["cargo", "test"], "timeout_seconds": 3601},
        )
        for field in ("decision", "tests"):
            for invalid in invalid_commands:
                with self.subTest(field=field, invalid=invalid):
                    candidate = {
                        **payload,
                        "decisions": [dict(payload["decisions"][0])],
                        "tests": list(payload["tests"]),
                    }
                    if field == "decision":
                        candidate["decisions"][0]["test"] = invalid
                    else:
                        candidate["tests"] = [invalid]
                    with self.assertRaises(ValueError):
                        validator.validate_output("reducer-contract", candidate)

    def test_red_proposals_accept_only_test_or_fixture_targets(self) -> None:
        payload = {
            "role": "coder",
            "phase": "red_proposal",
            "summary": "RED",
            "implementation_proposals": [proposal()],
            "proposed_red_checks": [
                command("python3", "-m", "unittest", "tests.focused")
            ],
            "proposed_green_checks": [],
            "proposed_verification_checks": [],
            "blockers": [],
        }
        accepted = (
            ("tests/parser.rs", "test"),
            ("src/__tests__/parser.ts", "test"),
            ("crates/parser/tests/fixtures/malformed.log", "fixture"),
            ("src/parser.test.ts", "test"),
            ("src/parser.spec.tsx", "test"),
        )
        for path, proposal_kind in accepted:
            with self.subTest(path=path, proposal_kind=proposal_kind):
                payload["implementation_proposals"] = [
                    proposal(path, proposal_kind)
                ]
                validator.validate_output("coder", payload)

        rejected = (
            ("src/parser.rs", "test"),
            ("src/parser.ts", "fixture"),
            ("package.json", "production"),
            ("tests/parser.rs", "production"),
            ("tests/fixtures/parser.log", "test"),
            ("src/test_parser.py", "test"),
        )
        for path, proposal_kind in rejected:
            with self.subTest(
                path=path,
                proposal_kind=proposal_kind,
            ), self.assertRaisesRegex(
                ValueError,
                "does not match|test or fixture",
            ):
                payload["implementation_proposals"] = [
                    proposal(path, proposal_kind)
                ]
                validator.validate_output("coder", payload)

        payload["phase"] = "green_proposal"
        payload["implementation_proposals"] = [
            proposal("src/parser.rs", "production")
        ]
        payload["proposed_red_checks"] = []
        payload["proposed_green_checks"] = [command("cargo", "test")]
        payload["proposed_verification_checks"] = [command("cargo", "check")]
        validator.validate_output("coder", payload)

    def test_future_role_does_not_fall_through_to_integration(self) -> None:
        role = "future-role"
        with tempfile.TemporaryDirectory() as agents_dir:
            Path(agents_dir, f"{role}.md").write_text(
                "---\n"
                f"name: {role}\n"
                "output:\n"
                "  type: object\n"
                "  additionalProperties: false\n"
                "  required: [role, phase, blockers]\n"
                "  properties:\n"
                "    role: { type: string, const: future-role }\n"
                "    phase: { type: string }\n"
                "    blockers: { type: array }\n"
                "---\n",
                encoding="utf-8",
            )
            original_agents_dir = validator.AGENTS_DIR
            validator.AGENTS_DIR = Path(agents_dir)
            validator.ROLES.add(role)
            validator.TEXT_LIST_KEYS[role] = ("blockers",)
            try:
                with self.assertRaisesRegex(
                    ValueError,
                    f"no validation contract for role: {role}",
                ):
                    validator.validate_output(
                        role,
                        {
                            "role": role,
                            "phase": "future-report",
                            "blockers": [],
                        },
                    )
            finally:
                validator.TEXT_LIST_KEYS.pop(role)
                validator.ROLES.remove(role)
                validator.AGENTS_DIR = original_agents_dir

    def test_output_keys_must_match_the_role_contract(self) -> None:
        for role, payload in blocked_payloads().items():
            with self.subTest(role=role, case="exact"):
                validator.validate_output(role, payload)
            with self.subTest(role=role, case="unexpected"):
                with self.assertRaisesRegex(
                    ValueError,
                    r"output keys must match its contract \(missing: \[\], "
                    r"unexpected: \['commands_run'\]\)",
                ):
                    validator.validate_output(
                        role,
                        {**payload, "commands_run": ["cargo test"]},
                    )
            for key in payload:
                if key == "role":
                    continue
                with self.subTest(role=role, case=f"missing {key}"):
                    missing = {k: v for k, v in payload.items() if k != key}
                    with self.assertRaisesRegex(
                        ValueError,
                        rf"output keys must match its contract \(missing: \['{key}'\]",
                    ):
                        validator.validate_output(role, missing)

    def test_every_role_has_a_readable_output_contract(self) -> None:
        for role in sorted(validator.ROLES):
            with self.subTest(role=role):
                keys = validator.output_contract_keys(role)
                self.assertIn("role", keys)
                self.assertIn("phase", keys)
                self.assertIn("blockers", keys)

    def _write_contract(
        self, agents_dir: str, role: str, required: str, properties: str
    ) -> None:
        Path(agents_dir, f"{role}.md").write_text(
            "---\n"
            f"name: {role}\n"
            "output:\n"
            "  type: object\n"
            "  additionalProperties: false\n"
            f"  required: [{required}]\n"
            "  properties:\n"
            f"{properties}"
            "---\n",
            encoding="utf-8",
        )

    def test_optional_property_is_accepted_present_or_absent(self) -> None:
        role = "optional-role"
        with tempfile.TemporaryDirectory() as agents_dir:
            self._write_contract(
                agents_dir,
                role,
                "role, phase, blockers",
                "    role: { type: string, const: optional-role }\n"
                "    phase: { type: string }\n"
                "    blockers: { type: array }\n"
                "    note: { type: string }\n",
            )
            original_agents_dir = validator.AGENTS_DIR
            validator.AGENTS_DIR = Path(agents_dir)
            try:
                self.assertEqual(
                    validator.output_contract_keys(role),
                    frozenset({"role", "phase", "blockers", "note"}),
                )
                payload = {"role": role, "phase": "p", "blockers": []}
                validator._validate_contract_keys(role, payload)
                validator._validate_contract_keys(role, {**payload, "note": "x"})
                with self.assertRaisesRegex(
                    ValueError,
                    r"output keys must match its contract \(missing: \[\], "
                    r"unexpected: \['extra'\]\)",
                ):
                    validator._validate_contract_keys(
                        role, {**payload, "extra": "y"}
                    )
            finally:
                validator.AGENTS_DIR = original_agents_dir

    def test_required_not_subset_of_properties_fails_loudly(self) -> None:
        role = "broken-role"
        with tempfile.TemporaryDirectory() as agents_dir:
            self._write_contract(
                agents_dir,
                role,
                "role, phase, blockers, missing_property",
                "    role: { type: string, const: broken-role }\n"
                "    phase: { type: string }\n"
                "    blockers: { type: array }\n",
            )
            original_agents_dir = validator.AGENTS_DIR
            validator.AGENTS_DIR = Path(agents_dir)
            try:
                with self.assertRaisesRegex(
                    ValueError,
                    r"required keys are not a subset of properties",
                ):
                    validator.output_contract_keys(role)
            finally:
                validator.AGENTS_DIR = original_agents_dir

    def test_accepts_explicit_blocked_payload_and_rejects_mixed_blocked_payload(self) -> None:
        blocked = {
            "role": "coder",
            "phase": "blocked",
            "summary": "Missing contract",
            "implementation_proposals": [],
            "proposed_red_checks": [],
            "proposed_green_checks": [],
            "proposed_verification_checks": [],
            "blockers": ["approved contract absent"],
        }
        validator.validate_output("coder", blocked)
        blocked["implementation_proposals"] = [proposal()]
        with self.assertRaises(ValueError):
            validator.validate_output("coder", blocked)
        blocked_review = {
            "role": "code-review",
            "phase": "blocked",
            "head_sha": "a" * 40,
            "base_sha": "b" * 40,
            "findings": [],
            "gate_states": {},
            "coverage": [],
            "blockers": ["exact-head artifacts absent"],
        }
        validator.validate_output("code-review", blocked_review)
        blocked_review["findings"] = [{
            "file_line": "src/change.ts:1",
            "mechanism": "verified defect",
            "failure_scenario": "the reviewed path fails",
            "severity": "important",
        }]
        blocked_review["coverage"] = ["src/change.ts"]
        validator.validate_output("code-review", blocked_review)
        blocked_review["coverage"] = []
        with self.assertRaisesRegex(
            ValueError,
            "blocked code-review findings require nonempty coverage",
        ):
            validator.validate_output("code-review", blocked_review)
        blocked_review["coverage"] = ["src/change.ts"]
        blocked_review["findings"] = []
        blocked_review["coverage"] = []
        blocked_review["gate_states"] = clean_review_gate_states()
        with self.assertRaises(ValueError):
            validator.validate_output("code-review", blocked_review)
        blocked_review["gate_states"] = {}
        blocked_review["blockers"] = [""]
        with self.assertRaises(ValueError):
            validator.validate_output("code-review", blocked_review)

    def test_rejects_role_mismatch_and_cross_platform_unsafe_paths(self) -> None:
        payload = {
            "role": "coder",
            "phase": "red_proposal",
            "summary": "RED",
            "implementation_proposals": [proposal()],
            "proposed_red_checks": [command("python3", "-m", "unittest", "focused")],
            "proposed_green_checks": [],
            "proposed_verification_checks": [],
            "blockers": [],
        }
        with self.assertRaises(ValueError):
            validator.validate_output("ui-design", payload)
        for path in ("src\\change.ts", "src/CON.txt", "src/trailing.", "src/a?.ts"):
            with self.subTest(path=path):
                payload["implementation_proposals"] = [proposal(path)]
                with self.assertRaises(ValueError):
                    validator.validate_output("coder", payload)
        payload["implementation_proposals"] = [proposal()]
        payload["proposed_red_checks"] = [command("")]
        with self.assertRaises(ValueError):
            validator.validate_output("coder", payload)

    def test_rejects_extended_windows_reserved_names_in_proposal_paths(
        self,
    ) -> None:
        payload = {
            "role": "coder",
            "phase": "red_proposal",
            "summary": "RED",
            "implementation_proposals": [],
            "proposed_red_checks": [command("python3", "-m", "unittest", "focused")],
            "proposed_green_checks": [],
            "proposed_verification_checks": [],
            "blockers": [],
        }
        reserved_paths = (
            "src/COM¹.txt",
            "src/com².ts",
            "src/Com³",
            "src/LPT¹.txt",
            "src/lpt².ts",
            "src/LpT³",
            "src/CONIN$.json",
            "src/conout$.log",
        )
        for path in reserved_paths:
            with self.subTest(path=path):
                payload["implementation_proposals"] = [proposal(path)]
                with self.assertRaisesRegex(ValueError, "portable"):
                    validator.validate_output("coder", payload)

    def test_coder_checks_require_policy_checked_bounded_argument_vectors(self) -> None:
        payload = {
            "role": "coder",
            "phase": "red_proposal",
            "summary": "RED",
            "implementation_proposals": [proposal()],
            "proposed_red_checks": [
                command("python3", "-m", "unittest", "tests.focused")
            ],
            "proposed_green_checks": [],
            "proposed_verification_checks": [],
            "blockers": [],
        }
        validator.validate_output("coder", payload)
        invalid_checks = (
            "open changed screen",
            "python3 -m unittest tests.focused",
            {"argv": "python3", "timeout_seconds": 120},
            {"argv": [], "timeout_seconds": 120},
            {"argv": ["python3", ""], "timeout_seconds": 120},
            {"argv": ["python3", 7], "timeout_seconds": 120},
            {"argv": ["python3"], "timeout_seconds": 0},
            {"argv": ["python3"], "timeout_seconds": 3601},
            {"argv": ["python3"], "timeout_seconds": True},
            {
                "argv": ["python3"],
                "timeout_seconds": 120,
                "shell": True,
            },
        )
        for invalid in invalid_checks:
            with self.subTest(invalid=invalid):
                payload["proposed_red_checks"] = [invalid]
                with self.assertRaises(ValueError):
                    validator.validate_output("coder", payload)

        payload["proposed_red_checks"] = [
            command("python3", "-m", "unittest", "tests.focused")
        ]
        payload["proposed_verification_checks"] = [
            command("python3", "-m", "unittest", "tests.focused")
        ]
        with self.assertRaisesRegex(ValueError, "verification"):
            validator.validate_output("coder", payload)

    def test_accepts_every_checked_in_repository_check_form(self) -> None:
        payload = {
            "role": "coder",
            "phase": "red_proposal",
            "summary": "RED",
            "implementation_proposals": [proposal()],
            "proposed_red_checks": [],
            "proposed_green_checks": [],
            "proposed_verification_checks": [],
            "blockers": [],
        }
        for arguments in repository_check_cases.ALLOWED_REPOSITORY_CHECKS:
            with self.subTest(arguments=arguments):
                payload["proposed_red_checks"] = [command(*arguments)]
                validator.validate_output("coder", payload)

    def test_rejects_indirect_unknown_network_and_mutating_checks(self) -> None:
        payload = {
            "role": "coder",
            "phase": "red_proposal",
            "summary": "RED",
            "implementation_proposals": [proposal()],
            "proposed_red_checks": [],
            "proposed_green_checks": [],
            "proposed_verification_checks": [],
            "blockers": [],
        }
        for arguments in repository_check_cases.REJECTED_REPOSITORY_CHECKS:
            with self.subTest(arguments=arguments):
                payload["proposed_red_checks"] = [command(*arguments)]
                with self.assertRaisesRegex(ValueError, "repository check policy"):
                    validator.validate_output("coder", payload)

    def test_ui_browser_checks_require_bounded_control_free_scenario_strings(
        self,
    ) -> None:
        scenario = (
            "At a 1280x720 viewport, click Settings and confirm the panel "
            "is visible without overlap."
        )
        payload = {
            "role": "ui-design",
            "phase": "edit_proposal",
            "summary": "UI",
            "edit_proposals": [edit_proposal()],
            "proposed_browser_checks": [scenario],
            "blockers": [],
        }

        validator.validate_output("ui-design", payload)
        payload["proposed_browser_checks"] = ["x" * 4096]
        validator.validate_output("ui-design", payload)

        invalid_scenarios = (
            command("npm", "run", "build"),
            "",
            "click Settings\nconfirm the panel",
            "confirm the panel\x7f",
            "confirm the panel\x85",
            "x" * 4097,
            7,
        )
        for invalid in invalid_scenarios:
            with self.subTest(invalid=invalid):
                payload["proposed_browser_checks"] = [invalid]
                with self.assertRaises(ValueError):
                    validator.validate_output("ui-design", payload)

        payload["proposed_browser_checks"] = scenario
        with self.assertRaises(ValueError):
            validator.validate_output("ui-design", payload)

        payload["proposed_browser_checks"] = []
        with self.assertRaises(ValueError):
            validator.validate_output("ui-design", payload)

        payload.update(
            phase="blocked",
            edit_proposals=[],
            proposed_browser_checks=[],
            blockers=["stable UI contract unavailable"],
        )
        validator.validate_output("ui-design", payload)
        payload["proposed_browser_checks"] = [scenario]
        with self.assertRaises(ValueError):
            validator.validate_output("ui-design", payload)

    def test_writer_checks_require_direct_bounded_argument_vectors(self) -> None:
        payload = {
            "role": "tech-writer",
            "phase": "edit_proposal",
            "summary": "Docs",
            "edit_proposals": [edit_proposal("docs/book/src/change.md")],
            "evidence_sources": ["src/change.ts:1"],
            "proposed_documentation_checks": [
                command("git", "diff", "--check", "--", "docs/change.md")
            ],
            "blockers": [],
        }
        validator.validate_output("tech-writer", payload)

        invalid_checks = (
            "mdbook build",
            {"argv": "python3", "timeout_seconds": 120},
            {"argv": [], "timeout_seconds": 120},
            {"argv": ["python3", ""], "timeout_seconds": 120},
            {"argv": ["python3", 7], "timeout_seconds": 120},
            {"argv": ["python3", "bad\narg"], "timeout_seconds": 120},
            {"argv": ["python3"] * 129, "timeout_seconds": 120},
            {"argv": ["python3"], "timeout_seconds": 0},
            {"argv": ["python3"], "timeout_seconds": 3601},
            {"argv": ["python3"], "timeout_seconds": True},
            {
                "argv": ["python3"],
                "timeout_seconds": 120,
                "shell": True,
            },
        )
        for invalid in invalid_checks:
            with self.subTest(invalid=invalid):
                payload["proposed_documentation_checks"] = [invalid]
                with self.assertRaises(ValueError):
                    validator.validate_output("tech-writer", payload)

    def test_rejects_empty_strings_hidden_inside_productive_payloads(self) -> None:
        payloads = {
            "coder": {
                "role": "coder",
                "phase": "red_proposal",
                "summary": "",
                "implementation_proposals": [proposal()],
                "proposed_red_checks": [command("python3", "-m", "unittest", "focused")],
                "proposed_green_checks": [],
                "proposed_verification_checks": [],
                "blockers": [],
            },
            "reducer-adversary": {
                "role": "reducer-adversary",
                "phase": "adversarial_red",
                "adversarial_contracts": [{
                    "invariant": "identity",
                    "fixture_proposal": {"path": "tests/adversarial.log", "content": ""},
                    "proposed_red_command": command("python3", "-m", "unittest", "focused"),
                    "expected_failure": "collision",
                }],
                "fixture_proposals": [{"path": "tests/adversarial.log", "content": ""}],
                "failure_scenarios": ["collision"],
                "blockers": [],
            },
            "code-review": {
                "role": "code-review",
                "phase": "review_report",
                "head_sha": "a" * 40,
                "base_sha": "b" * 40,
                "findings": [{
                    "file_line": "src/change.ts:1",
                    "mechanism": "",
                    "failure_scenario": "failure",
                    "severity": "important",
                }],
                "gate_states": clean_review_gate_states(),
                "coverage": ["src/change.ts"],
                "blockers": [],
            },
            "reducer-contract": {
                "role": "reducer-contract",
                "phase": "contract_report",
                "decisions": [{
                    "contract": "identity",
                    "evidence": "fixture",
                    "consequence": "stable key",
                    "test": "",
                }],
                "evidence": ["contract"],
                "tests": [command("python3", "-m", "unittest", "tests.focused")],
                "blockers": [],
            },
        }
        for role, payload in payloads.items():
            with self.subTest(role=role), self.assertRaises(ValueError):
                validator.validate_output(role, payload)



    def test_reducer_integration_report_requires_heads_and_gate_states(self) -> None:
        payload = {
            "role": "reducer-integration",
            "phase": "integration_report",
            "heads": {"317": "a" * 40},
            "gate_states": {
                "implementation": "green",
                "conformance": "passed",
                "review": "passed",
                "native_lab": "not_required",
                "mergeability": "mergeable",
            },
            "blockers": [],
        }
        validator.validate_output("reducer-integration", payload)

        for field in ("heads", "gate_states"):
            invalid = dict(payload, **{field: {}})
            with self.subTest(field=field), self.assertRaises(ValueError):
                validator.validate_output("reducer-integration", invalid)

        with self.assertRaises(ValueError):
            validator.validate_output(
                "reducer-integration",
                dict(payload, blockers=["aggregate gate unavailable"]),
            )

    def test_reducer_integration_blocked_requires_only_blockers(self) -> None:
        payload = {
            "role": "reducer-integration",
            "phase": "blocked",
            "heads": {},
            "gate_states": {},
            "blockers": ["aggregate gate unavailable"],
        }
        validator.validate_output("reducer-integration", payload)

        invalid_payloads = (
            dict(payload, heads={"317": "a" * 40}),
            dict(payload, gate_states={"implementation": "green"}),
            dict(payload, blockers=[]),
            dict(payload, heads=[]),
            dict(payload, gate_states=[]),
        )
        for invalid in invalid_payloads:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validator.validate_output("reducer-integration", invalid)

if __name__ == "__main__":
    unittest.main()
