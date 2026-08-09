"""Tests for memory/finding_state.py — the finding lifecycle engine."""

import json
from pathlib import Path

import pytest

from memory.finding_state import (
    FINDING_STATES,
    FindingStateDB,
    FindingStateError,
    can_transition,
    transition,
    verify_report_artifact,
    write_report_artifact,
)


# ─── HIGH-severity fix helpers: real, hash-bound report artifacts ──────────
# CONFIRMED/REPORT_READY now require a persisted validation_core.py/
# self_critique.py-shaped report on disk, verified by content hash at
# transition time -- these build a REAL artifact via the same
# write_report_artifact() the production code path uses (not a hand-rolled
# fake), so these tests exercise the exact function being trusted.

def _validation_report_evidence(tmp_path, overall_pass=True, name="validation_report.json"):
    report = {
        "gate1_is_real": {"passed": overall_pass, "notes": {}},
        "gate2_in_scope": {"passed": overall_pass, "notes": {}},
        "gate3_exploitable": {"passed": overall_pass, "notes": {}},
        "gate4_not_dup": {"passed": overall_pass, "notes": {}},
        "overall_pass": overall_pass,
    }
    path = tmp_path / name
    report_hash = write_report_artifact(report, path)
    return {"validation_report_path": str(path), "validation_report_hash": report_hash}


def _self_critique_report_evidence(
    tmp_path, overall="pass", reproducibility_status="pass", name="self_critique_report.json",
):
    # Shape matches tools/self_critique.py's real self_critique() return
    # value: details is {check_name: check_result}, and check_result has a
    # "status" field. CONFIRMED's gate reads details.reproducibility.status
    # specifically (see memory/finding_state.py); SELF_CRITIQUED/REPORT_READY
    # read the top-level "overall" rollup — independent fields, so tests can
    # exercise them separately.
    report = {
        "candidate_id": "cand-test",
        "checks": [],
        "overall": overall,
        "details": {"reproducibility": {"name": "reproducibility", "status": reproducibility_status, "reason": "", "details": {}}},
    }
    path = tmp_path / name
    report_hash = write_report_artifact(report, path)
    return {"self_critique_report_path": str(path), "self_critique_report_hash": report_hash}


def _confirmed_evidence(tmp_path, overall_pass=True, reproducibility_status="pass"):
    """Full evidence bundle needed to legally reach CONFIRMED: a STRONG
    verdict, a validation_core.py artifact, AND a self_critique.py artifact
    whose reproducibility check specifically passed (the live-verification
    hardening fix)."""
    return {
        "verdict": "STRONG",
        **_validation_report_evidence(tmp_path, overall_pass=overall_pass),
        **_self_critique_report_evidence(tmp_path, reproducibility_status=reproducibility_status),
    }


class TestCanTransition:

    def test_legal_forward_step(self):
        result = can_transition("SUSPECTED", "TESTING")
        assert result["allowed"] is True

    def test_skip_ahead_rejected(self):
        result = can_transition("SUSPECTED", "CONFIRMED")
        assert result["allowed"] is False
        assert "not a legal transition" in result["reason"]

    def test_backward_step_rejected(self):
        result = can_transition("VALIDATED", "TESTING")
        assert result["allowed"] is False

    def test_any_non_terminal_state_can_reject(self):
        for state in ("SUSPECTED", "TESTING", "VALIDATED", "CONFIRMED"):
            result = can_transition(state, "REJECTED")
            assert result["allowed"] is True, f"{state} -> REJECTED should be legal"

    def test_rejected_is_terminal(self):
        result = can_transition("REJECTED", "SUSPECTED")
        assert result["allowed"] is False

    def test_report_ready_is_terminal(self):
        result = can_transition("REPORT_READY", "CONFIRMED")
        assert result["allowed"] is False

    def test_unknown_current_state_rejected(self):
        result = can_transition("NOT_A_STATE", "TESTING")
        assert result["allowed"] is False
        assert "not a known state" in result["reason"]

    def test_unknown_next_state_rejected(self):
        result = can_transition("SUSPECTED", "NOT_A_STATE")
        assert result["allowed"] is False
        assert "not a known state" in result["reason"]

    def test_confirmed_without_verdict_blocked(self):
        result = can_transition("VALIDATED", "CONFIRMED")
        assert result["allowed"] is False
        assert "weak evidence cannot become CONFIRMED" in result["reason"]

    def test_confirmed_with_weak_verdict_blocked(self):
        result = can_transition("VALIDATED", "CONFIRMED", {"verdict": "WEAK"})
        assert result["allowed"] is False

    def test_confirmed_with_reject_verdict_blocked(self):
        result = can_transition("VALIDATED", "CONFIRMED", {"verdict": "REJECT"})
        assert result["allowed"] is False

    def test_confirmed_with_strong_verdict_allowed(self, tmp_path):
        evidence = _confirmed_evidence(tmp_path)
        result = can_transition("VALIDATED", "CONFIRMED", evidence)
        assert result["allowed"] is True

    # ── HIGH-severity fix: bare verdict/reproducible strings are no longer
    # sufficient on their own -- a persisted, hash-bound report artifact is
    # now required too. These prove the specific gap the review found
    # (a calling agent could satisfy the gate with a bare string) is closed.

    def test_confirmed_strong_verdict_without_artifact_blocked(self):
        result = can_transition("VALIDATED", "CONFIRMED", {"verdict": "STRONG"})
        assert result["allowed"] is False
        assert "persisted validation report" in result["reason"]

    def test_confirmed_artifact_missing_file_blocked(self, tmp_path):
        evidence = {
            "verdict": "STRONG",
            "validation_report_path": str(tmp_path / "does_not_exist.json"),
            "validation_report_hash": "0" * 64,
        }
        result = can_transition("VALIDATED", "CONFIRMED", evidence)
        assert result["allowed"] is False
        assert "not found" in result["reason"]

    def test_confirmed_artifact_hash_mismatch_blocked(self, tmp_path):
        evidence = {"verdict": "STRONG", **_validation_report_evidence(tmp_path)}
        # Tamper with the file after the hash was recorded -- the exact
        # "swapped/edited artifact" scenario this fix exists to catch.
        Path(evidence["validation_report_path"]).write_text('{"overall_pass": true, "tampered": true}')
        result = can_transition("VALIDATED", "CONFIRMED", evidence)
        assert result["allowed"] is False
        assert "hash mismatch" in result["reason"]

    def test_confirmed_artifact_overall_pass_false_blocked(self, tmp_path):
        evidence = {"verdict": "STRONG", **_validation_report_evidence(tmp_path, overall_pass=False)}
        result = can_transition("VALIDATED", "CONFIRMED", evidence)
        assert result["allowed"] is False
        assert "overall_pass" in result["reason"]

    # ── Live-verification fix: validation_core.py's gates are entirely
    # self-reported booleans (gate3's curl_poc is only checked for being
    # non-blank, never executed) -- a persisted validation report alone is
    # not proof the bug is real. CONFIRMED now ALSO requires a
    # self_critique.py artifact whose reproducibility check (real, live,
    # twice-replayed HTTP reproduction) specifically passed.

    def test_confirmed_with_validation_report_but_no_self_critique_blocked(self, tmp_path):
        evidence = {"verdict": "STRONG", **_validation_report_evidence(tmp_path)}
        result = can_transition("VALIDATED", "CONFIRMED", evidence)
        assert result["allowed"] is False
        assert "persisted self-critique report" in result["reason"]

    def test_confirmed_self_critique_artifact_missing_file_blocked(self, tmp_path):
        evidence = {
            "verdict": "STRONG",
            **_validation_report_evidence(tmp_path),
            "self_critique_report_path": str(tmp_path / "does_not_exist.json"),
            "self_critique_report_hash": "0" * 64,
        }
        result = can_transition("VALIDATED", "CONFIRMED", evidence)
        assert result["allowed"] is False
        assert "not found" in result["reason"]

    def test_confirmed_self_critique_artifact_hash_mismatch_blocked(self, tmp_path):
        evidence = _confirmed_evidence(tmp_path)
        Path(evidence["self_critique_report_path"]).write_text(
            '{"overall": "pass", "details": {"reproducibility": {"status": "pass"}}, "tampered": true}'
        )
        result = can_transition("VALIDATED", "CONFIRMED", evidence)
        assert result["allowed"] is False
        assert "hash mismatch" in result["reason"]

    def test_confirmed_reproducibility_block_status_blocked(self, tmp_path):
        # A self-critique artifact exists and is even hash-valid, but its
        # reproducibility check itself did not pass (e.g. the live replay
        # was non-reproducible or unverifiable) -- must still block
        # CONFIRMED even though the OTHER three self-critique checks, or
        # the "overall" rollup, might independently read "warn".
        evidence = _confirmed_evidence(tmp_path, reproducibility_status="block")
        result = can_transition("VALIDATED", "CONFIRMED", evidence)
        assert result["allowed"] is False
        assert "live-reproducibility check failed" in result["reason"]

    def test_confirmed_with_both_artifacts_and_passing_reproducibility_allowed(self, tmp_path):
        evidence = _confirmed_evidence(tmp_path)
        result = can_transition("VALIDATED", "CONFIRMED", evidence)
        assert result["allowed"] is True

    def test_report_ready_without_reproducible_blocked(self):
        # Phase 7: CONFIRMED must pass through SELF_CRITIQUED first.
        result = can_transition("SELF_CRITIQUED", "REPORT_READY")
        assert result["allowed"] is False
        assert "missing reproduction blocks REPORT_READY" in result["reason"]

    def test_report_ready_with_reproducible_false_blocked(self):
        result = can_transition("SELF_CRITIQUED", "REPORT_READY", {"reproducible": False})
        assert result["allowed"] is False

    def test_report_ready_with_reproducible_true_allowed(self, tmp_path):
        evidence = {"reproducible": True, **_self_critique_report_evidence(tmp_path)}
        result = can_transition("SELF_CRITIQUED", "REPORT_READY", evidence)
        assert result["allowed"] is True

    def test_report_ready_reproducible_without_artifact_blocked(self):
        result = can_transition("SELF_CRITIQUED", "REPORT_READY", {"reproducible": True})
        assert result["allowed"] is False
        assert "persisted self-critique report" in result["reason"]

    def test_report_ready_artifact_overall_block_blocked(self, tmp_path):
        # A self-critique report whose overall is "block" (not pass/warn)
        # must not satisfy REPORT_READY even with a valid hash-bound artifact.
        evidence = {"reproducible": True, **_self_critique_report_evidence(tmp_path, overall="block")}
        result = can_transition("SELF_CRITIQUED", "REPORT_READY", evidence)
        assert result["allowed"] is False
        assert "overall" in result["reason"]

    def test_report_ready_artifact_warn_allowed(self, tmp_path):
        evidence = {"reproducible": True, **_self_critique_report_evidence(tmp_path, overall="warn")}
        result = can_transition("SELF_CRITIQUED", "REPORT_READY", evidence)
        assert result["allowed"] is True

    # Phase 7 — the gate itself: CONFIRMED can no longer reach REPORT_READY
    # directly; SELF_CRITIQUED sits in between and requires the self-critique
    # gate to have actually run and cleared (pass or warn — not block).

    def test_confirmed_to_report_ready_directly_no_longer_legal(self):
        result = can_transition("CONFIRMED", "REPORT_READY", {"reproducible": True})
        assert result["allowed"] is False
        assert "not a legal transition" in result["reason"]

    def test_self_critiqued_without_evidence_blocked(self):
        result = can_transition("CONFIRMED", "SELF_CRITIQUED")
        assert result["allowed"] is False
        assert "self-critique gate must run" in result["reason"]

    def test_self_critiqued_with_block_overall_blocked(self):
        result = can_transition("CONFIRMED", "SELF_CRITIQUED", {"self_critique_overall": "block"})
        assert result["allowed"] is False

    def test_self_critiqued_with_pass_overall_allowed(self):
        result = can_transition("CONFIRMED", "SELF_CRITIQUED", {"self_critique_overall": "pass"})
        assert result["allowed"] is True

    def test_self_critiqued_with_warn_overall_allowed(self):
        result = can_transition("CONFIRMED", "SELF_CRITIQUED", {"self_critique_overall": "warn"})
        assert result["allowed"] is True

    def test_all_states_covered_by_transition_table(self):
        # Sanity check that FINDING_STATES and the transition rules agree.
        from memory.finding_state import ALLOWED_TRANSITIONS
        assert set(ALLOWED_TRANSITIONS.keys()) == set(FINDING_STATES)


class TestFindingStateCLI:
    """The CLI is how bash-only agents reach this module (module docstring) —
    --self-critique-overall must actually work end to end, not just the
    underlying can_transition()/advance() functions."""

    def test_can_transition_cli_pass_allows(self, monkeypatch, capsys):
        import sys as _sys
        from memory.finding_state import main

        monkeypatch.setattr(_sys, "argv", [
            "finding_state.py", "can-transition",
            "--current-state", "CONFIRMED", "--next-state", "SELF_CRITIQUED",
            "--self-critique-overall", "pass",
        ])
        assert main() == 0
        out = json.loads(capsys.readouterr().out)
        assert out["allowed"] is True

    def test_can_transition_cli_missing_overall_blocks(self, monkeypatch, capsys):
        import sys as _sys
        from memory.finding_state import main

        monkeypatch.setattr(_sys, "argv", [
            "finding_state.py", "can-transition",
            "--current-state", "CONFIRMED", "--next-state", "SELF_CRITIQUED",
        ])
        assert main() == 0
        out = json.loads(capsys.readouterr().out)
        assert out["allowed"] is False
        assert "self-critique gate must run" in out["reason"]

    def test_advance_cli_persists_self_critique_overall(self, monkeypatch, capsys, finding_states_path, tmp_path):
        import sys as _sys
        from memory.finding_state import main

        validation_evidence = _validation_report_evidence(tmp_path)
        sc_evidence = _self_critique_report_evidence(tmp_path)
        for state, extra in (
            ("SUSPECTED", []), ("TESTING", []), ("VALIDATED", []),
            ("CONFIRMED", [
                "--verdict", "STRONG",
                "--validation-report-path", validation_evidence["validation_report_path"],
                "--validation-report-hash", validation_evidence["validation_report_hash"],
                "--self-critique-report-path", sc_evidence["self_critique_report_path"],
                "--self-critique-report-hash", sc_evidence["self_critique_report_hash"],
            ]),
        ):
            monkeypatch.setattr(_sys, "argv", [
                "finding_state.py", "advance",
                "--target", "a.com", "--vuln-class", "idor", "--endpoint", "/api/x",
                "--state", state, "--memory-dir", str(finding_states_path.parent),
                *extra,
            ])
            assert main() == 0
            capsys.readouterr()

        monkeypatch.setattr(_sys, "argv", [
            "finding_state.py", "advance",
            "--target", "a.com", "--vuln-class", "idor", "--endpoint", "/api/x",
            "--state", "SELF_CRITIQUED", "--self-critique-overall", "warn",
            "--memory-dir", str(finding_states_path.parent),
        ])
        assert main() == 0
        out = json.loads(capsys.readouterr().out)
        assert out["advanced"] is True
        assert out["entry"]["self_critique_overall"] == "warn"

    def test_can_transition_cli_confirmed_artifact_flags_work_end_to_end(self, monkeypatch, capsys, tmp_path):
        """The --validation-report-path/--validation-report-hash CLI flags
        must actually thread through to the real verify_report_artifact()
        check, not just exist as unused argparse options."""
        import sys as _sys
        from memory.finding_state import main

        evidence = _validation_report_evidence(tmp_path)
        sc_evidence = _self_critique_report_evidence(tmp_path)
        monkeypatch.setattr(_sys, "argv", [
            "finding_state.py", "can-transition",
            "--current-state", "VALIDATED", "--next-state", "CONFIRMED",
            "--verdict", "STRONG",
            "--validation-report-path", evidence["validation_report_path"],
            "--validation-report-hash", evidence["validation_report_hash"],
            "--self-critique-report-path", sc_evidence["self_critique_report_path"],
            "--self-critique-report-hash", sc_evidence["self_critique_report_hash"],
        ])
        assert main() == 0
        out = json.loads(capsys.readouterr().out)
        assert out["allowed"] is True

    def test_can_transition_cli_confirmed_bad_hash_blocks(self, monkeypatch, capsys, tmp_path):
        import sys as _sys
        from memory.finding_state import main

        evidence = _validation_report_evidence(tmp_path)
        monkeypatch.setattr(_sys, "argv", [
            "finding_state.py", "can-transition",
            "--current-state", "VALIDATED", "--next-state", "CONFIRMED",
            "--verdict", "STRONG",
            "--validation-report-path", evidence["validation_report_path"],
            "--validation-report-hash", "f" * 64,
        ])
        assert main() == 0
        out = json.loads(capsys.readouterr().out)
        assert out["allowed"] is False
        assert "hash mismatch" in out["reason"]


class TestReportArtifactBinding:
    """Direct unit tests for write_report_artifact()/verify_report_artifact()
    -- the primitives the CONFIRMED/REPORT_READY gates above are built on."""

    def test_write_then_verify_round_trips(self, tmp_path):
        report = {"overall_pass": True, "gate1_is_real": {"passed": True}}
        path = tmp_path / "report.json"
        report_hash = write_report_artifact(report, path)
        assert path.exists()
        assert len(report_hash) == 64  # sha256 hex digest length

        result = verify_report_artifact(path, report_hash, {"overall_pass": True})
        assert result["ok"] is True

    def test_verify_missing_file(self, tmp_path):
        result = verify_report_artifact(tmp_path / "nope.json", "a" * 64, {})
        assert result["ok"] is False
        assert "not found" in result["reason"]

    def test_verify_hash_mismatch(self, tmp_path):
        path = tmp_path / "report.json"
        real_hash = write_report_artifact({"overall_pass": True}, path)
        result = verify_report_artifact(path, "0" * 64, {"overall_pass": True})
        assert result["ok"] is False
        assert "hash mismatch" in result["reason"]
        assert real_hash != "0" * 64

    def test_verify_detects_tampering_after_hash_recorded(self, tmp_path):
        path = tmp_path / "report.json"
        original_hash = write_report_artifact({"overall_pass": True}, path)
        # Same file path, contents swapped after the hash was captured.
        path.write_text('{"overall_pass": true, "extra": "swapped"}')
        result = verify_report_artifact(path, original_hash, {"overall_pass": True})
        assert result["ok"] is False
        assert "hash mismatch" in result["reason"]

    def test_verify_invalid_json(self, tmp_path):
        import hashlib

        path = tmp_path / "report.json"
        path.write_bytes(b"not json")
        actual_hash = hashlib.sha256(b"not json").hexdigest()
        result = verify_report_artifact(path, actual_hash, {})
        assert result["ok"] is False
        assert "not valid JSON" in result["reason"]

    def test_verify_missing_required_field(self, tmp_path):
        path = tmp_path / "report.json"
        report_hash = write_report_artifact({"unrelated": "field"}, path)
        result = verify_report_artifact(path, report_hash, {"overall_pass": True})
        assert result["ok"] is False
        assert "missing field" in result["reason"]

    def test_verify_field_wrong_value(self, tmp_path):
        path = tmp_path / "report.json"
        report_hash = write_report_artifact({"overall_pass": False}, path)
        result = verify_report_artifact(path, report_hash, {"overall_pass": True})
        assert result["ok"] is False
        assert "expected True" in result["reason"]

    def test_verify_set_of_acceptable_values(self, tmp_path):
        path = tmp_path / "report.json"
        report_hash = write_report_artifact({"overall": "warn"}, path)
        result = verify_report_artifact(path, report_hash, {"overall": {"pass", "warn"}})
        assert result["ok"] is True

    def test_advance_persists_artifact_reference_in_audit_trail(self, finding_states_path, tmp_path):
        """The append-only finding_states.jsonl log itself must show WHICH
        artifact backed a CONFIRMED transition, not just a bare verdict --
        otherwise a later audit can't tell what was actually checked."""
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        db.advance("a.com", "idor", "/api/x", "VALIDATED")
        artifact_evidence = _validation_report_evidence(tmp_path)
        sc_evidence = _self_critique_report_evidence(tmp_path)
        entry = db.advance(
            "a.com", "idor", "/api/x", "CONFIRMED",
            evidence={"verdict": "STRONG", **artifact_evidence, **sc_evidence},
        )
        assert entry["validation_report_path"] == artifact_evidence["validation_report_path"]
        assert entry["validation_report_hash"] == artifact_evidence["validation_report_hash"]
        persisted = db.history("a.com", "idor", "/api/x")[-1]
        assert persisted["validation_report_hash"] == artifact_evidence["validation_report_hash"]


class TestTransition:

    def test_legal_transition_does_not_raise(self):
        transition("SUSPECTED", "TESTING")  # should not raise

    def test_illegal_transition_raises(self):
        with pytest.raises(FindingStateError, match="not a legal transition"):
            transition("SUSPECTED", "CONFIRMED")

    def test_weak_evidence_raises_on_confirm(self):
        with pytest.raises(FindingStateError, match="weak evidence cannot become CONFIRMED"):
            transition("VALIDATED", "CONFIRMED", {"verdict": "WEAK"})

    def test_missing_reproduction_raises_on_report_ready(self):
        with pytest.raises(FindingStateError, match="missing reproduction blocks REPORT_READY"):
            transition("SELF_CRITIQUED", "REPORT_READY")

    def test_confirmed_to_report_ready_directly_raises(self):
        with pytest.raises(FindingStateError, match="not a legal transition"):
            transition("CONFIRMED", "REPORT_READY", {"reproducible": True})

    def test_missing_self_critique_raises_on_self_critiqued(self):
        with pytest.raises(FindingStateError, match="self-critique gate must run"):
            transition("CONFIRMED", "SELF_CRITIQUED")


class TestFindingStateDB:

    def test_save_and_read(self, finding_states_path, sample_finding_state_entry):
        db = FindingStateDB(finding_states_path)
        assert db.save(sample_finding_state_entry) is True
        assert finding_states_path.exists()
        entries = db.read_all()
        assert len(entries) == 1
        assert entries[0]["state"] == "TESTING"

    def test_read_all_on_missing_file(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        assert db.read_all() == []

    def test_current_state_none_when_no_history(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        assert db.current_state("a.com", "idor", "/api/x") is None

    def test_advance_first_call_must_be_suspected(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        with pytest.raises(FindingStateError, match="must register it as SUSPECTED"):
            db.advance("a.com", "idor", "/api/x", "TESTING")

    def test_advance_registers_suspected(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        entry = db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        assert entry["state"] == "SUSPECTED"
        assert db.current_state("a.com", "idor", "/api/x") == "SUSPECTED"

    def test_full_lifecycle_advances_in_order(self, finding_states_path, tmp_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        db.advance("a.com", "idor", "/api/x", "VALIDATED")
        db.advance("a.com", "idor", "/api/x", "CONFIRMED",
                   evidence=_confirmed_evidence(tmp_path))
        db.advance("a.com", "idor", "/api/x", "SELF_CRITIQUED", evidence={"self_critique_overall": "pass"})
        db.advance("a.com", "idor", "/api/x", "REPORT_READY",
                   evidence={"reproducible": True, **_self_critique_report_evidence(tmp_path)})
        assert db.current_state("a.com", "idor", "/api/x") == "REPORT_READY"

    def test_skip_ahead_via_advance_raises_and_does_not_persist(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        with pytest.raises(FindingStateError):
            db.advance("a.com", "idor", "/api/x", "CONFIRMED")
        # Still SUSPECTED -- the illegal attempt must not have been persisted.
        assert db.current_state("a.com", "idor", "/api/x") == "SUSPECTED"
        assert len(db.history("a.com", "idor", "/api/x")) == 1

    def test_confirm_without_strong_verdict_raises_and_does_not_persist(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        db.advance("a.com", "idor", "/api/x", "VALIDATED")
        with pytest.raises(FindingStateError, match="weak evidence cannot become CONFIRMED"):
            db.advance("a.com", "idor", "/api/x", "CONFIRMED", evidence={"verdict": "WEAK"})
        assert db.current_state("a.com", "idor", "/api/x") == "VALIDATED"

    def test_report_ready_without_reproduction_raises_and_does_not_persist(self, finding_states_path, tmp_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        db.advance("a.com", "idor", "/api/x", "VALIDATED")
        db.advance("a.com", "idor", "/api/x", "CONFIRMED",
                   evidence=_confirmed_evidence(tmp_path))
        db.advance("a.com", "idor", "/api/x", "SELF_CRITIQUED", evidence={"self_critique_overall": "pass"})
        with pytest.raises(FindingStateError, match="missing reproduction blocks REPORT_READY"):
            db.advance("a.com", "idor", "/api/x", "REPORT_READY")
        assert db.current_state("a.com", "idor", "/api/x") == "SELF_CRITIQUED"

    def test_report_ready_directly_from_confirmed_raises_and_does_not_persist(self, finding_states_path, tmp_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        db.advance("a.com", "idor", "/api/x", "VALIDATED")
        db.advance("a.com", "idor", "/api/x", "CONFIRMED",
                   evidence=_confirmed_evidence(tmp_path))
        with pytest.raises(FindingStateError, match="not a legal transition"):
            db.advance("a.com", "idor", "/api/x", "REPORT_READY", evidence={"reproducible": True})
        assert db.current_state("a.com", "idor", "/api/x") == "CONFIRMED"

    def test_self_critiqued_without_gate_evidence_raises_and_does_not_persist(self, finding_states_path, tmp_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        db.advance("a.com", "idor", "/api/x", "VALIDATED")
        db.advance("a.com", "idor", "/api/x", "CONFIRMED",
                   evidence=_confirmed_evidence(tmp_path))
        with pytest.raises(FindingStateError, match="self-critique gate must run"):
            db.advance("a.com", "idor", "/api/x", "SELF_CRITIQUED", evidence={"self_critique_overall": "block"})
        assert db.current_state("a.com", "idor", "/api/x") == "CONFIRMED"

    def test_history_ordered_oldest_first(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        hist = db.history("a.com", "idor", "/api/x")
        assert [e["state"] for e in hist] == ["SUSPECTED", "TESTING"]

    def test_history_matches_normalized_endpoint_shape(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/users/482/orders", "SUSPECTED")
        hist = db.history("a.com", "idor", "/api/users/9107/orders")
        assert len(hist) == 1

    def test_history_excludes_other_targets(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        assert db.history("other.com", "idor", "/api/x") == []

    def test_history_excludes_other_vuln_classes(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        assert db.history("a.com", "xss", "/api/x") == []

    def test_independent_findings_tracked_separately(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        db.advance("a.com", "idor", "/api/x", "TESTING")
        db.advance("a.com", "xss", "/api/y", "SUSPECTED")
        assert db.current_state("a.com", "idor", "/api/x") == "TESTING"
        assert db.current_state("a.com", "xss", "/api/y") == "SUSPECTED"

    def test_rejected_reachable_from_any_non_terminal_state(self, finding_states_path):
        db = FindingStateDB(finding_states_path)
        db.advance("a.com", "idor", "/api/x", "SUSPECTED")
        entry = db.advance("a.com", "idor", "/api/x", "REJECTED")
        assert entry["state"] == "REJECTED"
        assert db.current_state("a.com", "idor", "/api/x") == "REJECTED"


class TestSelfLearning:
    """Phase 7 -- REJECTED/CONFIRMED auto-save to failed_patterns.jsonl /
    patterns.jsonl, no manual /remember step required."""

    def test_rejected_with_technique_writes_failed_pattern(self, tmp_hunt_dir):
        db = FindingStateDB(tmp_hunt_dir / "finding_states.jsonl")
        db.advance("a.com", "ssrf", "/webhook", "SUSPECTED")
        entry = db.advance(
            "a.com", "ssrf", "/webhook", "REJECTED",
            technique="webhook_url_param", tech_stack=["express", "aws"], reason="egress filtered",
        )
        assert entry["auto_learned"] == {"file": "failed_patterns.jsonl", "saved": True}

        failed_path = tmp_hunt_dir / "failed_patterns.jsonl"
        assert failed_path.exists()
        from memory.vuln_intelligence import FailedPatternDB
        saved = FailedPatternDB(failed_path).read_all()
        assert len(saved) == 1
        assert saved[0]["technique"] == "webhook_url_param"
        assert saved[0]["reason"] == "egress filtered"
        assert saved[0]["tech_stack"] == ["express", "aws"]

    def test_confirmed_with_technique_writes_pattern(self, tmp_hunt_dir, tmp_path):
        db = FindingStateDB(tmp_hunt_dir / "finding_states.jsonl")
        db.advance("b.com", "idor", "/api/orders/482", "SUSPECTED")
        db.advance("b.com", "idor", "/api/orders/482", "TESTING")
        db.advance("b.com", "idor", "/api/orders/482", "VALIDATED")
        entry = db.advance(
            "b.com", "idor", "/api/orders/482", "CONFIRMED",
            evidence=_confirmed_evidence(tmp_path),
            technique="numeric_id_swap", tech_stack=["express", "postgresql"], payout=1500,
        )
        assert entry["auto_learned"] == {"file": "patterns.jsonl", "saved": True}

        from memory.pattern_db import PatternDB
        saved = PatternDB(tmp_hunt_dir / "patterns.jsonl").read_all()
        assert len(saved) == 1
        assert saved[0]["technique"] == "numeric_id_swap"
        assert saved[0]["payout"] == 1500

    def test_rejected_without_technique_writes_nothing(self, tmp_hunt_dir):
        db = FindingStateDB(tmp_hunt_dir / "finding_states.jsonl")
        db.advance("c.com", "xss", "/search", "SUSPECTED")
        entry = db.advance("c.com", "xss", "/search", "REJECTED")
        assert "auto_learned" not in entry
        assert not (tmp_hunt_dir / "failed_patterns.jsonl").exists()

    def test_confirmed_without_tech_stack_writes_nothing(self, tmp_hunt_dir, tmp_path):
        db = FindingStateDB(tmp_hunt_dir / "finding_states.jsonl")
        db.advance("d.com", "idor", "/api/x", "SUSPECTED")
        db.advance("d.com", "idor", "/api/x", "TESTING")
        db.advance("d.com", "idor", "/api/x", "VALIDATED")
        entry = db.advance(
            "d.com", "idor", "/api/x", "CONFIRMED",
            evidence=_confirmed_evidence(tmp_path),
            technique="numeric_id_swap",
        )
        assert "auto_learned" not in entry
        assert not (tmp_hunt_dir / "patterns.jsonl").exists()

    def test_non_terminal_transition_never_auto_learns(self, tmp_hunt_dir):
        db = FindingStateDB(tmp_hunt_dir / "finding_states.jsonl")
        entry = db.advance(
            "e.com", "idor", "/api/x", "SUSPECTED",
            technique="numeric_id_swap", tech_stack=["express"],
        )
        assert "auto_learned" not in entry
        entry = db.advance(
            "e.com", "idor", "/api/x", "TESTING",
            technique="numeric_id_swap", tech_stack=["express"],
        )
        assert "auto_learned" not in entry

    def test_auto_learn_false_suppresses_write_even_with_technique(self, tmp_hunt_dir):
        db = FindingStateDB(tmp_hunt_dir / "finding_states.jsonl")
        db.advance("f.com", "ssrf", "/webhook", "SUSPECTED")
        entry = db.advance(
            "f.com", "ssrf", "/webhook", "REJECTED",
            technique="webhook_url_param", tech_stack=["express"], auto_learn=False,
        )
        assert "auto_learned" not in entry
        assert not (tmp_hunt_dir / "failed_patterns.jsonl").exists()

    def test_illegal_transition_does_not_auto_learn(self, tmp_hunt_dir):
        db = FindingStateDB(tmp_hunt_dir / "finding_states.jsonl")
        db.advance("g.com", "idor", "/api/x", "SUSPECTED")
        with pytest.raises(FindingStateError):
            db.advance(
                "g.com", "idor", "/api/x", "CONFIRMED",
                technique="numeric_id_swap", tech_stack=["express"],
            )
        assert not (tmp_hunt_dir / "patterns.jsonl").exists()
