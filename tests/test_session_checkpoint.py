"""Tests for memory/object_model.py's Part 3 (stateful session checkpoint).

Covers the acceptance list: save_session()/load_session() round-trip, and
no raw credentials in the checkpoint -- reusing tools/auth_session.py's
AuthSession rather than reinventing session management.
"""

import json

import pytest

from memory import object_model as om
from memory.identity import capability_id, endpoint_id, object_id
from tools.auth_session import AuthSession


SECRET_COOKIE_VALUE = "sid=super-secret-raw-session-cookie-value-should-never-be-persisted"


def _auth_session():
    s = AuthSession()
    s.add_cookie(SECRET_COOKIE_VALUE)
    return s


class TestMakeCheckpoint:
    def test_shape_has_the_five_required_fields(self):
        cp = om.make_checkpoint(
            workflow_state={"step": "invite_sent"},
            reachable_objects=[object_id("Document", "1")],
            reachable_capabilities=[capability_id("ROLE_ADMIN")],
            auth_session=_auth_session(),
        )
        assert set(cp) >= {
            "version", "workflow_state", "reachable_objects",
            "reachable_capabilities", "fingerprinted_session_reference",
        }
        assert cp["version"] == om.CHECKPOINT_VERSION

    def test_fingerprinted_session_reference_is_the_auth_session_hash(self):
        session = _auth_session()
        cp = om.make_checkpoint({}, [], [], auth_session=session)
        assert cp["fingerprinted_session_reference"] == session.session_id()
        assert cp["fingerprinted_session_reference"] != SECRET_COOKIE_VALUE

    def test_no_auth_session_gives_none_reference(self):
        cp = om.make_checkpoint({}, [], [], auth_session=None)
        assert cp["fingerprinted_session_reference"] is None

    def test_empty_auth_session_gives_none_reference(self):
        cp = om.make_checkpoint({}, [], [], auth_session=AuthSession())
        assert cp["fingerprinted_session_reference"] is None

    def test_non_identity_reachable_object_rejected(self):
        with pytest.raises(ValueError):
            om.make_checkpoint({}, ["not-an-identity-ref"], [], auth_session=None)

    def test_non_identity_reachable_capability_rejected(self):
        with pytest.raises(ValueError):
            om.make_checkpoint({}, [], [SECRET_COOKIE_VALUE], auth_session=None)

    def test_valid_identity_refs_accepted(self):
        cp = om.make_checkpoint(
            {}, [object_id("Document", "1"), endpoint_id("/api/v1/x")],
            [capability_id("ROLE_ADMIN")], auth_session=None,
        )
        assert len(cp["reachable_objects"]) == 2
        assert len(cp["reachable_capabilities"]) == 1


class TestNoRawCredentialsInCheckpoint:
    def test_serialized_checkpoint_never_contains_the_raw_cookie_value(self):
        session = _auth_session()
        cp = om.make_checkpoint(
            workflow_state={"step": "logged_in"},
            reachable_objects=[object_id("Document", "1")],
            reachable_capabilities=[],
            auth_session=session,
        )
        serialized = json.dumps(cp)
        assert SECRET_COOKIE_VALUE not in serialized
        assert "super-secret-raw-session-cookie-value" not in serialized

    def test_saved_file_never_contains_the_raw_cookie_value(self, tmp_path):
        session = _auth_session()
        cp = om.make_checkpoint({}, [], [], auth_session=session)
        path = om.save_session(cp, tmp_path / "checkpoint.json")
        raw_file_text = open(path).read()
        assert SECRET_COOKIE_VALUE not in raw_file_text


class TestSaveLoadRoundTrip:
    def test_round_trip_is_equal(self, tmp_path):
        session = _auth_session()
        cp = om.make_checkpoint(
            workflow_state={"step": "invite_sent", "next_action": "accept_invite"},
            reachable_objects=[object_id("Document", "1"), object_id("Document", "2")],
            reachable_capabilities=[capability_id("ROLE_ADMIN")],
            auth_session=session,
            metadata={"target": "t.example"},
        )
        path = om.save_session(cp, tmp_path / "sessions" / "t.example.json")
        loaded = om.load_session(path)
        assert loaded == cp

    def test_load_rejects_unsupported_version(self, tmp_path):
        path = tmp_path / "checkpoint.json"
        path.write_text(json.dumps({"version": 999, "workflow_state": {}}))
        with pytest.raises(ValueError, match="unsupported checkpoint version"):
            om.load_session(path)

    def test_save_creates_parent_dirs(self, tmp_path):
        cp = om.make_checkpoint({}, [], [], auth_session=None)
        path = om.save_session(cp, tmp_path / "a" / "b" / "c.json")
        assert (tmp_path / "a" / "b" / "c.json").exists()

    def test_crash_mid_write_never_corrupts_the_prior_checkpoint(self, tmp_path, monkeypatch):
        # Phase 5 (state recovery): this checkpoint accumulates real
        # --establish/--probe workflow_state across a multi-step
        # business-logic test (business_logic_probe.py writes one after
        # EVERY call) -- a crash mid-write must never corrupt/empty the
        # prior checkpoint /pickup reads back to show where a killed
        # multi-step test left off.
        path = tmp_path / "t.example__invite_flow.json"
        cp1 = om.make_checkpoint(
            workflow_state={"step": "invite_sent"}, reachable_objects=[],
            reachable_capabilities=[], auth_session=None,
        )
        om.save_session(cp1, path)
        original_bytes = path.read_bytes()

        import memory.atomic_write as aw
        monkeypatch.setattr(aw.os, "replace", lambda *a, **kw: (_ for _ in ()).throw(OSError("simulated crash")))
        cp2 = om.make_checkpoint(
            workflow_state={"step": "invite_accepted"}, reachable_objects=[],
            reachable_capabilities=[], auth_session=None,
        )
        with pytest.raises(OSError, match="simulated crash"):
            om.save_session(cp2, path)

        assert path.read_bytes() == original_bytes
        assert om.load_session(path) == cp1  # still the last GOOD checkpoint, not corrupted
