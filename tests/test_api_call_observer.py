"""Tests for memory/api_call_observer.py — Phase 7 Part A.

Covers the acceptance list from the phase brief:
  - zero observations when there's no cross-context value correlation
  - a real observation when two different authenticated sessions' requests
    share a concrete correlated value (here: the exact same request target)
  - never crashes on missing/malformed api-calls.json
"""

import json

from memory.api_call_observer import observe_from_api_calls
from memory.object_model import ObservationStore


def _write_calls(recon_dir, target, calls):
    d = recon_dir / target / "browser"
    d.mkdir(parents=True, exist_ok=True)
    (d / "api-calls.json").write_text(json.dumps(calls))


def _entry(url, method="GET", status=200, auth_fp="aaa"):
    return {
        "method": method,
        "url": url,
        "response_status": status,
        "request_headers_auth_fingerprint": {"authorization": auth_fp} if auth_fp else {},
        "trigger": "page_load",
    }


class TestNoOverInference:
    def test_single_actor_produces_zero_observations(self, tmp_path):
        _write_calls(tmp_path, "example.com", [
            _entry("https://example.com/api/orders/1", auth_fp="same-actor"),
            _entry("https://example.com/api/orders/1", auth_fp="same-actor"),
        ])
        store = ObservationStore(tmp_path / "observations.jsonl")
        result = observe_from_api_calls("example.com", tmp_path, store)
        assert result == []
        assert store.all() == []

    def test_different_urls_never_correlated(self, tmp_path):
        _write_calls(tmp_path, "example.com", [
            _entry("https://example.com/api/orders/1", auth_fp="actor-a"),
            _entry("https://example.com/api/orders/2", auth_fp="actor-b"),
        ])
        store = ObservationStore(tmp_path / "observations.jsonl")
        result = observe_from_api_calls("example.com", tmp_path, store)
        assert result == []

    def test_no_auth_fingerprint_excluded(self, tmp_path):
        _write_calls(tmp_path, "example.com", [
            _entry("https://example.com/api/orders/1", auth_fp=None),
            _entry("https://example.com/api/orders/1", auth_fp=None),
        ])
        store = ObservationStore(tmp_path / "observations.jsonl")
        result = observe_from_api_calls("example.com", tmp_path, store)
        assert result == []

    def test_non_2xx_excluded(self, tmp_path):
        _write_calls(tmp_path, "example.com", [
            _entry("https://example.com/api/orders/1", status=403, auth_fp="actor-a"),
            _entry("https://example.com/api/orders/1", status=403, auth_fp="actor-b"),
        ])
        store = ObservationStore(tmp_path / "observations.jsonl")
        result = observe_from_api_calls("example.com", tmp_path, store)
        assert result == []


class TestRealCorrelation:
    def test_two_distinct_actors_same_url_produces_observations(self, tmp_path):
        _write_calls(tmp_path, "example.com", [
            _entry("https://example.com/api/orders/42", auth_fp="actor-a"),
            _entry("https://example.com/api/orders/42", auth_fp="actor-b"),
        ])
        store = ObservationStore(tmp_path / "observations.jsonl")
        result = observe_from_api_calls("example.com", tmp_path, store)
        assert len(result) == 2
        subjects = {o["subject_id"] for o in result}
        assert len(subjects) == 2
        for obs in result:
            assert obs["event"] == "accessed"
            assert obs["relationship_type"] is None
            assert obs["evidence"][0]["type"] == "Observed-HTTP-Response"
            assert obs["object_id"] == result[0]["object_id"]
        assert len(store.all()) == 2

    def test_never_emits_establishing_event(self, tmp_path):
        _write_calls(tmp_path, "example.com", [
            _entry("https://example.com/api/orders/42", method="POST", auth_fp="actor-a"),
            _entry("https://example.com/api/orders/42", method="POST", auth_fp="actor-b"),
        ])
        store = ObservationStore(tmp_path / "observations.jsonl")
        result = observe_from_api_calls("example.com", tmp_path, store)
        assert all(o["event"] == "accessed" for o in result)


class TestNeverCrashes:
    def test_missing_file(self, tmp_path):
        store = ObservationStore(tmp_path / "observations.jsonl")
        assert observe_from_api_calls("nope.com", tmp_path, store) == []

    def test_malformed_json(self, tmp_path):
        d = tmp_path / "example.com" / "browser"
        d.mkdir(parents=True)
        (d / "api-calls.json").write_text("{not valid json")
        store = ObservationStore(tmp_path / "observations.jsonl")
        assert observe_from_api_calls("example.com", tmp_path, store) == []

    def test_json_not_a_list_or_expected_dict(self, tmp_path):
        d = tmp_path / "example.com" / "browser"
        d.mkdir(parents=True)
        (d / "api-calls.json").write_text(json.dumps({"unexpected": "shape"}))
        store = ObservationStore(tmp_path / "observations.jsonl")
        assert observe_from_api_calls("example.com", tmp_path, store) == []

    def test_entries_missing_fields(self, tmp_path):
        _write_calls(tmp_path, "example.com", [
            {"method": "GET"},
            {"url": "https://example.com/x"},
            {},
        ])
        store = ObservationStore(tmp_path / "observations.jsonl")
        assert observe_from_api_calls("example.com", tmp_path, store) == []
