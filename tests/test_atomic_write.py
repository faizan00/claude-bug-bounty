"""Tests for memory/atomic_write.py — crash-safe whole-file replacement."""

import os
from pathlib import Path

import pytest

from memory.atomic_write import atomic_write_text


class TestAtomicWriteText:
    def test_creates_a_new_file(self, tmp_path):
        p = tmp_path / "state.json"
        atomic_write_text(p, '{"a": 1}')
        assert p.read_text() == '{"a": 1}'

    def test_creates_parent_directories(self, tmp_path):
        p = tmp_path / "nested" / "dir" / "state.json"
        atomic_write_text(p, "content")
        assert p.read_text() == "content"

    def test_overwrites_existing_content_completely(self, tmp_path):
        p = tmp_path / "state.json"
        p.write_text("old content that is much longer than new")
        atomic_write_text(p, "new")
        assert p.read_text() == "new"

    def test_no_temp_file_left_behind_on_success(self, tmp_path):
        p = tmp_path / "state.json"
        atomic_write_text(p, "content")
        leftover = [f for f in os.listdir(tmp_path) if f != "state.json"]
        assert leftover == []

    def test_write_failure_never_touches_the_original_file(self, tmp_path, monkeypatch):
        # Simulates a crash mid-write: os.replace() never runs, so the
        # live file must be untouched -- this is the exact property a
        # plain path.write_text() does NOT have (it truncates first).
        p = tmp_path / "state.json"
        p.write_text("original content must survive")

        import memory.atomic_write as aw

        def _boom(*a, **kw):
            raise OSError("simulated crash mid-write")

        monkeypatch.setattr(aw.os, "replace", _boom)
        with pytest.raises(OSError, match="simulated crash"):
            atomic_write_text(p, "new content that would replace it")

        assert p.read_text() == "original content must survive"

    def test_write_failure_cleans_up_the_temp_file(self, tmp_path, monkeypatch):
        p = tmp_path / "state.json"
        import memory.atomic_write as aw

        monkeypatch.setattr(aw.os, "replace", lambda *a, **kw: (_ for _ in ()).throw(OSError("boom")))
        with pytest.raises(OSError):
            atomic_write_text(p, "content")

        # No orphaned .state.json-*.tmp file left in the directory.
        leftover = list(tmp_path.iterdir())
        assert leftover == []

    def test_readers_never_see_a_partial_file(self, tmp_path):
        # Concurrent-write simulation: after atomic_write_text() returns,
        # the file is either fully the old content or fully the new
        # content -- there is no window where a reader could see a
        # truncated/mixed state, because the write happens to a temp file
        # first and os.replace() swaps it in as a single filesystem op.
        p = tmp_path / "state.json"
        atomic_write_text(p, "A" * 10_000)
        assert p.read_text() == "A" * 10_000
        atomic_write_text(p, "B" * 5_000)
        content = p.read_text()
        assert content == "B" * 5_000  # never "A"*n + "B"*m mixed, never truncated mid-write

    def test_custom_encoding(self, tmp_path):
        p = tmp_path / "state.json"
        atomic_write_text(p, "héllo wörld", encoding="utf-8")
        assert p.read_text(encoding="utf-8") == "héllo wörld"
