"""Tests for tools/memory_gc.py — hunt-memory JSONL rotation reporting.

Covers the fix that closed a real coverage gap: ROTATABLE previously only
listed 3 of the 10 hunt-memory files that already have real per-write
rotation protection (memory/rotation.py's rotate_if_needed(), called from
inside PatternDB/FailedPatternDB/ChainDB/ReportOutcomeDB/HypothesisDB/
ExperimentDB/FindingStateDB/ObservationStore's own .save()/.record()) — so
`/memory-gc`'s report, --rotate, and --purge-backups all silently ignored
7 of them, and the session-end Stop-hook's blind `--rotate` call did too.
"""

import json

import pytest

from tools import memory_gc as mg


# The exact set of hunt-memory JSONL filenames real memory/*.py modules
# write through rotate_if_needed()-protected .save()/.record() calls, as
# of this fix. If a future module adds an 11th such file and this set
# isn't updated, TestRotatableCoversEveryKnownRotationProtectedFile below
# fails loudly instead of silently reintroducing the exact gap this test
# file exists to prevent.
_KNOWN_ROTATION_PROTECTED_FIXED_NAMES = {
    "audit.jsonl", "patterns.jsonl", "journal.jsonl", "failed_patterns.jsonl",
    "chains.jsonl", "report_outcomes.jsonl", "hypotheses.jsonl",
    "experiments.jsonl", "finding_states.jsonl",
}


class TestRotatableCoversEveryKnownRotationProtectedFile:

    def test_every_known_fixed_name_is_in_rotatable(self):
        assert _KNOWN_ROTATION_PROTECTED_FIXED_NAMES.issubset(set(mg.ROTATABLE))

    def test_object_model_dynamic_pattern_is_present(self):
        assert "object_model/*.jsonl" in mg.ROTATABLE


class TestFindTargets:

    def test_missing_root_returns_empty(self, tmp_path):
        assert mg._find_targets(tmp_path / "nope") == []

    def test_empty_dir_returns_empty(self, tmp_path):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        assert mg._find_targets(root) == []

    def test_unrelated_file_is_ignored(self, tmp_path):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        (root / "targets").mkdir()
        (root / "targets" / "acme.com.json").write_text("{}")
        assert mg._find_targets(root) == []

    @pytest.mark.parametrize("name", sorted(_KNOWN_ROTATION_PROTECTED_FIXED_NAMES))
    def test_each_fixed_name_is_found_at_any_depth(self, tmp_path, name):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        (root / name).write_text('{"a":1}\n')
        found = mg._find_targets(root)
        assert root / name in found

    def test_object_model_per_target_files_are_found(self, tmp_path):
        root = tmp_path / "hunt-memory"
        (root / "object_model").mkdir(parents=True)
        (root / "object_model" / "acme.com.jsonl").write_text('{"a":1}\n')
        (root / "object_model" / "beta.example.jsonl").write_text('{"a":1}\n')
        found = mg._find_targets(root)
        assert root / "object_model" / "acme.com.jsonl" in found
        assert root / "object_model" / "beta.example.jsonl" in found

    def test_object_model_checkpoints_are_not_matched(self, tmp_path):
        # business_logic_probe.py's Part 3 checkpoints
        # (object_model/checkpoints/<target>__<pattern>.json) live one
        # level deeper and are .json, not .jsonl -- must never be treated
        # as rotatable.
        root = tmp_path / "hunt-memory"
        (root / "object_model" / "checkpoints").mkdir(parents=True)
        (root / "object_model" / "checkpoints" / "acme.com__invite_flow.json").write_text("{}")
        assert mg._find_targets(root) == []

    def test_orphaned_backup_surfaces_the_live_path_for_fixed_name(self, tmp_path):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        (root / "chains.jsonl.1").write_text('{"a":1}\n')
        found = mg._find_targets(root)
        assert root / "chains.jsonl" in found
        assert not (root / "chains.jsonl").exists()  # confirms it's an orphan, not a live file

    def test_orphaned_backup_surfaces_the_live_path_for_object_model(self, tmp_path):
        root = tmp_path / "hunt-memory"
        (root / "object_model").mkdir(parents=True)
        (root / "object_model" / "gone.example.jsonl.2").write_text('{"a":1}\n')
        found = mg._find_targets(root)
        assert root / "object_model" / "gone.example.jsonl" in found

    def test_coincidental_double_suffix_is_not_treated_as_a_backup(self, tmp_path):
        # "chains.jsonl.bak.1" strips one suffix to "chains.jsonl.bak",
        # which does NOT match the "chains.jsonl" pattern -- must be
        # left alone, not silently added as if it were chains.jsonl.
        root = tmp_path / "hunt-memory"
        root.mkdir()
        (root / "chains.jsonl.bak.1").write_text("junk")
        assert mg._find_targets(root) == []

    def test_object_model_coincidental_double_suffix_is_not_matched(self, tmp_path):
        root = tmp_path / "hunt-memory"
        (root / "object_model").mkdir(parents=True)
        (root / "object_model" / "acme.jsonl.bak.1").write_text("junk")
        assert mg._find_targets(root) == []

    def test_all_ten_entries_found_together(self, tmp_path):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        for name in _KNOWN_ROTATION_PROTECTED_FIXED_NAMES:
            (root / name).write_text('{"a":1}\n')
        (root / "object_model").mkdir()
        (root / "object_model" / "acme.com.jsonl").write_text('{"a":1}\n')
        found = mg._find_targets(root)
        assert len(found) == len(_KNOWN_ROTATION_PROTECTED_FIXED_NAMES) + 1


class TestReport:

    def test_no_targets_prints_none_found(self, tmp_path, capsys):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        over = mg.report(root, max_bytes=1024, keep=3)
        assert over == 0
        assert "No rotatable files" in capsys.readouterr().out

    def test_previously_invisible_file_now_appears_in_report(self, tmp_path, capsys):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        (root / "hypotheses.jsonl").write_text('{"a":1}\n')
        mg.report(root, max_bytes=1024 * 1024, keep=3)
        assert "hypotheses.jsonl" in capsys.readouterr().out

    def test_object_model_file_appears_in_report_with_relative_path(self, tmp_path, capsys):
        root = tmp_path / "hunt-memory"
        (root / "object_model").mkdir(parents=True)
        (root / "object_model" / "acme.com.jsonl").write_text('{"a":1}\n')
        mg.report(root, max_bytes=1024 * 1024, keep=3)
        out = capsys.readouterr().out
        assert "object_model/acme.com.jsonl" in out or "object_model\\acme.com.jsonl" in out

    def test_over_cap_file_is_counted_and_flagged(self, tmp_path, capsys):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        (root / "chains.jsonl").write_text("x" * 2048)
        over = mg.report(root, max_bytes=1024, keep=3)
        assert over == 1
        assert "OVER CAP" in capsys.readouterr().out


class TestDoRotate:

    def test_previously_uncovered_file_actually_rotates(self, tmp_path):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        live = root / "report_outcomes.jsonl"
        live.write_text("x" * 2048)
        rotated = mg.do_rotate(root, max_bytes=1024, keep=3)
        assert rotated == 1
        # rotate() renames the live file to .1 (os.replace) -- it does not
        # recreate an empty file at the original path, so the live path is
        # gone until the next real writer creates it again.
        assert not live.exists()
        assert (root / "report_outcomes.jsonl.1").read_text() == "x" * 2048

    def test_object_model_file_rotates(self, tmp_path):
        root = tmp_path / "hunt-memory"
        (root / "object_model").mkdir(parents=True)
        live = root / "object_model" / "acme.com.jsonl"
        live.write_text("x" * 2048)
        rotated = mg.do_rotate(root, max_bytes=1024, keep=3)
        assert rotated == 1
        assert (root / "object_model" / "acme.com.jsonl.1").exists()

    def test_under_cap_file_is_not_rotated(self, tmp_path):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        (root / "chains.jsonl").write_text('{"a":1}\n')
        rotated = mg.do_rotate(root, max_bytes=1024 * 1024, keep=3)
        assert rotated == 0

    def test_two_different_target_object_model_files_rotate_independently(self, tmp_path):
        root = tmp_path / "hunt-memory"
        (root / "object_model").mkdir(parents=True)
        (root / "object_model" / "acme.com.jsonl").write_text("x" * 2048)
        (root / "object_model" / "beta.example.jsonl").write_text('{"a":1}\n')  # small, stays live
        rotated = mg.do_rotate(root, max_bytes=1024, keep=3)
        assert rotated == 1
        assert (root / "object_model" / "acme.com.jsonl.1").exists()
        assert (root / "object_model" / "beta.example.jsonl").exists()
        assert not (root / "object_model" / "beta.example.jsonl.1").exists()


class TestDoPurge:

    def test_purges_backups_for_a_previously_uncovered_file(self, tmp_path):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        (root / "experiments.jsonl").write_text('{"a":1}\n')
        (root / "experiments.jsonl.1").write_text('{"a":1}\n')
        (root / "experiments.jsonl.2").write_text('{"a":1}\n')
        removed = mg.do_purge(root, keep=3)
        assert removed == 2
        assert not (root / "experiments.jsonl.1").exists()
        assert (root / "experiments.jsonl").exists()  # live file untouched

    def test_purges_object_model_backups(self, tmp_path):
        root = tmp_path / "hunt-memory"
        (root / "object_model").mkdir(parents=True)
        (root / "object_model" / "acme.com.jsonl").write_text('{"a":1}\n')
        (root / "object_model" / "acme.com.jsonl.1").write_text('{"a":1}\n')
        removed = mg.do_purge(root, keep=3)
        assert removed == 1
        assert not (root / "object_model" / "acme.com.jsonl.1").exists()


class TestMainCLI:

    def test_report_only_exits_zero(self, tmp_path, capsys):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        (root / "hypotheses.jsonl").write_text('{"a":1}\n')
        exit_code = mg.main(["--dir", str(root)])
        assert exit_code == 0
        assert "hypotheses.jsonl" in capsys.readouterr().out

    def test_rotate_flag_rotates_previously_uncovered_file(self, tmp_path, capsys):
        root = tmp_path / "hunt-memory"
        root.mkdir()
        (root / "finding_states.jsonl").write_text("x" * 2048)
        exit_code = mg.main(["--dir", str(root), "--rotate", "--max-mb", str(1024 / (1024 * 1024))])
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "Rotated 1 file" in out
        assert (root / "finding_states.jsonl.1").exists()
