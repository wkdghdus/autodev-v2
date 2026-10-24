from __future__ import annotations

import errno
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from autodev.contracts.validators import validate_operation_record
from autodev.safety.journal import OperationJournal, OperationRequest, canonical_request_digest
from autodev.safety.types import JournalError


ROOT = Path(__file__).resolve().parents[1]


def request() -> OperationRequest:
    return OperationRequest("local-update", "11111111-1111-4111-8111-111111111111", "AD-02",
                            "a" * 64, "b" * 64, {"project": "one"}, "idem-one", "owner-one", 1,
                            ("local-registry",))


class JournalTests(unittest.TestCase):
    def test_exact_request_binding_and_operation_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = OperationJournal(Path(tmp))
            original = journal.prepare(request(), operation_id="original")
            self.assertEqual(validate_operation_record(original).operation_state, "PREPARED")
            self.assertEqual(journal.prepare(request()), original)
            changes = {"operation_kind": "other", "installation_id": "22222222-2222-4222-8222-222222222222",
                       "milestone_id": None, "plan_digest": "c" * 64, "grant_digest": "d" * 64,
                       "canonical_arguments": {"project": "two"}, "owner_identity": "owner-two",
                       "deployment_epoch": 2, "local_mutation_target_ids": ("other-registry",)}
            for field, value in changes.items():
                with self.subTest(field=field), self.assertRaises(JournalError):
                    journal.prepare(replace(request(), **{field: value}))
            with self.assertRaises(JournalError):
                journal.prepare(request(), operation_id="replacement")
            with self.assertRaises(JournalError):
                journal.prepare(replace(request(), idempotency_key="another-key"), operation_id="original")
            self.assertEqual(journal.recover("idem-one").operation_id, "original")

    def test_unsupported_canonical_types_and_distinct_values(self):
        for value in (1.5, float('nan'), object(), {1: "a"}, {"nested": {1: "a"}}):
            with self.subTest(value=type(value).__name__), self.assertRaises(JournalError):
                canonical_request_digest(replace(request(), canonical_arguments={"value": value}))
        self.assertNotEqual(canonical_request_digest(replace(request(), canonical_arguments={"value": True})),
                            canonical_request_digest(replace(request(), canonical_arguments={"value": 1})))

    def test_no_raw_arguments_or_seeded_secrets_persist(self):
        canary = "CANARY-RAW-CREDENTIAL"
        with tempfile.TemporaryDirectory() as tmp:
            journal = OperationJournal(Path(tmp), canaries=(canary,))
            journal.prepare(replace(request(), canonical_arguments={"password": canary}))
            with self.assertRaises(JournalError):
                journal.mark_sent("idem-one", native_ids=(canary,))
            for path in Path(tmp).rglob('*'):
                if path.is_file():
                    self.assertNotIn(canary.encode(), path.read_bytes())
            with self.assertRaises(JournalError):
                journal.prepare(replace(request(), idempotency_key="second", owner_identity=canary))

    def test_callback_preconditions_and_replay_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = OperationJournal(Path(tmp))
            seen = []
            def effect():
                state = journal.recover("idem-one")
                self.assertEqual(state.status, "UNCERTAIN")
                self.assertEqual(state.native_ids, ("native-one",))
                seen.append("effect")
            journal.run_with_journal(request(), effect, native_ids_before_effect=("native-one",))
            self.assertEqual(journal.recover("idem-one").status, "ACKNOWLEDGED")
            with self.assertRaises(JournalError):
                journal.run_with_journal(request(), effect)
            self.assertEqual(seen, ["effect"])
            with self.assertRaises(JournalError):
                journal.mark_sent("idem-one")

    def test_real_sigkill_before_journal_prepared_sent_and_effect(self):
        for stage in ("BEFORE", "PREPARED", "SENT", "EFFECT"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                script = '''
import os, signal, sys
from pathlib import Path
from autodev.safety.journal import OperationJournal
from tests.test_ad02_journal import request
root = Path(sys.argv[1])
stage = sys.argv[2]
journal = OperationJournal(root)
def checkpoint(label):
    if label == stage:
        os.kill(os.getpid(), signal.SIGKILL)
def effect():
    (root / "effect").write_text("one")
checkpoint("BEFORE")
journal.run_with_journal(request(), effect, native_ids_before_effect=("native-one",), checkpoint=checkpoint)
'''
                child = subprocess.run([sys.executable, "-B", "-c", script, tmp, stage],
                                       cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src") + os.pathsep + str(ROOT)},
                                       capture_output=True, timeout=10)
                self.assertEqual(child.returncode, -signal.SIGKILL, child.stderr)
                journal = OperationJournal(Path(tmp))
                recovered = journal.recover("idem-one")
                self.assertEqual((Path(tmp) / "effect").exists(), stage == "EFFECT")
                if stage == "BEFORE":
                    self.assertEqual(recovered.status, "MISSING")
                else:
                    record = journal.store.read_json(journal.relative_path)["operations"]["idem-one"]["record"]
                    self.assertEqual(recovered.operation_id, record["operation_id"])
                    self.assertEqual(recovered.status, "UNCERTAIN")
                    self.assertEqual(recovered.native_ids_unknown, stage == "PREPARED")
                    with self.assertRaises(JournalError):
                        journal.run_with_journal(request(), lambda: self.fail("duplicate callback"))

    def test_disk_failure_during_ack_preserves_effect_and_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = OperationJournal(Path(tmp))
            original_replace = journal.store._replace
            def disk_full(path, payload, checkpoint=None):
                if b'ACKNOWLEDGED' in payload:
                    raise OSError(errno.ENOSPC, "disk full")
                return original_replace(path, payload, checkpoint)
            with patch.object(journal.store, '_replace', side_effect=disk_full):
                with self.assertRaises(JournalError):
                    journal.run_with_journal(request(), lambda: (Path(tmp) / "effect").write_text("one"))
            recovered = journal.recover("idem-one")
            self.assertEqual(recovered.status, "UNCERTAIN")
            self.assertTrue(recovered.native_ids_unknown)
            self.assertEqual((Path(tmp) / "effect").read_text(), "one")
            with self.assertRaises(JournalError):
                journal.run_with_journal(request(), lambda: self.fail("retry"))

    def test_corrupt_partial_records_and_bindings_block_new_admission(self):
        for mutation in ("partial", "binding", "key", "sidecar"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                journal = OperationJournal(Path(tmp))
                journal.prepare(request(), operation_id="original")
                path = journal.store.resolve(journal.relative_path)
                if mutation == "partial":
                    path.write_text('{')
                elif mutation == "sidecar":
                    journal.store._recovery_path(journal.relative_path).write_text('{')
                else:
                    raw = json.loads(path.read_bytes())
                    if mutation == "binding":
                        raw['operations']['idem-one']['request_digest'] = '0' * 64
                    else:
                        raw['operations']['idem-one']['record']['idempotency_key'] = 'wrong'
                    path.write_text(json.dumps(raw))
                self.assertEqual(journal.recover("idem-one").status, "CORRUPT")
                with self.assertRaises(JournalError):
                    journal.prepare(replace(request(), idempotency_key="new-key"))
