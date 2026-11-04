import json
from pathlib import Path
import tempfile
import unittest

from lookfirst import audit


class TrustedHead(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pub = audit.generate_key(self.root / 'audit.key')
        self.key = audit.load_private(self.root / 'audit.key')
        self.path = self.root / 'log.jsonl'
        self.log = audit.AuditLog(self.path, self.key)
        self.log.append('preview', 'test', 'tool')
        self.anchor = self.root / 'external.head'
        self.anchor.write_text(Path(str(self.path) + '.head').read_text())

    def verify(self):
        return audit.verify(self.path, self.pub, trusted_head=self.anchor)

    def test_current_and_older_checkpoint(self):
        self.assertTrue(self.verify()[0])
        self.log.append('result', 'test', 'tool')
        self.assertTrue(self.verify()[0])

    def test_deleted_sidecar_and_truncated_tail_detected(self):
        self.log.append('result', 'test', 'tool')
        self.anchor.write_text(Path(str(self.path) + '.head').read_text())
        first = self.path.read_text().splitlines()[0]
        self.path.write_text(first + '\n')
        Path(str(self.path) + '.head').unlink()
        self.assertFalse(self.verify()[0])

    def test_missing_malformed_unsigned_and_wrong_key_fail_closed(self):
        for content in ('not json', '[]', '{}',
                        json.dumps({'seq': True, 'hash': audit.GENESIS, 'sig': ''}),
                        json.dumps(audit.signed_head(1, 'f' * 64,
                            audit.Ed25519PrivateKey.generate()))):
            with self.subTest(content=content):
                self.anchor.write_text(content)
                self.assertFalse(self.verify()[0])
        self.anchor.unlink()
        self.assertFalse(self.verify()[0])

    def test_replaced_history_with_same_key_is_detected(self):
        other = self.root / 'other.jsonl'
        log = audit.AuditLog(other, self.key)
        log.append('preview', 'other', 'tool')
        self.path.write_text(other.read_text())
        Path(str(self.path) + '.head').write_text(Path(str(other) + '.head').read_text())
        self.assertFalse(self.verify()[0])
