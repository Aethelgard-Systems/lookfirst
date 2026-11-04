import contextlib
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import anyio
from lookfirst.cli import serve


class StartWarning(unittest.TestCase):
    def test_warning_precedes_upstream_start_and_is_only_for_elicitation(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                conf = SimpleNamespace(elicitation=enabled)
                err = io.StringIO()
                with patch('lookfirst.cli._gate', side_effect=RuntimeError('stop before upstream')):
                    with contextlib.redirect_stderr(err):
                        with self.assertRaisesRegex(RuntimeError, 'stop before upstream'):
                            anyio.run(serve, conf, 'stdio', '127.0.0.1', 8470)
                self.assertEqual('autonomous clients' in err.getvalue(), enabled)
                self.assertEqual('confirm.elicitation: false' in err.getvalue(), enabled)
