"""Local artifact guard: mismatched artifacts must never reach publishing."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

from tools.check_release_dist import MARKER, check


class ReleaseDistTest(unittest.TestCase):
    def write_candidates(self, root, version='0.2.1', marker=MARKER):
        data = f'Name: lookfirst\nVersion: {version}\n\n# README\n<!-- {marker} -->\n'.encode()
        with zipfile.ZipFile(root / 'lookfirst-0.2.1-py3-none-any.whl', 'w') as z:
            z.writestr('lookfirst-0.2.1.dist-info/METADATA', data)
        with tarfile.open(root / 'lookfirst-0.2.1.tar.gz', 'w:gz') as t:
            member = tarfile.TarInfo('lookfirst-0.2.1/PKG-INFO')
            member.size = len(data)
            t.addfile(member, io.BytesIO(data))

    def test_correct_pair_and_invalid_candidates(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.write_candidates(root)
            check(root, '0.2.1')
            with self.assertRaises(ValueError):
                check(root, '9.9.9')
            (root / 'unreviewed.whl').write_text('unexpected')
            with self.assertRaises(ValueError):
                check(root, '0.2.1')
            (root / 'unreviewed.whl').unlink()
            self.write_candidates(root, marker='not the registry ownership marker')
            with self.assertRaises(ValueError):
                check(root, '0.2.1')
            self.write_candidates(root, version='0.2.2')
            with self.assertRaises(ValueError):
                check(root, '0.2.1')


if __name__ == '__main__':
    unittest.main()
