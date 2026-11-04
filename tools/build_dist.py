"""Build release candidates locally; normalize sdist metadata for repeatability.

Requires the declared setuptools build backend. Does not upload or tag.
"""
import gzip
import io
import os
from pathlib import Path
import tarfile

from setuptools import build_meta


def main():
    epoch = int(os.environ['SOURCE_DATE_EPOCH'])
    target = Path(os.environ.get('LOOKFIRST_DIST_DIR', 'dist')).resolve()
    target.mkdir(parents=True, exist_ok=True)
    archive = target / build_meta.build_sdist(str(target))
    with tarfile.open(archive, 'r:gz') as original:
        records = [(member, original.extractfile(member).read() if member.isfile() else None)
                   for member in original.getmembers()]
    with archive.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch) as zipped:
            with tarfile.open(fileobj=zipped, mode='w', format=tarfile.PAX_FORMAT) as normalized:
                for member, data in sorted(records, key=lambda record: record[0].name):
                    member.mtime = epoch
                    member.uid = member.gid = 0
                    member.uname = member.gname = ''
                    member.pax_headers = {}
                    normalized.addfile(member, io.BytesIO(data) if data is not None else None)
    build_meta.build_wheel(str(target))


if __name__ == '__main__':
    main()
