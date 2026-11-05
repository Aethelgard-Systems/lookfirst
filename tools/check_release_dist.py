"""Validate exactly the candidate sdist + wheel, without importing package code."""
from email.parser import BytesParser
from pathlib import Path
import sys
import tarfile
import zipfile

MARKER = 'mcp-name: io.github.Aethelgard-Systems/lookfirst'


def check(directory, version):
    directory = Path(directory)
    files = sorted(directory.iterdir())
    wheels = [p for p in files if p.name.endswith('.whl')]
    sdists = [p for p in files if p.name.endswith('.tar.gz')]
    if len(files) != 2 or len(wheels) != 1 or len(sdists) != 1 or not all(p.is_file() for p in files):
        raise ValueError('expected exactly one wheel and one source archive')
    with zipfile.ZipFile(wheels[0]) as wheel:
        names = [n for n in wheel.namelist() if n.endswith('.dist-info/METADATA')]
        if len(names) != 1:
            raise ValueError('wheel must contain exactly one METADATA file')
        metadata = BytesParser().parsebytes(wheel.read(names[0]))
    if metadata['Name'] != 'lookfirst' or metadata['Version'] != version:
        raise ValueError('wheel name/version differs from reviewed candidate')
    if MARKER not in metadata.get_payload():
        raise ValueError('wheel description is missing MCP ownership marker')
    with tarfile.open(sdists[0], 'r:gz') as sdist:
        members = [m for m in sdist.getmembers() if m.name.endswith('/PKG-INFO') and m.name.count('/') == 1]
        if len(members) != 1 or not members[0].isfile():
            raise ValueError('sdist must contain exactly one top-level PKG-INFO')
        source_metadata = BytesParser().parsebytes(sdist.extractfile(members[0]).read())
    if source_metadata['Name'] != 'lookfirst' or source_metadata['Version'] != version:
        raise ValueError('sdist name/version differs from reviewed candidate')
    if MARKER not in source_metadata.get_payload():
        raise ValueError('sdist description is missing MCP ownership marker')


if __name__ == '__main__':
    check(*sys.argv[1:])
    print('PASS: reviewed candidate metadata, ownership marker and two-file artifact set')
