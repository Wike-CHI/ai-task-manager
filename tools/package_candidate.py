"""Produce unsigned candidate archives and integrity manifest, never a release."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile
from build_channel import select_channel


def package(root: Path, output: Path, sha: str, channel: str, run: str) -> dict:
    if not re.fullmatch(r'[0-9a-f]{40}', sha) or channel not in ('validation', 'nightly-candidate', 'stable-candidate'):
        raise ValueError('Invalid immutable build identity')
    if not re.fullmatch(r'[0-9]+', run):
        raise ValueError('Invalid run identity')
    binaries = ('AITaskManager.exe', 'AITaskManagerReadOnly.exe')
    # Validate all inputs before creating an output.
    for name in binaries:
        file = root / name
        if not file.is_file() or file.is_symlink():
            raise ValueError('Missing native artifact')
    output.mkdir(parents=True, exist_ok=False)
    files = []
    for name in binaries:
        data = (root / name).read_bytes()
        archive = output / (name[:-4] + '.zip')
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
        files.append({'file': archive.name, 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                      'binary': name, 'binarySha256': hashlib.sha256(data).hexdigest(), 'binaryBytes': len(data)})
    manifest = {'schemaVersion': 1, 'channel': channel, 'sourceSha': sha, 'workflowRun': run,
                'unsigned': True, 'published': False, 'files': files,
                'limits': ['Checksums identify bytes, not publisher trust.',
                           'No real Argus comparison or manual GUI acceptance is implied.']}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest


if __name__ == '__main__':
    sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if sha != os.environ['GITHUB_SHA']:
        raise ValueError('Checkout differs from workflow source')
    channel = select_channel(os.environ['GITHUB_EVENT_NAME'], os.environ.get('REQUESTED_CHANNEL', ''), os.environ['GITHUB_REF'])
    package(Path('.'), Path('build/candidate'), sha, channel, os.environ['GITHUB_RUN_ID'])
