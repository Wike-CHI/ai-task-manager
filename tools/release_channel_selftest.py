"""Offline release-negative policy and packaging tests; no API or network calls."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from build_channel import select_channel
from package_candidate import package


class ChannelTests(unittest.TestCase):
    def test_automatic_events_are_validation_only(self):
        for event in ('push', 'pull_request'):
            for ref in ('refs/heads/main', 'refs/tags/v1.0.0'):
                self.assertEqual(select_channel(event, 'stable-candidate', ref), 'validation')

    def test_manual_channels(self):
        for channel in ('validation', 'nightly-candidate'):
            self.assertEqual(select_channel('workflow_dispatch', channel, 'refs/heads/main'), channel)
        self.assertEqual(select_channel('workflow_dispatch', 'stable-candidate', 'refs/tags/v1.2.3'), 'stable-candidate')

    def test_fail_closed(self):
        for event, channel, ref in [('schedule', '', 'refs/heads/main'), ('workflow_dispatch', 'publish', 'refs/heads/main'),
                                     ('workflow_dispatch', 'stable-candidate', 'refs/heads/main'),
                                     ('workflow_dispatch', 'stable-candidate', 'refs/tags/v1.2.3\n')]:
            with self.assertRaises(ValueError):
                select_channel(event, channel, ref)

    def test_archive_manifest_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('AITaskManager.exe', 'AITaskManagerReadOnly.exe'):
                (root/name).write_bytes(b'fixture-not-an-executable')
            m = package(root, root/'out', 'a'*40, 'nightly-candidate', '123')
            self.assertTrue(m['unsigned'])
            self.assertFalse(m['published'])
            for f in m['files']:
                archive=root/'out'/f['file']
                self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), f['sha256'])
                with zipfile.ZipFile(archive) as z:
                    self.assertEqual(z.namelist(), [f['binary']])
                    self.assertEqual(hashlib.sha256(z.read(f['binary'])).hexdigest(), f['binarySha256'])
            self.assertEqual(json.loads((root/'out/manifest.json').read_text()), m)
            with self.assertRaises(FileExistsError):
                package(root, root/'out', 'a'*40, 'validation', '123')

    def test_missing_or_invalid_input_fails_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for sha,channel,run in [('bad','validation','1'),('a'*40,'published','1'),('a'*40,'validation','../x'),('a'*40,'validation','1')]:
                with self.assertRaises(ValueError):
                    package(root, root/'out', sha,channel,run)
                self.assertFalse((root/'out').exists())

    def test_workflow_has_no_publication_or_elevated_token(self):
        text=(Path(__file__).resolve().parents[1]/'.github/workflows/build.yml').read_text(encoding='utf-8')
        self.assertIn('contents: read',text)
        for forbidden in ('contents: write','action-gh-release','gh release','gh api','git push','schedule:', 'pull_request_target:', 'workflow_run:', 'secrets.'):
            self.assertNotIn(forbidden,text)
        self.assertIn('python tools/release_channel_selftest.py',text)
        self.assertIn('python tools/package_candidate.py',text)

if __name__=='__main__': unittest.main(verbosity=2)
