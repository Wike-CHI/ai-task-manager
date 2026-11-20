"""Regression gate for release-neutral validation on main (stdlib only)."""
from pathlib import Path
import unittest


class ReleaseGuardTests(unittest.TestCase):
    def test_build_only(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/build.yml').read_text(encoding='utf-8')
        self.assertIn('contents: read', workflow)
        for forbidden in ('contents: write', 'action-gh-release', 'gh release', 'AUTO_VERSION_BASE', 'make_latest:', 'prerelease:', 'draft:', 'git push', 'create-release'):
            self.assertNotIn(forbidden, workflow)
        for required in ('actions/checkout@', 'Core and safety tests', 'actions/upload-artifact@', 'pull_request:', 'workflow_dispatch:', 'branches: [main]'):
            self.assertIn(required, workflow)
        self.assertIn('python -B tools/release_guard_selftest.py', workflow)


if __name__ == '__main__':
    unittest.main()
