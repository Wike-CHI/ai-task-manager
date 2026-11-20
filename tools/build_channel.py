"""Artifact-only channel policy. This module never publishes a release or tag."""
import os
import re


def select_channel(event: str, requested: str, ref: str) -> str:
    if event == 'workflow_dispatch':
        if requested not in ('validation', 'nightly-candidate', 'stable-candidate'):
            raise ValueError('Unsupported build channel')
        if requested == 'stable-candidate' and not re.fullmatch(r'refs/tags/v[0-9]+\.[0-9]+\.[0-9]+', ref):
            raise ValueError('Stable candidate requires an exact version tag ref')
        return requested
    if event in ('pull_request', 'push'):
        return 'validation'
    raise ValueError('Unsupported build event')


if __name__ == '__main__':
    channel = select_channel(os.environ['GITHUB_EVENT_NAME'],
                             os.environ.get('REQUESTED_CHANNEL', ''),
                             os.environ['GITHUB_REF'])
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write('channel=' + channel + '\n')
