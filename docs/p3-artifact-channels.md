# P3: release-negative candidate channels

This patch replaces the old main/tag auto-publisher **in this branch's workflow**.
It is a proposal in a Draft PR, not a change already deployed to main. Do not merge
this or its stacked dependencies without reviewing the complete base/head diff:
merging an earlier PR into the old main can still trigger that old auto-publisher.

## Implemented behavior

| Trigger | Channel | Result |
| --- | --- | --- |
| Pull request | validation | tested unsigned CI artifacts only |
| Push to main or a v* tag | validation | tested unsigned CI artifacts only |
| Manual: validation | validation | tested unsigned CI artifacts only |
| Manual: nightly-candidate | nightly-candidate | tested unsigned CI artifacts only |
| Manual: stable-candidate | stable-candidate | requires exact refs/tags/vMAJOR.MINOR.PATCH; artifacts only |

There is deliberately no schedule, release API, tag creation, push command,
`workflow_run`/`pull_request_target` trigger, write token or secret access. All jobs
use `contents: read`. Nightly here means a candidate classification, **not an active
nightly schedule**. Stable-candidate is not a Stable release or an approval claim.
An existing version tag must be chosen for a stable candidate; this workflow does
not create one. Dispatch on a different branch uses that branch's workflow, so
review its immutable SHA before starting it. Do not dispatch the old main workflow.

After all native/protocol/boundary tests, packaging creates separate GUI and CLI
ZIP archives with a JSON manifest: exact checkout SHA, workflow run ID, channel,
archive SHA256, binary SHA256 and byte length, and explicit unsigned/unpublished
labels. The script verifies `git rev-parse HEAD == GITHUB_SHA`; PR artifacts identify
the tested merge commit, not necessarily the feature head. Checksums establish
byte identity only. ZIP timestamp normalization does not prove reproducible native
binaries or compiler provenance. Python/MCP dependencies are not bundled.

## Validation and remaining publication gate

`python tools/release_channel_selftest.py` exercises push/PR/manual channel policy,
invalid channel/tag/event rejection, fixture ZIP/hash integrity, missing input and
output-overwrite rejection, plus negative workflow text checks. CI runs it before
packaging. These checks are defense in depth, not a full semantic GitHub Actions
policy analyzer. The workflow's actual PR run validates native packaging without
creating a release. Manual candidate dispatch and production publication have not
been executed by this development task.

A future publisher needs a separately reviewed immutable artifact selection,
verified tests, signing/provenance choice, real GUI/benchmark acceptance, explicit
owner approval and platform permission gates. No environment protection or
repository setting is assumed to exist. No publisher is included because an input
checkbox alone is not an enforceable approval boundary.
