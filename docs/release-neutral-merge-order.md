# Release-neutral merge prerequisite

This narrow change targets main independently of the Draft feature stack. It removes
both tag and main-push Release steps and reduces the workflow token to contents: read.
Main pushes, tags, PRs and manual runs still build/test and upload unsigned artifacts.
It does not create a release channel, signing setup, environment approval or release.

Before merging the feature stack, explicitly approve and merge this prerequisite,
then verify the resulting main workflow and run have no publishing step. Do not merge
any earlier feature PR first: the current main workflow automatically publishes it.
Existing published releases are untouched. A Draft PR alone does not change main.

## Relationship to PR #16

PR #16 (build/p3-safe-channels) is stacked after #15, not a safe first merge into main.
It independently removes the same publishing steps and adds candidate packaging.
After this prerequisite is merged, integrate current main into the first stacked
branch (#3), then propagate/reconcile through the dependent branches with tests.
Preserve the release_guard_selftest.py step and file during workflow conflict resolution.
At #16 retain its contents: read, candidate-only manual choices and archive manifest
checks as well as this regression gate. Do not replace the entire workflow with an
older branch version. Run both release_guard_selftest.py and release_channel_selftest.py
and inspect the resolved workflow before merging. A successful earlier CI run does not
verify a newly resolved commit; rerun Windows CI on every changed head.

The text regression test is an intentionally narrow guard for this workflow, not a
security proof against every possible indirect publication mechanism. Independently
review workflow diffs and exact commit CI. Merging and publishing still require the
owner's authorization. No feature PR is merged by preparing this patch.
