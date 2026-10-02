# Upstream source import

Product: Blender

Official upstream: https://github.com/blender/blender.git

Upstream branch: `main`

Upstream commit: `59d9609b821ec5fa4d02ffe791aeeb016942fc84`

Import date: 2026-10-02

This repository contains the official Blender source-code snapshot from the
upstream branch and commit above.

Blender's upstream repository uses Git LFS for thousands of binary assets.
Those binary payloads are intentionally not duplicated into this repository.
Their original paths, SHA-256 object IDs, and declared sizes are recorded in
`UPSTREAM_LFS_POINTERS.txt`.

Upstream GitHub Actions workflows are preserved under
`.github-workflows-disabled/` so importing the source cannot automatically
execute third-party CI in this repository.

The source import itself remains attributable to the official Blender project
and preserves the upstream source files and licensing material included in the
snapshot.
