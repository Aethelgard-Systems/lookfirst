# PyPI preparation — no publication

This is a candidate for 0.2.1, not a release. Merge the reviewed fixes first and rebuild from the resulting pinned commit. Do not tag or upload from this preparation branch.

The name `lookfirst` is a candidate. Its availability could not be verified on 2026-11-04: the PyPI JSON lookup was unavailable. A missing public project alone would not reserve the name or prove that a pending publisher can claim it. Name availability remains a release blocker.

## Reproducible local artifacts

Use a fresh virtual environment with the same Python and build dependencies for both builds. The observed reference backend was Python 3.14.4, setuptools 78.1.1 (including its bundled wheel builder); dependency installation from the public index was not verified in that environment.

```sh
python -m pip install 'setuptools==78.1.1'
SOURCE_DATE_EPOCH=1793808000 LOOKFIRST_DIST_DIR=/tmp/lookfirst-one python tools/build_dist.py
SOURCE_DATE_EPOCH=1793808000 LOOKFIRST_DIST_DIR=/tmp/lookfirst-two python tools/build_dist.py
sha256sum /tmp/lookfirst-one/* /tmp/lookfirst-two/*
```

Compare the two wheel hashes and the two source-archive hashes separately. Keep the commit, Python/backend versions and hashes with the review. This checks repeatability within that toolchain, not across every toolchain. The script normalizes source-archive timestamps and ownership; it never uploads.

## Trusted Publishing, maintainer actions only

Reference: https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/

1. Check the candidate name at https://pypi.org/project/lookfirst/ while signed into the intended maintainer account.
2. Read the pending-publisher instructions at the reference above; verify the current form before entering anything.
3. Prepare a separate reviewed GitHub publishing workflow; no such workflow is activated by this patch.
4. Record the exact workflow filename and optional GitHub environment from that reviewed workflow.
5. Register a pending publisher for the approved name, owner `Aethelgard-Systems`, repository `lookfirst`, and those exact workflow/environment values.
6. Ensure the publishing job has only the required OIDC `id-token: write` and repository read permissions, an environment approval gate, and a pinned artifact input.
7. Stop before running the publishing workflow; obtain the existing explicit publication approval for that concrete artifact and version.

Do not create API tokens as a workaround. Do not confuse a registered publisher with an uploaded package. Updating the PyPI configuration or workflow permissions is a maintainer action; this document performs neither.
