# PyPI Trusted Publishing: maintainer steps

Preparation only. No package, tag, release, account or publisher is created by this patch.

The workflow filename is **publish-pypi.yml**. Its publisher identity is **Aethelgard-Systems / lookfirst / publish-pypi.yml / pypi**.

## Configure once (one action per line)

1. Open the independently reviewed workflow PR in https://github.com/Aethelgard-Systems/lookfirst/pulls.
2. Merge the workflow PR only after your review (MARCO gate).
3. Open https://github.com/Aethelgard-Systems/lookfirst/settings/environments.
4. Create the environment named `pypi`.
5. Add Marco as a required reviewer for `pypi`.
6. Check that the intended reviewer can approve the run under the configured self-review policy; use a separate permitted initiator/reviewer where required.
7. Restrict environment deployment branches to `main`.
8. Verify required-reviewer protection is actually supported and enabled for this repository plan; stop if it cannot be enforced.
9. Open https://pypi.org/project/lookfirst/ to check the candidate project name.
10. Sign into the intended PyPI maintainer account.
11. Open https://pypi.org/manage/account/publishing/.
12. Select the GitHub pending-publisher form (or the existing project's Publishing page if you already own the project).
13. Set PyPI Project Name to `lookfirst` (pending publisher only).
14. Set Owner to `Aethelgard-Systems`.
15. Set Repository name to `lookfirst`.
16. Set Workflow name to `publish-pypi.yml`.
17. Set Environment name to `pypi`.
18. Submit the publisher form only when ready; a pending publisher does not reserve the name.
19. Stop here: do not trigger a workflow during preparation.

## Later publication (only after approval for the concrete artifact/version)

1. Record the full reviewed `main` SHA and package version from that commit.
2. Open https://github.com/Aethelgard-Systems/lookfirst/actions/workflows/publish-pypi.yml.
3. Choose Run workflow on `main`.
4. Paste the full reviewed SHA into `source_sha`.
5. Enter the reviewed version into `version`.
6. Start the run only with the explicit publication approval.
7. Inspect the successful build/test result and distribution hashes in the job summary.
8. Approve the waiting `pypi` environment job only if its source SHA and artifacts match the review.
9. Check the published version and files at https://pypi.org/project/lookfirst/.
10. Keep the actual PyPI URL, workflow run, source SHA and artifact hashes as evidence.

The build job has repository read permission only. OIDC permission exists only in the environment-gated publish job, which checks out no source and downloads only this run's artifact ID. Trigger is manual only: no push, pull-request, tag or release trigger.

References checked 2026-11-04: [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/), [pending publishers](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/), [GitHub environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).
