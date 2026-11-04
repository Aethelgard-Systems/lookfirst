# Contributing

Open a bug report or question before substantial changes. Keep each pull request focused on one behavior and explain the expected result and any limitations.

Use Python 3.12 or later in a fresh virtual environment:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests
```

For Windows, activate with `.venv\Scripts\activate` instead. Run tests for the affected behavior while developing, then the suite before review. Existing expected failures document unresolved limits; do not skip, delete, or weaken tests to hide a regression. Add a regression test for behavior changes and update the relevant README limits.

Use synthetic data only. Never commit tokens, keys, audit logs with personal information, real account details, or production configuration. Report security problems through SECURITY.md rather than public issues.

Describe what you tested, the exact version or commit, and any tests you could not run. A passing test is not evidence of support for every MCP client or of production safety. Maintainers review changes before merging; publishing a version is a separate action.
