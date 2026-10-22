# Releasing

Publishing is public and permanent: PyPI never lets a filename be reused, and
a yank only hides a release. A release needs Julien's go.

## One-time setup

1. **PyPI trusted publisher.** On pypi.org, under the account that will own
   the project, add a *pending* trusted publisher (the project does not exist
   yet): project `hippius-drive`, owner `thenervelab`, repository
   `hippius-drive-sdk`, workflow `release.yml`, environment `pypi`. No API
   token is created or stored anywhere.
2. **GitHub environment.** In the repository settings, create the environment
   `pypi`, add required reviewers, and limit deployments to tags matching
   `v*`. The `publish` job waits for that approval.

## Each release

1. Bump `hippius_drive/_version.py` and add a `CHANGELOG.md` section in one PR.
2. Merge it once CI is green on the current main.
3. Tag the merge commit `vX.Y.Z` and push the tag. The `Release` workflow
   checks the tag against the version, reruns lint, types, tests and the
   audit, builds, installs the built wheel in a clean environment (with and
   without `[login]`), and uploads the artefacts.
4. Approve the `pypi` environment. The `publish` job uploads exactly the
   artefacts the `verify` job built.
5. Check `pip install hippius-drive==X.Y.Z` in a fresh environment.
