# Releasing

Every place a version number or fixture-derived count can go stale, in order.
This exists because both have already gone stale in real releases: `--version`
once kept reporting the old release after a bump, and the README's example
output kept a wrong number after fixtures changed.

## Versioning

`CHANGELOG.md` commits to semantic versioning. Individual commits never bump
the version - `pyproject.toml`'s `version` only changes when a release
actually happens, so `master` can carry any number of small commits between
releases at the same version. What changes is which number the *next*
release gets:

- **PATCH** (0.2.0 -> 0.2.1): bug fixes only. Nothing new to use, something
  broken now works.
- **MINOR** (0.2.0 -> 0.3.0): anything new - a check, a flag, a capability.
  One small new check is still MINOR, not PATCH; "new" is the test, not
  "big."
- **MAJOR**: a breaking change - a renamed check ID (breaks existing
  baseline files, since fingerprints hash `check_id`), a removed flag, or a
  default that changes exit codes for an existing CI config. Semver allows
  breaking changes without a MAJOR bump pre-1.0 (`0.x.y`), but reserve it
  for these anyway, so a version jump always means the same thing.

1. **Bump the version.** Edit `version` in `pyproject.toml`. That is the only
   place to edit it - `modelmoat.__version__` reads it from installed package
   metadata, not a second hardcoded string.

2. **Update the changelog.** Move `CHANGELOG.md`'s `Unreleased` section (or
   add a new one) to `## X.Y.Z - YYYY-MM-DD`.

3. **Regenerate the README's example output.**

       python scripts/update_release_assets.py

   This overwrites `assets/screenshots/scan-insecure.svg` and
   `scan-secure.svg` from a real scan, and prints a plain-text block to paste
   into README.md's `## Usage` section, replacing the existing "Real output
   from the test fixtures in this repo" example. It warns on stderr if the
   secure fixture produced any findings - that fixture must always be clean;
   fix the check, do not accept the new screenshot.

   Check `git diff --stat assets/screenshots/` after. If nothing about scan
   output actually changed, the diff should be empty - the script pins a
   fixed SVG id specifically so an unrelated re-run does not produce noise.

4. **Verify.**

       pytest -q
       ruff check modelmoat tests
       python -m build
       twine check dist/*
       modelmoat scan tests/fixtures/secure   # exit 0
       modelmoat scan tests/fixtures/insecure # exit 1

   Then install the actual built wheel into a fresh venv and run
   `modelmoat --version` plus both fixtures again from there, not from the
   dev checkout. This is what caught the `__version__` bug - it read `0.2.0`
   from the editable install while the built wheel would have still said
   `0.1.0`, and only testing the real wheel surfaced that.

5. **Commit, tag, push.**

       git commit -m "Release X.Y.Z"
       git tag -a vX.Y.Z -m "modelmoat X.Y.Z"
       git push origin master
       git push origin vX.Y.Z

6. **Publish to PyPI.**

       twine upload dist/*

   Irreversible. That exact version can never be re-uploaded, even deleted.
   Verify with a real install afterward:
   `pip install modelmoat==X.Y.Z` in yet another fresh venv.

   The PyPI badge in the README can keep showing the old version on GitHub
   for a while after this. That is GitHub's own image proxy
   (camo.githubusercontent.com) caching the badge image separately from
   shields.io - shields.io itself is typically already correct immediately.
   Confirm with `curl -s https://img.shields.io/pypi/v/modelmoat.svg` before
   assuming something is wrong. If it needs to look right on GitHub sooner
   than the cache clears on its own, change the badge URL slightly (e.g.
   bump the `cacheSeconds` value) to force a fresh fetch.

7. **Create the GitHub Release from the tag.** Not automatable without a
   token or `gh` - go to `/releases/new`, pick the tag, and write the release
   body by hand.

   Do not rely on GitHub's "Generate release notes" button - the "What's
   Changed" list, PR links, and "New Contributors" section it produces are
   all built from merged pull requests, and every modelmoat commit lands
   directly on `master`. With no PRs in the range it generates nothing but
   the "Full Changelog" compare link. Confirmed empirically on v0.2.0.

   Instead, condense that version's `CHANGELOG.md` entry into one-line
   bullets under `## Added` / `## Fixed` headers (drop the longer
   explanatory prose - that belongs in the changelog, not here). End each
   bullet with a link to the commit that made that change, the same role a
   PR link plays in a PR-based project's auto-generated notes - find it with
   `git log v<prev>..v<this> --oneline`. Close with the compare link:

       ## Added

       - `FLAG-ID`: one line, what it does ([abc1234](https://github.com/rashadlee/modelmoat/commit/abc1234))

       ## Fixed

       - one line, what broke and how ([abc1234](https://github.com/rashadlee/modelmoat/commit/abc1234))

       **Full Changelog**: https://github.com/rashadlee/modelmoat/compare/vX.Y.Z-1...vX.Y.Z

   A short 7-character SHA is enough - GitHub resolves it and autolinks bare
   SHAs on its own, but an explicit markdown link renders identically to a
   PR link, which is the point.

   This is a workflow choice, not a limitation to work around: switching to
   pull requests for every change would make the auto-generated version
   richer, but adds real per-change overhead for no reviewer other than
   yourself. Revisit only if that tradeoff changes - e.g. other contributors
   show up, or PR-gated CI checks become worth having.

8. **Any new image in the README** (screenshot, banner, roadmap) needs an
   absolute `raw.githubusercontent.com` URL pinned to `master`, not a
   relative path - see the comment at the top of README.md. Relative paths
   render fine on GitHub but show as broken images on PyPI, since PyPI's
   long_description has no access to the rest of the repo tree.
