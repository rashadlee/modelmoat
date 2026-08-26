# Releasing

Every place a version number or fixture-derived count can go stale, in order.
This exists because both have already gone stale in real releases: `--version`
once kept reporting the old release after a bump, and the README's example
output kept a wrong number after fixtures changed.

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
   token or `gh` - go to `/releases/new`, pick the tag, paste in the
   changelog entry for this version.

8. **If the repo is still private:** the images and CI badge in the README
   will not render on GitHub for anyone without repo access, and image paths
   need to stay relative for the same reason (see the comment at the top of
   README.md). If the repo is public, switch those to absolute
   `raw.githubusercontent.com` URLs before or as part of this release, so
   they also render correctly on the PyPI project page.
