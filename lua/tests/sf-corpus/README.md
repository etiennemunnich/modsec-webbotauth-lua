# Structured Field test corpus

The HTTP Working Group's tests for RFC 9651, copied unmodified from
[httpwg/structured-field-tests](https://github.com/httpwg/structured-field-tests)
at commit `00462dd7938b43bf596cb2af6a373d9c928a6cbe` (2026-09-16).

- `MANIFEST` holds each file's SHA-256. `test_sf_corpus.lua` checks every file against it before running, so a corpus file edited to make a test pass fails the run.
- `LICENSE.md` is the upstream licence (IETF Trust, Revised BSD).
- Every record runs. None is skipped or allowlisted.

To update: copy the `*.json` files and `serialisation-tests/` from a newer upstream commit, regenerate `MANIFEST`, and record the commit above.

```bash
cd lua/tests/sf-corpus
find . -name '*.json' | sed 's|^\./||' | sort | while read -r f; do
  printf '%s  %s\n' "$(openssl dgst -sha256 -r "$f" | cut -d' ' -f1)" "$f"
done > MANIFEST
```
