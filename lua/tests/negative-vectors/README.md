# Web Bot Auth negative test vectors

Requests a verifier must not verify, for draft-ietf-webbotauth-httpsig-protocol-00, from
[ParallaxGrain/webbotauth-negative-vectors](https://github.com/ParallaxGrain/webbotauth-negative-vectors)
at commit `dd489ba3a302e1009de5329dc359124dd1aed15a` (2026-09-03). They were offered to the draft
in [issue #11](https://github.com/thibmeu/http-message-signatures-directory/issues/11). CC0 1.0 (see `LICENSE`).

- `web-bot-auth-negative-vectors.json` is unmodified; its SHA-256 is
  `175b26a13309f90ed654ae1e80c862ddd6e74f1bf992bdf2cdd58bdeaf4f4be4`, which `test_negative_vectors.lua` checks.
- `expected.outcome` follows the draft's Appendix C.1 and is the part the vectors call normative. `expected.reason` is a vocabulary the vectors propose; the test prints ours beside it.
- Every vector is signed with RFC 9421's published test key, so the run disables `reject_test_keys`, as the draft's own vector tests do.
