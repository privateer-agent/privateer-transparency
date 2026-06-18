# Contributing

Thanks for looking closely — that's exactly the point of this repo.

## What this repo is

This is a **read-only transparency mirror** of Privateer's privacy trust boundary, not
the full application. It is published so the cryptography and the ciphertext-only data
path can be **audited**. It is an excerpt and does not build or run on its own.

## How you can help

- **Audit the crypto and the data path.** Read it critically. If something is weaker than
  the README/`docs/` claim, that's the most valuable thing you can find.
- **Report security issues privately** via [`SECURITY.md`](SECURITY.md) — not as public
  issues or PRs.
- **Open an issue** for documentation errors, unclear claims, or mismatches between the
  docs and the code.

## What we generally won't merge

- Feature PRs against this excerpt — the source of truth is our main (closed) codebase;
  this mirror is regenerated from it, so changes here would be overwritten.
- Anything that depends on the omitted closed modules (billing, entitlement, infra).

If you're unsure whether something fits, open an issue first and ask. We'd rather have
the conversation than have you spend effort on a PR we can't take.
